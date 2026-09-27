# Comprehensive Test Mechanism — Design

The 6-phase e2e gate (`tests/e2e/run-e2e.sh`) is the first permanent
regression gate: it proves the stack boots, deploys, loads every BPF program,
and shows the expected verdict lines. This document is the design exercise
ticket #106 was created to hold: how the mechanism extends beyond that first
gate. Decisions were settled in the 2026-09-26 design session; the record is
in §7.

**Scope rule** (per #95/#106 acceptance): every future e2e test lands as a
named phase in `tests/e2e/` plus a line in the runbook
(`docs/vm-enforcement-testing.md`) and a row in the probe table in
`tests/e2e/README.md`. No ad-hoc scripts.

## 1. The wire is the oracle (measurement layer)

**Problem.** Today's probes assert *verdict log lines*. A verdict line says
what the firewall *decided*; it cannot distinguish "blocked at the firewall"
from "lost in slirp". The missing guarantee: did the byte actually cross (or
not cross) the enforcement boundary?

**Decision: capture the enforced interface inside the guest** (`tcpdump -w`
for capture, `tshark` for headless assertions). Rationale:

- The AF_PACKET capture point sits **downstream of every enforcement layer**
  (TC `cls_act` ingress/egress, `sock_ops`, cgroup `sock_addr`) in **both**
  directions. So: frame *in* the capture = enforcement let it through; frame
  *not in* the capture = it never crossed the boundary, regardless of which
  layer cut it. (Layer attribution stays with the verdict lines, which the
  gate already asserts.)
- Zero rig changes: the test NIC is user-mode slirp, so there is no
  host-side tap on that link at all. Guest-side is the only place the wire
  is visible without re-architecture.
- The capture is a replayable artifact: every probe leaves a pcap that can be
  opened in Wireshark afterwards.

Host-side visibility on the same link (TAP + host netns, second independent
oracle, cross-check of guest measurements) is the follow-up: **ticket #115**.
It is deliberately out of the first build.

Tooling: `tcpdump` + `tshark` are in the guest seed (PR #116) and baked in via
the golden image rebuild.

## 2. Phases

### 2.1 Phase D1 — data-level enforcement (baseline → allow → block, one run)

**Peer:** the host, over slirp. The guest reaches the host at `10.0.3.2`
(slirp routes guest→`10.0.3.2` to host loopback; no rig change needed). The
host runs a small listener (`nc` or a python socket) on `127.0.0.1:PORT`;
the guest probe opens TCP through the enforced interface and sends a known
byte string. (The existing allow probe already curls `10.0.3.2:80` — nothing
was listening; D1 adds the listener and the wire assertions.)

**One run, three legs** — this also settles the ticket's "baseline vs
enforced in one run" question:

| Leg | Rules | Data-level assertion | Wire assertion (tshark) |
|---|---|---|---|
| baseline | none | bytes arrive (if not, the network is broken, not the firewall) | frames present |
| allow | allow rule for the probe 4-tuple | exact payload received by the listener | frames present |
| block | no matching rule (or explicit deny) | connect fails / nothing received | **no probe frames in the capture** — cut at the boundary, not lost downstream |

The three legs in one run are what separate a broken allow path from a broken
block path.

### 2.2 Phase S1 — deliberate SSH block (a feature test, not a bug hunt)

Semantics settled in the session: enforcement touches **exactly what the
rules say** — including the mgmt NIC, if a rule targets it. "Mgmt isolation"
is therefore the *collateral guard* (2.3), and this phase proves the system
*can* cut SSH when told to.

Mechanism (the hard part: if the block works, we cannot reach the VM to
remove the rule):

1. **Create** a block rule: enp0s2 (mgmt path), tcp/22.
2. **Self-expiry:** at creation, the harness installs a VM-local self-expiry
   (implemented as a detached guest process — see the inversion note below
   for why not a systemd timer) that removes the rule after N seconds via the
   normal IPC path — independent of SSH state. The VM owns its own unlock.
3. **Probe:** from the host, loop `ssh -o ConnectTimeout=3` to the mgmt IP
   during the window; expect 100% failure. Wire-verified: no SSH frames on
   enp0s2 during the window (tshark).
4. **Out-of-band backstop:** add a second hostfwd to the rig (`2223→22` on
   the enp0s3 slirp, one line in `fw-vm`). While the mgmt path is cut,
   `ssh -p 2223` still works — for shortening the window, inspecting state,
   and as a live demonstration of the collateral guard (2.3) in the same
   test.
5. **Record & reconnect:** the harness writes the timeline to the VM (rule-up,
   failed attempts, rule-down, SSH-OK, verdict). After the window, the gate
   reconnects and asserts the record.

**Safety:** the only path to losing SSH is the *passing* path, and the
self-expiry restores it. If the block regresses (no cut), SSH stays up and
the harness cleans up normally and fails the run — the test can never lock
us out of itself.

**Inversion for this rig (as implemented, 2026-09-27).** FireWhal enforces
only on `enforced_interfaces` (enp0s3 here), so step 1's "enp0s2 (mgmt
path)" would be a no-op — there are no hooks on the mgmt NIC. The implemented
phase therefore blocks incoming `tcp/22` on the *enforced* path (enp0s3,
i.e. the 2223 hostfwd) — proving the firewall *can* cut SSH when told to —
while the unenforced mgmt path (2222) stays up; that is exactly the M1
collateral guard (§2.3) asserted live in the same window, and 2222 doubles
as the OOB backstop (step 4), since the gate drives every guest step over
it. The wire assertion is direction-specific: the ingress AF_PACKET tap sits
**upstream** of the TC ingress drop on this rig, so blocked SYNs are visible
in the guest capture; the ingress oracle is "the guest never replies" (no
frame with the ACK flag), while the egress oracle stays "frame absent" (D1).
The self-expiry is a VM-local sleeper — a detached `setsid` guest process
that sleeps out the window (default 120 s, `FW_S1_WINDOW` overridable) and
then restores the config and restarts the stack as root; the mechanism is
"config swap + restart" (the same path the deploy uses) rather than a live
IPC rule push, since the TUI's IPC push has no headless CLI. It is
deliberately **not** a systemd timer/service: this guest's systemd
(255.4-1ubuntu8.17) rejects `KillMode=main` (the parse error is logged and
the value silently dropped — reproduced with `systemd-analyze verify` on the
intact unit), so a one-shot service under the default `control-group` kill
mode SIGTERMs the daemon the unlock just restarted the moment the unit
completes (first full gate run: the stack was dead for the whole verify
window, and the "recovered" port was fail-open, not rule-restored). A
detached guest process sidesteps the kill-mode and timer-repetition
semantics entirely, and ssh-spawned process survival is proven in this rig
(the deploy daemon and the per-leg captures outlive their ssh sessions).
The self-expiry does not survive a guest reboot — same as the (never-
enabled) timer would have been; the block is fail-closed on the throwaway
overlay by design. Landed as gate phase 7; runbook + first-run findings
(incl. guest real-time delays running +6..+43 s late under NTP slewing) in
`docs/vm-enforcement-testing.md`.

### 2.3 Phase M1 — mgmt collateral guard

While any data-plane rule is active (D1 legs, S1 window), a background SSH
ping on the mgmt path must stay healthy **except** when S1's rule explicitly
targets it. A regression where a data-plane rule degrades the mgmt path is
self-inflicted lockout — this phase asserts it never happens. (S1's OOB
channel is this guard in action, live.)

### 2.4 Phase C1 — config-path regression

Ticket question: deploy with the tomls in the wrong place — silent zero-rule
start, or daemon fails loudly?

**Decision (refined 2026-09-27): "loud" means *visibly degraded on every
channel* — not dead.** A config error must never be a silent zero-rules
start, but the fix is not a non-zero exit: when the daemon exits, the kernel
component detaches all eBPF programs, and a dead firewall is not "blocked" —
it is *no* firewall (fail-open). The stack stays up, holds the safe posture,
and enters an explicit **degraded** state that is honest on every channel.

Model: UFW (verified against the 0.36.2 source): policy must be *explicit* —
it validates config and never guesses (missing/corrupt file → hard
`UFWError` before the kernel is touched; a failed `enable` reverts the
`ENABLED` flag it just set); status is first-class and never implicitly green
(`Status: active|inactive`, no in-between); and the boot unit fails loudly
(`ufw.service`, oneshot, `Before=network-pre.target`) so a broken config is
visible at three levels — CLI, boot unit, status command. UFW also attaches
to *all* interfaces by default — its escape path is an allow rule, not an
unenforced interface (the `ufw enable` ssh-prompt is the acknowledgment of
that trade-off). We adopt all of it: the three loudness levels, the
all-interfaces default (below), and a `wall` broadcast (UFW has no live
process to watch).

**The posture matrix** (the three tomls fail differently — verified in code;
the alarm must name the file *and the actual resulting posture*):

| Misplaced file | Posture today | Posture after C1 |
|---|---|---|
| `firewall_rules.toml` | hooks attached, zero rules → default-deny — everything blocked (fail-closed) | unchanged — already fail-closed; now announced |
| `interface_state.toml` | **no TC hooks attach at all** (attachment happens only from the `LoadInterfaceState` message) → the rule layer is unenforced (**fail-open** — the "corrupt a text file and the floodgates are open" case) | **fail-closed by default: hooks attach to all non-loopback interfaces** (mechanism item 2) |
| `app_identity.toml` | silently bootstraps an **empty allowlist** file → app gate denies all egress (fail-closed, but the self-created file masks the problem) | unchanged — already fail-closed; now announced (the bootstrap stays) |

After C1, every misconfiguration lands in a deny posture — the system is
uniformly fail-closed. "Degraded" then means *safe but not as intended*,
which is exactly what the alarm bundle and `firewhal-health` exist to say.

**Mechanism:**

1. **Config-health state (daemon):** per-toml `Ok | Missing | Malformed`,
   computed at startup and on every load/reload. While degraded, the daemon
   never reports `is_healthy: true` — the `Status` message carries the
   degraded state + reason (UFW's honest-status contract).
2. **Fail-closed interface default.** Today a missing/malformed/empty
   `interface_state.toml` leaves the TC layer *unattached* — open. C1
   changes the semantics: the daemon attaches TC hooks to **all non-loopback
   interfaces** (enumerated from `/sys/class/net` at load time — same
   fixed-at-load semantics as today's declared list). The operator's escape
   path stops being "the interface I didn't list" (that information lived in
   the missing file) and becomes "the interface my rules allow" — UFW's
   model. Consequence the alarm must state: the daemon cannot know which
   interface is the operator's escape, so it names every interface the
   default newly covers and says their traffic is now subject to the rules.
   The remaining edge — no rules *and* no interface declaration → the
   management path is blocked too — is correct deny-all behavior (the UFW
   equivalent is `enable` with deny-incoming and no SSH rule); in the rig it
   is recoverable from the host side (serial/VNC), and the alarm fires first.
3. **Alarm bundle** (fires on state transitions — healthy→degraded *and*
   degraded→healthy — so no spam):
   - persistent record: timestamped line in `/var/log/firewhal/config-alert.log`
     (never `/tmp` — S1 forensics proved it non-durable on this image);
   - `wall` broadcast (the daemon is root; the message names the file, the
     live posture in plain language, and the fix);
   - TUI: the main menu already tracks per-component status — extended to a
     degraded state with red/yellow marking + reason.
4. **`firewhal-health`** (new small binary + `firewhal-health.service`
   oneshot unit): boot-time validator for the three tomls using the same
   parse as the daemon (the three load helpers move to `firewhal-core` so
   both share them). Missing/malformed → non-zero exit →
   `systemctl status firewhal-health` shows **failed**, never green (UFW's
   `ufw.service` loudness); its message states what is missing *and which
   safe default is in effect* (e.g. "defaulting to all non-loopback
   interfaces — fail-closed, not as configured"). `Type=oneshot`,
   `RemainAfterExit=yes` (last state stays visible, as in ufw). In the e2e
   rig the stack is not systemd-managed, so the gate invokes the binary
   directly — the same validation the unit would run.
5. **Revert on failed swap:** any config swap (S1, C1 legs, TUI updates)
   follows backup → write → verify → restore-on-failure; no half-swapped
   state (UFW reverts `ENABLED` on a failed start for exactly this reason;
   S1's backup/restore already follows it).

**Test (gate phase 8, wire-verified, three legs + validator).** Each leg
moves one toml aside, starts the stack without the happy-path readiness gate,
and asserts the posture *on the wire* (D1-style probe):

- **leg 1 (rules):** processes up; wire shows default-deny (probe frames
  absent — cut at the rule layer); alarm line present, stating "blocked".
- **leg 2 (interfaces):** processes up; hooks attached to **all
  non-loopback interfaces** under the new default (`sched_cls` count =
  2 × non-loopback count, not 0); enforcement active under the default —
  the D1 block port (8080) is still cut on the wire and the allowed port
  (80) still delivered; mgmt 2222 still reachable (the test rules allow
  :22 — M1 holds under the default too); alarm naming the newly covered
  interfaces.
- **leg 3 (app IDs):** processes up; wire shows egress denied at the app
  gate; the empty bootstrap file was created; alarm present.
- **validator:** `firewhal-health` exits non-zero with a clear message
  against the misplaced config, 0 after restore.
- each leg restores → recovery alarm + wire back to baseline.

The `wall`/TUI channels are asserted via the daemon's alarm record in e2e
(headless rig: no tty to observe; the wall text is visible in the serial
log); the TUI rendering itself is a manual check.

### 2.5 Phase F1 — fail-open as a first-class test

The readiness phase already asserts both TC `sched_cls` programs loaded (the
regression guard for the original fail-open incident, PR #97). F1 makes the
*behavior* explicit rather than just the *load*: a known-bad packet (the D1
block leg) must be absent from the wire. F1 is the naming + cataloging of that
probe, not a separate implementation.

### 2.6 Phase R — resilience (deferred, test follows feature)

Nothing in the stack is resilient today, so a resilience phase now would only
document the absence of the feature. It is parked with **pre-written
acceptance criteria** (in ticket #114): kill -9 each component (daemon, IPC
router, kernel-side) one at a time; expect reconnect, re-register, re-attach;
no wedged state afterwards. The phase drops in as a named phase when the
self-healing feature lands. Note: systemd `Restart=` is the existing backstop
for plain process death; the feature is about IPC-level coordination.
**#114 is gated on owner review before implementation.**

## 3. CI

GitHub's public runners have no `/dev/kvm`; the gate wants KVM.

**Decision: self-hosted runner** — a VM on the owner's Proxmox server. One
hard requirement: **nested virtualization enabled on that Proxmox VM**
(KVM-in-KVM); without it the inner VM degrades to TCG (several-fold slower,
workable but not the goal).

Shape: golden image published as a workflow artifact (reproducible + fast
runs); full gate (preflight + phases 1–5) on pushes to `main`; heavier phases
nightly once they exist. If keeping a runner on turns out to be too much, the
fallback is the ticket's "or documented manual runner" branch — status quo.

## 4. Sequence

1. ✅ Wire tools in seed + seed pipefail fix (PR #116) + golden rebuild
2. ✅ Dependency-freshness preflight in the gate (PR #117)
3. ✅ This design doc
4. D1 data-level — first run the ~5-minute check that guest→`10.0.3.2`
   delivery actually works on this rig; it decides listener placement
5. ✅ S1 + M1 — gate phase 7 (2026-09-27; the `2223` hostfwd rig change
   landed in the same arc, §2.2 documents the inversion)
6. C1 — config-path regression (decision refined in §2.4: degraded-and-
   announced, not dead; three wire-verified legs + the `firewhal-health`
   validator; daemon-side config-health + alarm bundle + oneshot unit)
7. R — after #114 (gated)
8. CI — after the Proxmox runner VM exists
9. #115 (host-side wire visibility) — whenever

## 5. Open items (honest remainder)

- **D1 direction:** guest→host (`10.0.3.2`) is the default; if the delivery
  check shows it flaky on this rig, flip to host→guest (needs the hostfwd).
- **C1 scope:** resolved (2026-09-27) — full daemon-side implementation:
  config-health state + alarm bundle (`/var/log/firewhal/` + `wall` + TUI)
  + `firewhal-health` oneshot validator + three wire-verified legs; see §2.4.
- **S1 window:** resolved — default 120 s, overridable by env
  (`FW_S1_WINDOW`); the gate uses the default (the observed guest real-time
  delay lag is absorbed by the recovery deadline).

## 6. Verdict-line and probe catalog

Every phase above adds its lines to the existing catalog in
`docs/vm-enforcement-testing.md` and its row to the probe table in
`tests/e2e/README.md`. This document points at them; it does not duplicate
them.

## 7. Decision record (2026-09-26 session)

| # | Question | Decision |
|---|---|---|
| 1 | Wire-monitor placement | guest-side `tcpdump`/`tshark` on the enforced interface; host-side via TAP+netns later (#115) |
| 2 | Data-level peer | the host, over slirp (`10.0.3.2` / hostfwd) — no second VM |
| 3 | Baseline vs enforced | one run, three legs: baseline → allow → block |
| 4 | SSH blocking | deliberate feature test: self-expiry + slirp OOB + wire-verified; "mgmt isolation" = the collateral guard, not a prohibition |
| 5 | Config path | daemon must fail loudly on misconfig — never a silent zero-rules start |
| 6 | Resilience | test follows the feature (#114, gated on owner review) |
| 7 | CI | self-hosted runner on a Proxmox VM; nested KVM required |
| 8 | bpf-linker freshness | tracked in the runbook (host tool), outside the cargo check |
