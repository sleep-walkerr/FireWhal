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
2. **Self-expiry:** at creation, the harness installs a VM-local one-shot
   (systemd timer) that removes the rule after N seconds via the normal IPC
   path — independent of SSH state. The VM owns its own unlock.
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

**Safety:** the only path to losing SSH is the *passing* path, and the timer
restores it. If the block regresses (no cut), SSH stays up and the harness
cleans up normally and fails the run — the test can never lock us out of
itself.

### 2.3 Phase M1 — mgmt collateral guard

While any data-plane rule is active (D1 legs, S1 window), a background SSH
ping on the mgmt path must stay healthy **except** when S1's rule explicitly
targets it. A regression where a data-plane rule degrades the mgmt path is
self-inflicted lockout — this phase asserts it never happens. (S1's OOB
channel is this guard in action, live.)

### 2.4 Phase C1 — config-path regression

Ticket question: deploy with the tomls in the wrong place — silent zero-rule
start, or daemon fails loudly? **Decision: the daemon must fail loudly** — a
config error is a startup failure, never a silent zero-rules start.

Test: deploy with a deliberately misplaced toml; assert the daemon does **not**
start with zero rules. The readiness phase already guards the *symptom*
(silent zero-rules start) on the happy path; C1 exercises the misconfig path.
If/when the daemon fix lands (separate PR, daemon side), C1 asserts the new
loud failure instead.

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
5. S1 + M1 — needs the `2223` hostfwd rig change (`fw-vm`)
6. C1 — needs the daemon-fail-loudly decision (daemon-side PR if we do the
   fix, not just the guard test)
7. R — after #114 (gated)
8. CI — after the Proxmox runner VM exists
9. #115 (host-side wire visibility) — whenever

## 5. Open items (honest remainder)

- **D1 direction:** guest→host (`10.0.3.2`) is the default; if the delivery
  check shows it flaky on this rig, flip to host→guest (needs the hostfwd).
- **C1 scope:** guard-only test now vs. daemon-side fail-loudly fix — decide
  at implementation time (the guard test lands either way).
- **S1 window:** default 120 s, overridable by env in the probe.

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
