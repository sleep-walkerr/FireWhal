# VM E2E Regression Gate

One-command end-to-end test of FireWhal enforcement inside the disposable
`fw-test` KVM VM. This is **a** test — the first permanent regression gate —
not **the** whole test strategy; the comprehensive mechanism to build on top
of it is tracked in ticket #106. See `test-vm/README.md` for the rig itself.

```
tests/e2e/run-e2e.sh          # from the host, from anywhere in the repo
FW_VM_DIR=/path/to/rig tests/e2e/run-e2e.sh   # if the rig is not at the default
```

The rig directory defaults to `/home/torch/fw-vm`.

## What it does

| Phase | Where | What |
|---|---|---|
| preflight | host | dependency freshness: Cargo.lock core set vs latest stable on crates.io (report-only, never fails the gate — #106) |
| 1. rig | host | VM reachable, or recreate the overlay from the golden image and boot (waits up to 180 s for SSH) |
| 2. build | host | `cargo build --release` + the `ipc_smoke` sample |
| 3. deploy | guest | tarball → `/opt/firewhal/bin`; writes the three TOML configs there (the daemon reads from `bin/`, not `config/`); curl hash computed **in the guest** so it cannot go stale |
| 4. ready | guest | 3 processes; all FireWhal BPF programs present — including **both TC `sched_cls` classifiers** (the original fail-open bug failed to load them) — and all three config pushes in the daemon log (guards the silent zero-rules start) |
| 5. probes | guest | `ipc_smoke` router round-trip; then the three enforcement differentials (log-signal assertions) |
| 6. data | host+guest | D1 data-level enforcement: baseline (stack down) → allow → block in one run; host listener on `127.0.0.1:9999` (byte-level) + guest-side `tcpdump`/`tshark` capture per leg (frame-level) — the first wire-outcome phase |
| 7. dv | host+guest | DV default-verdict legs (#159): **zero explicit rules in every leg** — the per-direction default itself is the policy. egress-allow: payload crosses the wire to the host listener (byte-level) + frames + verdict; egress-block: cut at the boundary (0 frames) + verdict; incoming-allow: `ssh -p 2223` up 3/3 + guest replies on the wire; incoming-block: 2223 down 3/3, no guest reply (ingress tap sits upstream of the TC drop — the blocked SYNs are visible), **M1:** mgmt 2222 up 3/3; ends with a full redeploy of the standard rig config |
| 8. ssh-block | host+guest | S1 deliberate SSH block on the enforced path (2223): baseline → block (config swap + restart) → window (2223 down 5/5; **M1:** mgmt 2222 up 5/5) → VM-local self-expiry (detached sleeper, 120 s) → recovery; verdict + wire + timeline verified (state in `/var/lib/fw-e2e/`) |
| 9. c1 | host+guest | C1 config-path regression: three legs, each moving one config toml aside, restarting the stack (degraded starts must still come up), and asserting the fail-closed posture **on the wire** (rules: default-deny holds; interfaces: the all-non-loopback default keeps enforcement active and mgmt 2222 reachable; apps: egress denied at the app gate). Each leg restores the file and verifies `CONFIG ALERT` + `CONFIG RECOVERED` in the persistent alarm log; the `firewhal-health` validator (same parse as the daemon) must exit 1 while misplaced and 0 after restore |
| 10. cleanup | host | power the VM off (state stays in the overlay; the next run recreates the overlay and boots in phase 1) |

After a run the VM is powered off. The next run always starts from a
pristine overlay (phase 1). To inspect a run's state afterwards, boot it
yourself first (`fw-vm boot`) — the next `run-e2e.sh` will wipe the overlay.

## The enforcement probes

Phases 4–5 are **log-signal** assertions: `enp0s3` is an isolated slirp
network, and the kernel's verdict lines are the truth:

| Probe | Action | Asserted log line(s) |
|---|---|---|
| allow | trusted `curl` (allowlisted, hash-verified) → `10.0.3.2:80` (rule allows TCP/80) | `Rule N ALLOWED connection to 10.0.3.2:80` |
| rule block | trusted `curl` → `10.0.3.2:8080` (no rule matches) | `No rule matched; default OUTGOING = Block. Blocking connection to 10.0.3.2:8080` |
| app block | untrusted `python3` (not in allowlist) → `10.0.3.2:443` (port is allowed) | `Inserted trust for PID N: Deny` + `Pending Connection Blocked (PID Denied)` |
| ipv6 block | `ping6` to the connected `fec0::/64` subnet (deterministic guest IPv6 egress) | `IPv6 packet blocked (policy: all IPv6 is blocked)` |

Egress is forced onto the test NIC with `--interface` / `SO_BINDTODEVICE`
(both slirp NICs share the guest IP). The allow probe exercises the full
two-gate flow: app gate (re-hash of `/usr/bin/curl` vs. allowlist) then
network gate (rule match).

## D1 data-level enforcement (phase 6)

The first phase that asserts **wire outcomes** instead of log signals. The
host runs a listener on `127.0.0.1:9999` (slirp maps guest `10.0.3.2` to the
host loopback) and verifies the exact bytes; the guest captures the enforced
interface with `tcpdump` during each leg and `tshark` asserts frame
presence/absence in the capture. The three legs run in one pass so a broken
allow path and a broken block path are told apart — the baseline leg proves
the raw path itself delivers, so a leg failure is a firewall verdict, not
network flake.

| Leg | Stack | Probe | Wire assertion | Byte-level |
|---|---|---|---|---|
| baseline | down (the phase tears it down and verifies no residual FireWhal BPF) | `curl` POST → `10.0.3.2:9999` | frames present — the raw path delivers | listener receives the payload |
| allow | up (full redeploy) | `curl` POST → `10.0.3.2:9999` (rule allows) | frames present + `Rule N ALLOWED connection to 10.0.3.2:9999` | listener receives the payload |
| block | up | `curl` → `10.0.3.2:8080` (no rule matches) | **no** frames for the probe flow — cut at the boundary, not lost downstream | — + `No rule matched; default OUTGOING = Block. Blocking connection to 10.0.3.2:8080` |

The `:9999` allow rule exists only for this phase (port ≥1024 so the
unprivileged host listener can bind it) and is generated by `vm_deploy.sh`
alongside the other test rules.

## DV default-verdict legs (phase 7)

Ticket #159: the per-direction default verdict (the `ufw default` analogue).
The first phase that exercises the default **itself** as the policy: every
leg runs with **zero** explicit rules (both rule arrays empty), so whatever
crosses or is cut is the configured default, not a rule. `vm_dv.sh` writes
each leg's config; the stack restarts per leg and must pass the full
readiness gate:

| Leg | Defaults (in/out) | Probe | Assertion |
|---|---|---|---|
| egress-allow | Block / Allow | guest `curl` POST → `10.0.3.2:9999` | frames on the wire + host listener receives the payload (byte-level) + `No rule matched; default OUTGOING = Allow. Allowing connection to 10.0.3.2:9999` |
| egress-block | Block / Block | guest `curl` → `10.0.3.2:8080` | 0 frames (cut at the boundary — the egress tap is downstream) + `No rule matched; default OUTGOING = Block. Blocking connection to 10.0.3.2:8080` |
| incoming-allow | Allow / Allow | host `ssh -p 2223` ×3 | up 3/3; capture: the guest replies (ACK frames for `:22`); `No ingress rule matched; default INCOMING = Allow. Allowing connection from 10.0.3.2:<port>` |
| incoming-block | Block / Allow | host `ssh -p 2223` ×3 | down 3/3; capture: no guest reply (0 ACK frames for `:22`; the blocked SYNs are visible — the ingress tap sits upstream of the TC drop, S1 finding); **M1:** mgmt 2222 up 3/3; `No ingress rule matched; default INCOMING = Block. Blocking connection from 10.0.3.2:<port>` |

The outgoing default is deliberately `Allow` on the incoming legs: the
sshd's replies are egress and must cross for the handshake to complete
(incoming-allow) or are irrelevant (incoming-block — nothing is sent), so
INCOMING is the only variable. No self-expiry sleeper (unlike S1): the
worst leg only blocks the OOB 2223 path and the unenforced mgmt 2222 stays
up, so the gate always keeps control; the phase ends with a full redeploy
of the standard rig config, which the later phases (S1, C1) depend on.

## S1 SSH-block + M1 (phase 8)

The deliberate SSH block (ticket #106, design doc §2.2, inverted for this
rig: the block targets the enforced `2223` path — incoming `tcp/22` on
`enp0s3` — because FireWhal only enforces `enforced_interfaces`; the
unenforced mgmt `2222` must stay up, which is exactly the M1 collateral
guard, §2.3). The VM owns its own unlock: a VM-local self-expiry sleeper
(a detached guest process; not a systemd one-shot — see the runbook S1
findings) restores the config and restarts the stack after the
window (default 120 s, `FW_S1_WINDOW` overridable), independent of SSH
state. If the block regresses (no cut), 2223 stays up and the "must be
down" checks fail — the test can never lock us out of itself (2222 is never
at risk).

| Leg | Stack | Assert |
|---|---|---|
| baseline | up (incoming `:22` rule present) | `ssh -p 2223` and `fw-vm ssh` (2222) both succeed |
| block | up, incoming `:22` rule dropped (config swap + restart) | in-guest: backup taken, self-expiry armed, config swapped, stack ready; host: `ssh -p 2223` down 5/5; **M1:** mgmt 2222 up 5/5 |
| window wire | (blocked) | verdict `No ingress rule matched; default INCOMING = Block. Blocking connection from 10.0.3.2:<port>` in the block log; capture: no guest reply (0 frames with the ACK flag for `:22`; the blocked SYNs are visible at the tap — the ingress tap sits upstream of the TC drop, see runbook) |
| self-expiry | sleeper fires | config restored byte-for-byte, stack ready, timeline records `rule-down (self-expiry)` + `rule-up restored` |
| recovery | up, rule restored | `ssh -p 2223` succeeds again with no outside intervention; recovery capture: `:22` frames present again |

## C1 config-path regression (phase 9)

Ticket #106, design doc §2.4. The question: deploy with a toml missing or
malformed — silent zero-rules start, or loudly degraded? The contract: the
stack stays **up** (a dead firewall detaches every eBPF hook — that is
fail-open, the worst case) in the fail-closed default for whatever is
missing, and announces the degraded state on every channel (persistent
alarm log, `wall`, TUI banner, and the `firewhal-health` oneshot validator —
never green on a broken config).

Each leg moves one toml aside, restarts the stack (the degraded start must
still come up — no happy-path readiness gate), and asserts the resulting
posture on the wire (D1-style `tcpdump`/`tshark` capture on `enp0s3`):

| Leg | Degraded posture (fail-closed) | Wire assertion | Also asserted |
|---|---|---|---|
| rules | `firewall_rules.toml` missing → empty rule set: default-deny, everything blocked | probe `:9999` (allowed under normal config) cut — **0 frames** | validator rc=1 → 0 across the restore |
| interfaces | `interface_state.toml` missing → hooks on **all non-loopback** interfaces (the TC layer is never left unattached) | enforcement still active: `:8080` cut (0 frames) **and** `:9999` delivered (frames present) | **M1 under the default:** mgmt 2222 reachable 3/3 (the rules allow `tcp/22`) |
| apps | `app_identity.toml` missing → daemon bootstraps an **empty** allowlist | egress denied at the app gate: `:9999` cut — **0 frames** (the rule allows it; the allowlist does not) | the empty allowlist file exists after the start |

After each leg the file is restored, the stack restarts healthy, and the
verify step asserts the alarm log recorded both `CONFIG ALERT` and
`CONFIG RECOVERED` for that file (the recovery alarm survives the restart
because the daemon persists its health state in
`/var/log/firewhal/config-health.state`) and that all three config pushes
came back as `(configured)`.

The alarm log (`/var/log/firewhal/config-alert.log`) is persistent (never
`/tmp` — S1 forensics proved it non-durable on this image) and is the
e2e's ground truth for the wall/TUI channels (the rig is headless).

## Files

- `run-e2e.sh` — host-side orchestrator (preflight + phases 1–3, 6–10, then runs the guest scripts)
- `dep_freshness.py` — preflight: core-set drift report (Cargo.lock vs crates.io, ticket #106)
- `vm_deploy.sh` — guest-side: teardown, install, config generation (incl. the D1 `:9999` rule), launch, readiness wait
- `vm_probes.sh` — guest-side: the phase 5 checks; exits non-zero on any failure
- `vm_data_probe.sh` — guest-side D1: per-leg `tcpdump` capture, `tshark` frame assertions, verdict lines
- `vm_s1.sh` — guest-side S1: self-expiry arming (detached sleeper), config swap + restart, per-leg `tcpdump` captures, `verify` (config restore, readiness, verdict, wire, timeline); state in `/var/lib/fw-e2e/`
- `vm_dv.sh` — guest-side DV: per-leg zero-rule config writes, per-leg restart + readiness, `tcpdump`/`tshark` captures, verdict + wire assertions (`run` is self-contained for the egress legs; `arm`/`stop-capture`/`verify` for the host-driven incoming legs)
- `vm_c1.sh` — guest-side C1: `move`/`start` (detached — the new enforcement may sever the in-flight ssh session, by design)/`c1-status` (non-blocking status read; the gate polls it from the host with fresh short probes)/`wait-start` (manual poll)/`probe`/`restore`/`verify`; backups in `/var/lib/fw-e2e/c1-backup/`

## Adding a probe

1. Record the log line(s) a correct run prints (check
   `docs/vm-enforcement-testing.md` for the catalog of verdict lines).
2. Add a `check` block in `vm_probes.sh` (snapshot `wc -l < $LOG` first).
3. Note it in the table above and in the runbook.

## What this does NOT cover (yet)

- Resilience (kill -9 each component, expect re-attach/re-register)
- CI (needs a KVM runner; see ticket)

These belong in the comprehensive test mechanism — ticket #106.
