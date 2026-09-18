# VM E2E Regression Gate

One-command end-to-end test of FireWhal enforcement inside the disposable
`fw-test` KVM VM. This is **a** test — the first permanent regression gate —
not **the** whole test strategy; see `test-vm/README.md` for the rig itself
and the open ticket for the comprehensive mechanism to build on top of it.

```
tests/e2e/run-e2e.sh          # from the host, from anywhere in the repo
FW_VM_DIR=/path/to/rig tests/e2e/run-e2e.sh   # if the rig is not at the default
```

The rig directory defaults to `/home/torch/fw-vm`.

## What it does

| Phase | Where | What |
|---|---|---|
| 1. rig | host | VM reachable, or recreate the overlay from the golden image and boot (waits up to 180 s for SSH) |
| 2. build | host | `cargo build --release` + the `ipc_smoke` sample |
| 3. deploy | guest | tarball → `/opt/firewhal/bin`; writes the three TOML configs there (the daemon reads from `bin/`, not `config/`); curl hash computed **in the guest** so it cannot go stale |
| 4. ready | guest | 3 processes; all FireWhal BPF programs present — including **both TC `sched_cls` classifiers** (the original fail-open bug failed to load them) — and all three config pushes in the daemon log (guards the silent zero-rules start) |
| 5. probes | guest | `ipc_smoke` router round-trip; then the three enforcement differentials |

After a run the stack is left running on the VM; the next run tears down
whatever it finds first (pidfile-lock friendly).

## The enforcement probes

`enp0s3` is an isolated slirp network with nothing listening, so probes can
not be measured by wire outcome. The kernel's verdict lines are the
assertions:

| Probe | Action | Asserted log line(s) |
|---|---|---|
| allow | trusted `curl` (allowlisted, hash-verified) → `10.0.2.2:80` (rule allows TCP/80) | `Rule N ALLOWED connection to 10.0.2.2:80` |
| rule block | trusted `curl` → `10.0.2.2:8080` (no rule matches) | `No rule matched. Blocking connection to 10.0.2.2:8080` |
| app block | untrusted `python3` (not in allowlist) → `10.0.2.2:443` (port is allowed) | `Inserted trust for PID N: Deny` + `Pending Connection Blocked (PID Denied)` |

Egress is forced onto the test NIC with `--interface` / `SO_BINDTODEVICE`
(both slirp NICs share the guest IP). The allow probe exercises the full
two-gate flow: app gate (re-hash of `/usr/bin/curl` vs. allowlist) then
network gate (rule match).

## Files

- `run-e2e.sh` — host-side orchestrator (phases 1–3, then runs the guest scripts)
- `vm_deploy.sh` — guest-side: teardown, install, config generation, launch, readiness wait
- `vm_probes.sh` — guest-side: the checks above; exits non-zero on any failure

## Adding a probe

1. Record the log line(s) a correct run prints (check
   `docs/vm-enforcement-testing.md` for the catalog of verdict lines).
2. Add a `check` block in `vm_probes.sh` (snapshot `wc -l < $LOG` first).
3. Note it in the table above and in the runbook.

## What this does NOT cover (yet)

- Data-level transfer assertions (the dead-end network has no listener)
- Mgmt-NIC isolation (that enforcement never touches SSH)
- Resilience (kill -9 each component, expect re-attach/re-register)
- Baseline-vs-enforced comparison
- CI (needs a KVM runner; see ticket)

These belong in the comprehensive test mechanism — tracked separately.
