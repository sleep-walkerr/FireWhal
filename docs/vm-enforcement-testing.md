# VM Enforcement Testing — Runbook & Findings

E2e testing of FireWhal inside the disposable KVM VM `fw-test`. Everything
runs in the VM; the host is never subjected to enforcement or BPF.

## Running the rig (since 2026-09-18, one command)

```
tests/e2e/run-e2e.sh
```

Builds the release workspace on the host, deploys it to the VM, and runs the
regression gate: stack readiness (all FireWhal BPF programs including both TC
classifiers, all three config pushes) plus the three enforcement differentials
(allow / rule-block / app-block, asserted from kernel verdict log lines). See
`tests/e2e/README.md` for the probe table and `test-vm/README.md` for rig
setup. The findings below document what the first manual runs found and what
each probe guards against.

## Findings (first manual run, 2026-09-18)

## Rig layout

- Raw qemu (no libvirt), manager script `fw-vm {reset|boot|stop|ssh}`.
- Disk chain: `noble.img` (pristine) -> `golden.qcow2` (provisioned state) ->
  `run.qcow2` (throwaway overlay; `fw-vm reset` recreates it).
- Networking: `enp0s2` = slirp mgmt NIC (SSH hostfwd `127.0.0.1:2222`);
  `enp0s3` = isolated slirp test NIC (the interface under test).
- Both slirp NICs get the same guest IP (10.0.2.15); force egress through the
  test NIC with `SO_BINDTODEVICE`.
- Deploy: `cargo build --release` on the host, tarball into
  `/opt/firewhal/{bin,config}` in the guest.

## Test procedure used

1. **IPC smoke** — `firewhal-core/examples/ipc_smoke.rs`: connect as DEALER to
   `ipc:///tmp/firewhal_ipc.sock`, register as TUI (`Status{Ready}`), send
   `Ping{source:"TUI"}`, expect `Pong{source:"IPC"}` (plus relayed Pongs from
   Firewall and Daemon). Pass.
2. **Enforcement** — baseline (no rules) vs enforced, via enp0s3:
   - baseline: TCP 443/80/53 all connect
   - restart daemon with rules in place
   - data-transfer probes (connect alone is not a sufficient probe — see below)

## Findings

### 1. Daemon config path mismatch (deploy bug)

The daemon loads all three tomls from `/opt/firewhal/bin/`
(`firewall_rules.toml`, `app_identity.toml`, `interface_state.toml`) — **not**
from `/opt/firewhal/config/` where the deploy layout puts them. With the file
in the wrong place the daemon starts cleanly with zero rules and no error.

### 2. Router registration race (fixed)

The router dropped messages for not-yet-registered components. Component
registration order is a race (the router is a child of the Daemon, so the
Daemon's own slow-joiner connect can lose it to the Firewall). A dropped
`Firewall -> Ready` left the Daemon's one-shot rule-load gate waiting forever.
Fixed in `firewhal-ipc`: bounded pending buffer (100/component), flushed on
registration, reset on rebind.

### 3. Swallowed TC attach errors (fixed)

`firewhal-kernel` discarded `load()` results and reused the "ingress" warn
text in the egress branch. Now prints the real errors.

### 4. FAIL-OPEN: TC classifiers failed to load on kernel 6.8 (**fixed**, PR #97)

Architecture (by design): the cgroup `sock_addr` programs are deliberately
pass-through (`Ok(1) // blocking delegated to tc egress program`). They log
every `CONN_ATTEMPT` and userspace records allowlist verdicts
(`Inserted trust ...: Deny` appears even for allowlisted flows — the default
is Deny in the trust map; per-connection allows come from rule matching).
Actual packet drops happen in the **TC classifiers** (default `TC_ACT_SHOT`
on no match).

On this VM (Ubuntu 24.04, kernel `6.8.0-139-generic`) both TC classifiers
failed `BPF_PROG_LOAD`:

- aya verifier log: a single line `0: R1=ctx() R10=fp0` (buffer is 10KB+, so
  the kernel genuinely logged only that)
- no BPF lines in dmesg/journal at all
- `bpftool prog load` cannot load the object at all: aya's legacy map format
  (`maps` section) is rejected by libbpf v1.0+
- the cgroup programs from the **same object** load fine, so BPF itself works
  in this environment

Observed behavior at the time: allowlisted ports (80, 443 TCP) pass;
**non-allowlisted ports also pass** (8080 TCP returned an HTTP response
through enp0s3). The firewall monitored and logged but dropped nothing — a
silent fail-open.

**Resolution (2026-09-18):** the eBPF object was fixed (PR #97) and the
release build verified in this VM: both `sched_cls` classifiers now load on
6.8.0-139 and actually drop. The e2e rig's readiness phase asserts both TC
programs are present on every run, so a regression to this state fails the
gate before any probe runs.

### 5. Connect-only probes are insufficient

`SO_BINDTODEVICE` + TCP connect succeeds even for a connection that will be
cut at send time (the cgroup layer lets connects through; blocking happens on
data). Probes must transfer data (e.g. an HTTP GET) to measure enforcement.
(The port-53 "block" in raw testing was the DNS server not answering an HTTP
probe, not a firewall drop.)

## Open work

- [x] TC classifier load failure — fixed (PR #97), regression-guarded by the
      e2e rig's readiness phase.
- [x] Wire the procedure into a permanent, repo-integrated test rig —
      `tests/e2e/` + `test-vm/` (one command: `tests/e2e/run-e2e.sh`).
- [ ] Design the comprehensive test mechanism: data-level transfer probes,
      mgmt-NIC isolation, resilience (kill/re-attach), baseline-vs-enforced,
      and a KVM-capable CI runner (tracked in its own ticket).
