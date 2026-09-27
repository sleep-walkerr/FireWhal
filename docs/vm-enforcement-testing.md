# VM Enforcement Testing — Runbook & Findings

E2e testing of FireWhal inside the disposable KVM VM `fw-test`. Everything
runs in the VM; the host is never subjected to enforcement or BPF.

## Running the rig (since 2026-09-18, one command)

```
tests/e2e/run-e2e.sh
```

Builds the release workspace on the host, deploys it to the VM, and runs the
regression gate: stack readiness (all FireWhal BPF programs including both TC
classifiers, all three config pushes) plus the enforcement differentials
(allow / rule-block / app-block / ipv6-block, asserted from kernel verdict
log lines). See
`tests/e2e/README.md` for the probe table and `test-vm/README.md` for rig
setup. A report-only dependency-freshness preflight (`tests/e2e/dep_freshness.py`)
runs before phase 1: it compares the locked core crate set against crates.io
and prints drift — warning-level only, it never fails the gate (ticket #106).
The findings below document what the first manual runs found and what
each probe guards against.

## D1 data-level phase (gate phase 6, since 2026-09-26)

Phase 6 is the first **wire-outcome** phase (ticket #106, design doc
`docs/comprehensive-test-design.md` §2.1). The host runs a listener on
`127.0.0.1:9999` (slirp maps guest `10.0.3.2` to the host loopback); the
guest captures `enp0s3` with `tcpdump`/`tshark` per leg. Three legs in one
run, so a broken allow path and a broken block path are told apart:

1. **baseline** — stack down (the phase tears it down and verifies no
   residual FireWhal BPF). `curl` POST → `10.0.3.2:9999` must deliver the
   payload to the listener, and probe frames must appear on the wire. If
   this leg fails, the network path itself is broken — not the firewall.
2. **allow** — full redeploy (the generated config includes an allow rule
   for `:9999`). Payload arrives, frames present, verdict
   `Rule N ALLOWED connection to 10.0.3.2:9999`.
3. **block** — `curl` → `10.0.3.2:8080` (no rule matches). Connect fails and
   **no** probe frames appear on the wire — cut at the boundary, not lost
   downstream — with verdict `No rule matched. Blocking connection to
   10.0.3.2:8080`.

## Findings (first manual run, 2026-09-18)

## Rig layout

- Raw qemu (no libvirt), manager script `fw-vm {reset|boot|stop|ssh}`.
- Disk chain: `noble.img` (pristine) -> `golden.qcow2` (provisioned state) ->
  `run.qcow2` (throwaway overlay; `fw-vm reset` recreates it).
- Networking: `enp0s2` = slirp mgmt NIC (`10.0.2.0/24`, SSH hostfwd
  `127.0.0.1:2222`); `enp0s3` = isolated slirp test NIC in its own subnet
  (`10.0.3.0/24`; gateway `10.0.3.2`) — the interface under test. The own
  subnet is deliberate: sharing `10.0.2.0/24` makes both slirp instances
  present the same gateway `10.0.2.2`, and the guest's FIB then routes
  replies to `10.0.2.2` via whichever interface won the boot-order tie —
  the other slirp RSTs them (a per-boot coin flip that silently kills one
  path).
- Probes still pin egress to the test NIC with `SO_BINDTODEVICE`
  (`--interface enp0s3`), so the enforced path is exercised regardless of
  routing.
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

### 6. IPv6 was completely unguarded (fail-open, fixed — ticket #70)

The whole stack was IPv4-only by construction: the cgroup hooks only cover
`connect4`/`sendmsg4`/`bind4` (no v6 variants), and the TC parser returned an
error for ether type `0x86dd` which the classifier wrappers converted to
`TC_ACT_OK` (allow). Net effect: an app on an enforced interface could
communicate over IPv6 bypassing both the app gate and the rule gate.

Fix: `parse_packet_tuple` now distinguishes the failure modes
(`PacketParseError::Ipv6` vs `Other`), and both TC classifiers drop IPv6
packets with `TC_ACT_SHOT` (`IPv6 packet blocked (policy: all IPv6 is
blocked)`), while still passing through truly unhandled ether types (ARP,
VLAN, ...) as before. The e2e rig asserts this with the ipv6-block probe
(`ping6` to the connected `fec0::/64` subnet — deterministic guest v6 egress,
no raw sockets needed).

## Open work

- [x] TC classifier load failure — fixed (PR #97), regression-guarded by the
      e2e rig's readiness phase.
- [x] Wire the procedure into a permanent, repo-integrated test rig —
      `tests/e2e/` + `test-vm/` (one command: `tests/e2e/run-e2e.sh`).
- [x] Design the comprehensive test mechanism (ticket #106; design doc
      `docs/comprehensive-test-design.md`); D1 data-level phase landed as
      gate phase 6 on 2026-09-26.
- [ ] Remaining #106 sequence: S1 SSH-block + mgmt-NIC collateral guard,
      C1 config-path fail-loud, R resilience (ticket #114), CI on a KVM
      runner. Host-side TAP/netns wire visibility: ticket #115.
