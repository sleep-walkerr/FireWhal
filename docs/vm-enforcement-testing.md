# VM Enforcement Testing — Findings (2026-09-18)

E2e test of FireWhal inside the disposable KVM VM `fw-test` (see ticket:
"Integrate VM-based e2e test rig into the repo"). Everything below ran in the
VM; the host was never subjected to enforcement or BPF.

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

### 4. FAIL-OPEN: TC classifiers fail to load on kernel 6.8 (open bug)

Architecture (by design): the cgroup `sock_addr` programs are deliberately
pass-through (`Ok(1) // blocking delegated to tc egress program`). They log
every `CONN_ATTEMPT` and userspace records allowlist verdicts
(`Inserted trust ...: Deny` appears even for allowlisted flows — the default
is Deny in the trust map; per-connection allows come from rule matching).
Actual packet drops happen in the **TC classifiers** (default `TC_ACT_SHOT`
on no match).

On this VM (Ubuntu 24.04, kernel `6.8.0-139-generic`) both TC classifiers
fail `BPF_PROG_LOAD`:

- aya verifier log: a single line `0: R1=ctx() R10=fp0` (buffer is 10KB+, so
  the kernel genuinely logged only that)
- no BPF lines in dmesg/journal at all
- `bpftool prog load` cannot load the object at all: aya's legacy map format
  (`maps` section) is rejected by libbpf v1.0+
- the cgroup programs from the **same object** load fine, so BPF itself works
  in this environment

Observed behavior: allowlisted ports (80, 443 TCP) pass; **non-allowlisted
ports also pass** (8080 TCP returned an HTTP response through enp0s3). The
firewall currently monitors and logs but drops nothing in this environment.

### 5. Connect-only probes are insufficient

`SO_BINDTODEVICE` + TCP connect succeeds even for a connection that will be
cut at send time (the cgroup layer lets connects through; blocking happens on
data). Probes must transfer data (e.g. an HTTP GET) to measure enforcement.
(The port-53 "block" in raw testing was the DNS server not answering an HTTP
probe, not a firewall drop.)

## Open work

- [ ] Get the full verifier rejection: bisect with a minimal `#[classifier]`
      program (isolates "TC BPF broken in this KVM/kernel env" vs "something
      in this program's code"), then fix.
- [ ] Decide target kernel for the VM (user's real machine runs a newer
      kernel; 6.8 may be the wrong baseline).
- [ ] Wire the procedure in this file into a permanent, repo-integrated test
      harness (see ticket).
