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

## S1 SSH-block phase (gate phase 7, since 2026-09-27)

Phase 7 is the **deliberate SSH block** (ticket #106, design doc
`docs/comprehensive-test-design.md` §2.2) — a feature test, not a bug hunt:
the firewall must be able to cut SSH when told to, and it must touch exactly
what the rules say. It asserts the **M1 mgmt collateral guard** (§2.3) live,
in the same window.

**Inversion for this rig** (documented in §2.2): FireWhal enforces only on
`enforced_interfaces` (`enp0s3` here), so a rule targeting the mgmt NIC
(`enp0s2`) would be a no-op — there are no hooks on that interface. The block
therefore targets the *enforced* path — incoming `tcp/22` on `enp0s3`, i.e.
the `2223` hostfwd — and the unenforced mgmt path (`2222`) must stay up for
the whole window.

1. **Baseline** — both `2223` (OOB, via the enforced path) and `2222` (mgmt)
   up.
2. **Block** — the guest backs up `firewall_rules.toml`, arms a VM-local
   self-expiry sleeper (a detached `setsid` guest process, `fw-e2e-s1-unlock`;
   window 120 s default, `FW_S1_WINDOW` overridable; state in
   `/var/lib/fw-e2e/`) that restores the config and restarts the stack —
   **the VM owns its own unlock**, independent of SSH state — then drops the
   incoming `:22` rule and restarts the stack.
3. **Window** — from the host: `ssh -p 2223` must fail 100 % (the rule cut
   SSH, as configured); the mgmt ping must stay 100 % healthy (M1 — no
   collateral lockout). Wire-verified in-guest: the block log carries the
   verdict `No ingress rule matched. Blocking connection from
   10.0.3.2:<port>`, and the capture shows **no guest reply** (no frame with
   the ACK flag for `:22`) — see the capture-semantics finding below.
4. **Self-expiry & recovery** — the sleeper fires, the config is restored
   byte-for-byte, the stack restarts, and `2223` comes back with no outside
   intervention; a second capture proves `:22` traffic crosses the boundary
   again.
5. **Record & reconnect** — a guest timeline
   (`/var/lib/fw-e2e/fw-s1-timeline`) records
   rule-up → block → rule-down (self-expiry) → restored; the gate reconnects
   and asserts the record, the config restore, and readiness.

**Safety** (design §2.2): the only path to losing SSH is the *passing* path,
and the self-expiry restores it. If the block regresses (no cut), `2223`
stays up and the "must be down" checks fail; if the self-expiry fails,
`2222` is never at risk — the test can never lock us out of itself.

### S1 findings (first runs, 2026-09-27)

- **Direction-dependent capture semantics:** on this rig the *ingress*
  AF_PACKET tap sits **upstream** of the TC ingress drop — blocked SYNs are
  visible in the guest `tcpdump` (flags `S` only, no reply), while the
  *egress* tap is downstream (D1's block leg: 0 frames). The design doc's
  "frame not in the capture = never crossed the boundary" oracle holds for
  egress; for ingress the oracle is "the guest never replies" (no frame with
  the ACK flag for the probe flow).
- **Guest real-time delays run late:** the guest runs NTP
  (systemd-timesyncd active; the RTC is ~37 s behind at boot), and the
  resulting real-time slewing makes real-time delays fire +6 s..+43 s over
  (measured on the original `OnActiveSec` timer implementation: a 10 s
  control timer took 16 s; the 30 s dry runs took 51 s/73 s; the 120 s gate
  window fired 17 s late). The same slewing affects the current sleeper's
  `sleep` (it is CLOCK_REALTIME too). The block lifts *later* than the window
  — the safe direction — and the gate's recovery deadline absorbs the
  observed lag (`window + 120 s`).
- **Kernel quirk (guest kernel 6.8, Ubuntu):** root `open(O_CREAT)` on a
  **non-root-owned** file inside a **sticky** dir (`/tmp`) returns EACCES,
  while root-owned files in the same dir are fine (reproducible, isolated by
  an owner/dir/user matrix: owner appends and non-sticky dirs are OK). The
  timeline file is created `root:ubuntu 662` so both the ubuntu-side appends
  (block script, gate window line) and the root-side appends (the
  self-expiry) work. (The timeline moved from /tmp to /var/lib/fw-e2e —
  a non-sticky dir, where the quirk does not apply — but the ownership is
  kept for the cross-user appends.)
- **Self-expiry mechanism: not systemd.** The first implementation used a
  VM-local systemd one-shot + timer. Two traps, both on this guest
  (systemd 255.4-1ubuntu8.17):
  - a daemonized daemon started from a `Type=oneshot` unit stays in the
    unit's cgroup and is SIGTERMed when the unit completes (default
    `KillMode=control-group`; observed on the first dry run: daemon log
    mtime == unit finish, "stack not ready" afterwards);
  - the fix `KillMode=main` is **rejected by this systemd** ("Failed to
    parse kill mode specification, ignoring: main" — reproduced with
    `systemd-analyze verify` on the intact unit, file byte-clean), so the
    default kill mode applied silently and the first full gate run killed
    the just-restored stack at unit finish: the "recovered" 2223 was
    fail-open (no enforcement), the recovery capture was unfiltered, and
    the verify's `stack_ready` correctly reported the dead stack for its
    full 120 s.
  The implementation is therefore a detached `setsid` sleeper (sleep out the
  window, then run the unlock as root) — no kill-mode semantics, no
  periodic-timer re-fire risk; ssh-spawned process survival is proven in
  this rig (the deploy daemon and per-leg captures outlive their ssh
  sessions; a logged-out session scope kept a recovery capture alive for
  105 s). The self-expiry does not survive a guest reboot (the block
  persists on the throwaway overlay, fail-closed by design).
- **Guest /tmp is not durable:** every /tmp artifact of the failed run
  (timeline, snapshots, pcaps, backup, daemon logs) was gone after the
  forensic reboot, while /etc state survived; /tmp is disk-backed (not a
  tmpfs) and the tmpfiles rules are stock 30 d, so the exact agent is
  unidentified (boot-bound, 02:31-epoch). S1 state therefore lives in
  `/var/lib/fw-e2e/` (the daemon's own logs stay in /tmp — the binary
  hardcodes the path; the block-window snapshot protects what verify needs).
- **Guest journal is lossy on this image:** all journal files cap at exactly
  8 MiB and the post-rotation segment does not survive to the archive (the
  failed run's journal stops 40 s before the guest died). For forensics,
  the guest timeline + the host tee-log of the gate are the authoritative
  record, not `journalctl`.
- **Verdict-line grep hardened:** the first full gate run failed the
  block-verdict check even though the printed haystack (byte-verified clean
  ASCII) contained the matching line; the mechanism was not fully
  determined, so the check now greps the snapshot file directly (no
  `$(cat)`-into-variable, no pipe), which removes the mechanism class.

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
- [x] S1 SSH-block + M1 mgmt collateral guard (gate phase 7, 2026-09-27;
      see the S1 section above for the inverted mechanism + first-run
      findings).
- [ ] Remaining #106 sequence: C1 config-path fail-loud, R resilience
      (ticket #114), CI on a KVM runner. Host-side TAP/netns wire visibility:
      ticket #115.
