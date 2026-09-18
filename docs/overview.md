# Overview

FireWhal is an application-aware, integrity-checked firewall for Linux. Instead of
treating the network as a bag of IP addresses and ports, it ties every connection
to **the process that opened it**, verifies that the executable (and the whole
process lineage above it) matches a cryptographic allowlist, and only then lets it
communicate with destinations permitted by the rule set.

The core threat it addresses: Linux egress filtering is *path-based*. If you allow
`/usr/bin/curl`, then a **tampered or replaced** binary at the same path gets the
same network access. FireWhal makes trust a function of *content*, not just
location: each allowed application is a `(path, SHA3-256 hash)` pair, and the hash
is re-checked against the running binary. A patched binary is a *different* hash,
so it is treated as a new, untrusted application and blocked.

## The problem

- **No application identity on Linux egress.** Windows has a per-process firewall
  story; Linux `nftables`/`iptables` rules match on addresses, ports, and marks,
  not on "which program is this socket owned by."
- **No integrity awareness.** Even path-based allow rules are only as strong as the
  filesystem. A local attacker who can write to an allowed binary inherits its
  privileges.
- **Coarse control.** "Allow port 443 out" is all-or-nothing; there is no native
  way to say "only *this* verified browser may talk to 443."

## The solution

FireWhal composes several eBPF hooks to build a **two-gate, default-deny** model:

1. **Application gate.** When a process attempts a connection (or binds a port), a
   cgroup `sock_addr` hook records the attempt. Userspace walks the process's
   lineage, hashes each executable with SHA3-256, and checks the allowlist. The
   result — `Allow` or `Deny` — is cached per-process (`tgid`) in a kernel map.
2. **Network gate.** Every packet is inspected by a TC (traffic control)
   classifier. A packet is allowed only if *both* its owning process is trusted
   *and* an explicit allow rule matches its (protocol, address, port) tuple.
   Default is deny at every layer.

Return traffic for an allowed outgoing connection is then permitted *statefully*
(the reverse tuple is remembered), without re-running the application check.

```
                                   ┌────────────────────────────────────────────┐
                                   │                 firewhal-daemon            │
                                   │   (supervisor + config authority)          │
                                   └───────────────┬───────────────┬────────────┘
        launches & supervises                       │               │
            ┌─────────────────────┬────────────────┴───┐           │
            │                     │                     │           │
   ┌────────▼────────┐   ┌────────▼────────┐   ┌────────▼──────────┐
   │  firewhal-ipc   │   │ firewhal-kernel │   │ firewhal-discord  │
   │  (ZMQ ROUTER)   │◄──┤ (eBPF loader /  │   │ -bot (nobody)     │
   │  (nobody)       │   │  Firewall, root)│   │  ← block notices  │
   └────────┬────────┘   └────────┬────────┘   └───────────────────┘
            │  routes messages    │  loads & attaches eBPF
            │  (ipc:///tmp/...)   │
   ┌────────▼────────┐            │
   │   firewhal-tui  │            │   ┌──────────────────────────────────────────┐
   │  (user UI)      │            │   │        firewhal-kernel-ebpf (kernel)     │
   └─────────────────┘            │   │  TC classifiers (ingress/egress)         │
        reads/writes config       │   │  cgroup sock_addr (connect/sendmsg/bind) │
        (via daemon)              └──►│  sock_ops (socket state)  + BPF maps     │
                                      └──────────────────────────────────────────┘
```

See [Components](./components.md) for the full crate-by-crate breakdown and the
message routing table.

## Security model (summary)

- **Default deny, everywhere.** An untrusted process cannot connect; a trusted
  process cannot connect to a non-allowlisted destination; unmatched traffic is
  dropped at the TC layer.
- **Integrity via SHA3-256.** Trust is `(path, hash)`. The hash of the *running*
  binary is recomputed in-process and compared. Lineage
  walking means a trusted interpreter does not automatically trust an arbitrary
  script it runs — each level is checked.
- **Per-connection tracking.** Connections move through `PENDING → TRUSTED` state
  as they are verified. Stale trust (a process that died, or whose binary changed)
  is pruned, and per-connection sockets can be trusted by *socket cookie*.
- **Privilege separation.** The kernel loader runs as root (it must attach eBPF);
  the IPC router and the Discord bot drop to `nobody`. The IPC socket file is
  `chown`ed to a `firewhal-admin` group with mode `0770` so only authorized
  local users can talk to the stack.
- **Stateful return path.** Once an egress connection is allowed, its reverse
  tuple is stored so ingress (return) packets are accepted without re-verification.

## Design goals and trade-offs

- **Kernel-side enforcement, userspace policy.** The fast path (per-packet
  allow/drop) runs entirely in eBPF so it is fast and cannot be bypassed from a
  compromised userspace process. The *slow* path (hashing, lineage, policy
  decisions) runs in userspace where it can be slow and complex without impacting
  the data path.
- **Integrity over convenience.** FireWhal deliberately re-hashes binaries and
  re-verifies on connection, favoring security over performance. This is why a
  standalone hasher and a permissive mode exist (see [Modes & Features](./modes-and-features.md)).
- **Single source of truth for config.** The daemon owns the three TOML config
  files and is the only component that writes them; the TUI talks to the daemon,
  and the daemon pushes changes into the kernel maps.

The next documents go deeper: [Components](./components.md) explains who does what
and how they talk; [Data Paths](./data-paths.md) walks each client/server packet
path in detail; [Modes & Features](./modes-and-features.md) covers strict/permissive
operation and future work.
