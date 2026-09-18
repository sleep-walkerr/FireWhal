# FireWhal

An application-aware, integrity-checked firewall for Linux, built on eBPF.

FireWhal ties every connection to **the process that opened it**, verifies that the
executable (and its process lineage) matches a cryptographic allowlist, and only
then lets it talk to destinations permitted by the rule set. A terminal UI drives
everything over a local ZeroMQ bus, and blocks can be mirrored to Discord.

The core idea: Linux egress filtering is *path-based* and has no concept of
application identity or integrity — if you allow `/usr/bin/curl`, a **tampered**
binary at the same path gets the same access. FireWhal makes trust a function of
*content*, not location: each allowed application is a `(path, SHA3-256 hash)`
pair, re-checked against the running binary. A patched binary is a different hash,
so it is treated as a new, untrusted application and blocked.

## How it works (in one paragraph)

FireWhal composes several eBPF hooks into a **two-gate, default-deny** model. A
cgroup `sock_addr` hook records every connection attempt; userspace walks the
process lineage, SHA3-256-hashes each binary, and checks the allowlist, caching the
result per process. Every packet then passes a TC (traffic control) classifier,
where it is allowed only if *both* its owning process is trusted *and* an explicit
allow rule matches its (protocol, address, port) tuple. Default is deny at every
layer. Return traffic for an allowed connection is then permitted statefully.

```
  TUI ────────────────┐
                      │  ZeroMQ ROUTER  (ipc:///tmp/firewhal_ipc.sock)
  Discord bot ────────┤            │
                      │            │ routes by message type
  Daemon (supervisor) ┤            │  + owns the TOML config
                      │            ▼
                      │     firewhal-kernel  (root)
                      │        loads + attaches  ▼
                      │   ┌──────────────────────────────────────────┐
                      └──┤ firewhal-kernel-ebpf  (kernel, eBPF)      │
                          │  TC classifiers · cgroup sock_addr        │
                          │  sock_ops · 13 BPF maps                   │
                          └──────────────────────────────────────────┘
```

## Features

- **Two-gate default-deny** — application gate (is the *process* trusted?) and
  network gate (is the *destination* allowed?), both defaulting to deny.
- **SHA3-256 integrity checking** — trust is `(path, hash)`; the running binary is
  re-hashed and compared, so a replaced binary loses its trust.
- **Process-lineage verification** — walks up to 10 ancestors, so a trusted
  interpreter does not automatically trust an arbitrary script it runs.
- **Stateful return path** — allow an egress connection once and its return traffic
  is admitted without re-checking.
- **Per-connection trust states** — connections move `PENDING → TRUSTED` as they
  are verified; stale trust is pruned; established server connections are trusted by
  socket cookie.
- **Permissive detection mode** — observe and explicitly approve new applications
  to build the allowlist (see [Modes & Features](./docs/modes-and-features.md)).
- **Per-interface enforcement** — TC programs attach only to interfaces you select.
- **Discord notifications** — blocks are DM'd to a configured user.
- **Privilege separation** — root only where eBPF attach requires it; the IPC router
  and Discord bot drop to `nobody`; the IPC socket is restricted to a `firewhal-admin`
  group.

## Components

Eight crates in a cargo workspace (five runtime binaries, two shared libraries, one
eBPF object):

| Crate | Role |
|---|---|
| `firewhal-kernel-ebpf` | The eBPF object: TC classifiers, cgroup `sock_addr` hooks, `sock_ops`, all BPF maps. |
| `firewhal-kernel` | Userspace eBPF loader / the "Firewall" component (runs as root). |
| `firewhal-ipc` | ZeroMQ ROUTER — the message broker (drops to `nobody`). |
| `firewhal-daemon` | Supervisor + config authority; starts and monitors everything. |
| `firewhal-tui` | The terminal user interface. |
| `firewhal-discord-bot` | Discord notification sink. |
| `firewhal-core` | Shared userspace types + the IPC message enum + the ZMQ client. |
| `firewhal-kernel-common` | Shared `no_std` structs + packet parsers (kernel & userspace). |

## Requirements

- A Linux distribution with kernel **5.8+** (newer is better; the eBPF features used
  are `cgroup/sock_addr`, `sock_ops`, and TC classifiers).
- Rust (stable + nightly), via `rustup`.
- LLVM from the system package manager, and `bpf-linker` (via Cargo).
- The `firewhal-admin` system group and a `nobody` user (the install scripts create
  the group; re-login afterward).

## Building & installing

Install scripts live in the repo root. `release_install.sh` builds the workspace in
release mode and installs the binaries; `debug_install.sh` does the same for debug
builds. Both:

- create the `firewhal-admin` group (and offer to add your user to it),
- copy the three config files (`app_identity.toml`, `firewall_rules.toml`,
  `interface_state.toml`) into `/opt/firewhal/bin`,
- install the binaries (daemon to `/usr/local/sbin`, the rest to `/opt/firewhal/bin`,
  the TUI to `/usr/local/bin`), and
- `chmod 755` the install directory.

The firewall runs as a systemd service (`firewhal_systemd.service`); start it with:

```sh
sudo systemctl enable --now firewhal_systemd
```

Run the TUI with:

```sh
firewhal-tui
```

### Development notes

Run the eBPF program under `sudo` from a terminal:

```sh
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' --
```

Sync a local build to a remote test VM with Mutagen:

```sh
mutagen sync create --name=firewhal-dir-syncing --sync-mode=one-way-replica \
    {directory to send} {user}@{ip or hostname}:{target directory} -i target
```

> **Note on config location:** the daemon reads its three TOML files from
> `/opt/firewhal/bin/` (not a separate `config/` directory). Placing them elsewhere
> starts the firewall with zero rules and no error. See
> [VM Enforcement Testing](./docs/vm-enforcement-testing.md).

## Documentation

- [**Documentation index**](./docs/README.md)
- [Overview](./docs/overview.md) — the problem, the security model, the architecture
- [Components & Relationships](./docs/components.md) — the eight crates, the IPC routing table, startup/shutdown
- [Data Paths](./docs/data-paths.md) — every client/server path (slow & fast), step by step
- [Modes & Features](./docs/modes-and-features.md) — strict & permissive modes, permissive future work
- [VM Enforcement Testing](./docs/vm-enforcement-testing.md) — findings from the end-to-end test in the `fw-test` KVM VM

## License

MIT — see [LICENSE](./LICENSE).
