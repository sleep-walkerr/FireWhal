# FireWhal Documentation

FireWhal is an application-aware, integrity-checked egress firewall for Linux built
on eBPF. It ties each outgoing connection to the process that opened it, verifies
that the executable (and its process lineage) matches a cryptographic allowlist,
and then enforces per-connection allow/deny rules in the kernel. A terminal UI
drives everything over a local ZeroMQ IPC bus, and blocks can be mirrored to
Discord.

These documents describe the system as it currently stands in this repository.
Line numbers reference the files in-tree at the time of writing.

## Start here

| Document | What it covers |
|---|---|
| [Overview](./overview.md) | What FireWhal is, the problem it solves, the high-level architecture, and the security model. |
| [Components](./components.md) | The eight crates, what each one does, how they relate to each other, the IPC topology, and the startup/shutdown sequence. |
| [Data Paths](./data-paths.md) | The eBPF programs and maps, then each client and server path — slow and fast — in step-by-step detail. |
| [Modes & Features](./modes-and-features.md) | Strict and permissive modes, the permissive-mode workflow, and planned/future work (with ticket references). |

## Reference

| Document | What it covers |
|---|---|
| [VM Enforcement Testing](./vm-enforcement-testing.md) | Findings from the end-to-end enforcement test in the disposable `fw-test` KVM VM. |

## Where things live

- `firewhal-kernel-ebpf/` — the eBPF object (kernel-side programs + maps).
- `firewhal-kernel-common/` — shared `no_std` structs and packet parsers used by both sides.
- `firewhal-kernel/` — the userspace eBPF loader / "Firewall" component.
- `firewhal-core/` — shared userspace types, the IPC message enum, and the ZeroMQ client.
- `firewhal-ipc/` — the ZeroMQ ROUTER (message broker).
- `firewhal-daemon/` — the supervisor / process manager / config authority.
- `firewhal-tui/` — the terminal user interface.
- `firewhal-discord-bot/` — Discord notification sink.
