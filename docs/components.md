# Components & Relationships

FireWhal is a cargo workspace of **eight crates**. Five of them produce runtime
binaries; two are shared libraries; one compiles to an eBPF object. The runtime
topology is a small client/server mesh over a single local ZeroMQ ROUTER socket.

## The eight crates

| Crate | Artifact | Role | Runs as | Privileges |
|---|---|---|---|---|
| `firewhal-kernel-ebpf` | **eBPF object** (not a binary) | The kernel side: TC classifiers, cgroup `sock_addr` hooks, `sock_ops`, and all BPF maps. | kernel | n/a (eBPF) |
| `firewhal-kernel-common` | library (`no_std`) | Shared data types (`ConnectionTuple`, `ConnectionKey`, `RuleKey`, `KernelEvent`, …) and the packet/TCP header parsers used by both the eBPF object and the loader. | n/a | n/a |
| `firewhal-core` | library | Shared userspace types: the `FireWhalMessage` IPC enum, config structs (`Rule`, `FireWhalConfig`, `AppIdentity`, …), and the reusable ZeroMQ **DEALER** client (`ipc_client_connection`). | n/a | n/a |
| `firewhal-kernel` | `firewhal-kernel` binary ("**Firewall**") | Userspace eBPF loader. Loads the object, attaches programs, manages the maps, runs the event loop that verifies processes and applies rules. | root | root (must attach eBPF) |
| `firewhal-ipc` | `firewhal-ipc` binary ("**IPC**") | ZeroMQ **ROUTER** — the message broker. Binds the socket, routes messages by type, tracks registered clients, drops privileges. | `nobody` | drops to `nobody` after bind |
| `firewhal-daemon` | `firewhal-daemon` binary ("**Daemon**") | Supervisor + **config authority**. Starts as root, launches the privileged children, drops to `nobody`, monitors/restarts children, owns the three TOML config files, and pushes config into the kernel. | `nobody` (root during startup) | root → `nobody` |
| `firewhal-tui` | `firewhal-tui` binary ("**TUI**") | Terminal UI (ratatui). Seven screens for status, rules, apps, interfaces, permissive mode, and debug. The user-facing front end. | user | unprivileged |
| `firewhal-discord-bot` | `firewhal-discord-bot` binary ("**DiscordBot**") | Discord notification sink. Receives block events over IPC and DMs the configured user via serenity. | `nobody` | unprivileged |

> The eBPF object (`firewhal-kernel-ebpf`) is intentionally **not** a workspace
> default member — it builds for the eBPF target only and is linked into
> `firewhal-kernel` via `include_bytes_aligned!`. See the workspace `Cargo.toml`
> note.

## How the components relate

There are two distinct relationships to keep straight:

1. **Process supervision** (parent/child) — the *Daemon* owns the others.
2. **Message passing** (peer-to-peer via the router) — every component is an
   independent client of the *IPC* router; they do not talk directly.

### Process tree

```
systemd (firewhal_systemd.service, User=root)
└── firewhal-daemon                       [root → daemonize → nobody]
    ├── firewhal-ipc                      [root, drops to nobody]  (launched in privileged_action)
    ├── firewhal-kernel                   [root]                    (launched in privileged_action)
    └── firewhal-discord-bot              [nobody]                  (launched after forking)

firewhal-tui                              [user, started separately, e.g. from a terminal]
```

- The daemon uses `daemonize` and spawns the two **root** children (`firewhal-ipc`,
  `firewhal-kernel`) inside its `privileged_action` (i.e. *before* it forks to the
  background and drops privileges), because only root can attach eBPF and bind the
  root-only socket. Their PIDs are passed back through a `pipe`.
- The **Discord bot** is launched *after* the daemon has dropped to `nobody`, and
  runs as `nobody`.
- The **TUI** is not a child of the daemon — the user starts it independently; it
  simply connects to the router socket.

### IPC topology

All inter-component traffic flows through one ZeroMQ **ROUTER** socket bound at
`ipc:///tmp/firewhal_ipc.sock` (`firewhal_core::DEFAULT_IPC_ENDPOINT`). Every
client uses a **DEALER** socket and registers by sending
`Status { component, is_healthy: true, message: "Ready" }`. The router keeps a
`component-name → socket-identity` table and routes every other message by type.

Key properties (see `firewhal-ipc/src/lib.rs`):

- **Registration-gated routing.** A component is only a routing target once it has
  sent `Ready`. Messages arriving for a not-yet-registered component are **buffered**
  (bounded to 100/component) and flushed on registration — this closes the slow-joiner
  race where the daemon's rule-load gate could wait forever for a `Firewall → Ready`
  that was dropped.
- **Self-healing.** A dead client connection evicts that client from the table; the
  client's own task reconnects and re-registers. If the router's transport dies it
  unbinds, removes the stale socket file, and rebinds.
- **Privilege drop.** After binding, the router `chown`s the socket file to the
  `firewhal-admin` group, sets mode `0770`, then `setgid`/`setuid`s to `nobody`.

### Message routing table

Component names used by the router: `TUI`, `Daemon`, `Firewall`, `DiscordBot`
(the router itself replies as `IPC`).

| Message | From | Routed to |
|---|---|---|
| `Status{Ready}` | any | register sender; forward (unless it's the Daemon) to `Daemon` |
| `Debug` | non-`TUI` | re-encoded and forwarded to `TUI` |
| `LoadRules` / `LoadAppIds` / `LoadInterfaceState` | `Daemon` | `Firewall` |
| `InterfaceRequest` | `TUI` | `Daemon` |
| `InterfaceResponse` | `Daemon` | `TUI` |
| `UpdateInterfaces` | `TUI` | `Daemon` |
| `Ping` | `TUI` | `Pong` to `TUI` + forwarded to `Firewall`, `Daemon`, `DiscordBot` |
| `Pong` | any | `TUI` |
| `DiscordBlockNotify` | `Firewall` | `DiscordBot` |
| `EnablePermissiveMode` / `DisablePermissiveMode` | `TUI` | `Firewall` |
| `PermissiveModeTuple` | `Firewall` | `TUI` |
| `AddAppIds` | `TUI` | `Daemon` |
| `RulesRequest` / `AppsRequest` | `TUI` | `Daemon` |
| `RulesResponse` / `AppsResponse` | `Daemon` | `TUI` |
| `UpdateRules` / `UpdateAppIds` | `TUI` | `Daemon` |
| `HashRequest` / `HashUpdateRequest` | `TUI` | `Daemon` |
| `HashResponse` / `HashUpdateResponse` | `Daemon` | `TUI` |

`CommandShutdown` and `RuleAddBlock` currently have **no route** (defined in the
enum but not dispatched).

A subtlety worth knowing: **config changes (rules, apps, interfaces) go
`TUI → Daemon → Firewall`**, because the daemon is the config authority and the
persisting side. **Permissive-mode toggles go `TUI → Firewall` directly**, because
they are a runtime flag, not persisted config.

## Startup sequence

1. systemd starts `firewhal-daemon` as root (`Type=forking`, `Before=pre-network.target`).
2. The daemon daemonizes. In its `privileged_action` (still root) it spawns
   `firewhal-ipc` and `firewhal-kernel`, writing their PIDs to a pipe.
3. `firewhal-ipc` binds the router socket, drops to `nobody`, and starts serving.
4. `firewhal-kernel` loads the eBPF object, initializes the eBPF logger, takes
   ownership of the maps, attaches the cgroup programs, attaches TC classifiers to
   the configured interfaces, sets permissive mode off, then sends
   `Status{Firewall, Ready}`.
5. The router forwards that `Ready` to the daemon. **Only then** does the daemon
   read the three TOML config files and send `LoadRules` + `LoadAppIds` +
   `LoadInterfaceState` to the Firewall.
6. The user starts `firewhal-tui`; it connects, registers as `TUI`, and `Ping`s to
   populate the status screen.

## Shutdown sequence

- On `SIGTERM`/`SIGINT`, the daemon's shutdown handler broadcasts an internal
  shutdown, then sends `SIGTERM` to all children and waits up to 5 s for graceful
  exit, escalating to `SIGKILL` for stragglers.
- The Firewall, on shutdown, sends a final `Pong` and detaches its eBPF programs.
- Each component's IPC task also watches a `broadcast` shutdown signal and exits
  cleanly, dropping its DEALER socket.

## Config authority (the daemon)

The daemon owns three TOML files (in the deployed layout, `/opt/firewhal/bin/`):

| File | Contents | Loaded as |
|---|---|---|
| `firewall_rules.toml` | `[[outgoing_rules]]` / `[[incoming_rules]]` | `FireWhalConfig` → `RULES` / `INCOMING_RULES` maps |
| `app_identity.toml` | `[apps.<id>] path + hash` | `ApplicationAllowlistConfig` → userspace allowlist |
| `interface_state.toml` | `enforced_interfaces = [...]` | `InterfaceStateConfig` → which TC programs attach where |

Every mutation (from the TUI) is written to disk first, then re-read and pushed to
the Firewall, so the file is the single source of truth. See
[VM Enforcement Testing](./vm-enforcement-testing.md) for the documented config-path
mismatch that this layout is sensitive to.
