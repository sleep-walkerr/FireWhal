# Modes & Features

## Operating modes

FireWhal has one always-on enforcement mode (strict) and one temporary,
review-oriented mode (permissive). Everything below is keyed off the
`PERMISSIVE_MODE_ENABLED` BPF map (a one-element `u32` array) unless noted.

### Strict mode (default)

The normal operating state. Every new process is **verified** on its first
connection attempt (path C1 in [Data Paths](./data-paths.md)):

- The process lineage is walked, each binary is SHA3-256-hashed, and the result is
  compared against the allowlist.
- `Allow` → the `tgid` is cached in `TRUSTED_PIDS`; the process may connect to
  rule-permitted destinations.
- `Deny` (unknown path, hash mismatch, hash error) → the `tgid` is recorded as
  denied and its traffic is blocked.

Strict mode is what runs at boot — the loader explicitly sets the permissive flag
to `0` on startup (`update_permissive_mode_flag(..., false)`), so the stack never
starts permissive by accident.

### Permissive mode (current implementation)

A temporary **detection/approval** mode for building the allowlist. It is **not**
"the firewall is off" — rule enforcement stays on; only the *application gate* is
relaxed, so new applications can be observed and then explicitly approved.

**How it is toggled.** Entering the TUI's *Permissive Detection* screen sends
`EnablePermissiveMode`; leaving it sends `DisablePermissiveMode`
(`firewhal-tui/src/main.rs`, screen enter/exit handlers). The TUI routes both
straight to the Firewall (they are runtime flags, not persisted config).

**What enabling does** (`firewhal-kernel` main loop):

1. Sets `PERMISSIVE_MODE_ENABLED[0] = 1`.
2. `prune_denied_pids` — removes all `Deny` entries from `TRUSTED_PIDS` and the
   userspace cache, so previously-rejected processes get a fresh look.

**What happens per new connection while enabled** (event loop, permissive branch):

1. The process lineage is walked and **every** binary in it is hashed.
2. The `(path, hash)` pairs are packaged into a `ProcessLineageTuple` and sent to
   the TUI as `PermissiveModeTuple`.
3. The process is immediately allowed (placeholder hash `"PERMISSIVE_ALLOW"`) and
   recorded in `TRUSTED_PIDS`.

**The TUI side.** The *Permissive Detection* screen shows two panels:

- **Lineages** — one row per observed process tree (`a -> b -> c`, root to leaf).
- **Processes** — the individual `(path, hash)` entries of the selected lineage;
  toggle entries with **Space**, approve the selection with **Enter**.

Approving sends `AddAppIds` → the **Daemon** merges the entries into
`app_identity.toml` (updating hashes in place for existing paths, adding new ones)
and pushes a fresh `LoadAppIds` to the Firewall. Approved apps are now part of the
permanent allowlist.

**What disabling does.** `on_disable_permissive_mode` wipes **all** trust state:
`TRUSTED_PIDS`, `TRUSTED_CONNECTIONS_MAP`, `PENDING_CONNECTIONS_MAP`, and the
userspace cache. Every process must be re-verified from scratch on its next
connection — so permissive mode cannot leak trust into strict mode.

## Planned permissive work (from the tickets)

The user has described where permissive mode is headed; these are open tickets
that define it:

### #75 — Permissive *Traffic* Mode

Today's permissive mode is an **app** mode: it relaxes application verification.
The planned **permissive traffic mode** would instead ignore the **rules** and, for
each connection tuple that *would be inserted* into the connection maps, send it to
the userspace loader → TUI for review (mirroring how permissive app mode works, but
at the connection level).

Open sub-problems called out in the ticket:

- A mechanism to avoid sending **duplicate** tuples (userspace processing strain).
  The ticket suggests only sending a connection key **when an insertion actually
  happens** — noting that tuple insertion currently happens in more than one place
  and should be consolidated to one.
- Fixing **missing fields** in some connection keys (missing source port/address,
  and occasionally destination port) before they can be displayed/used.

### #91 — Permissive Mode from File

Make permissive mode state **persistent** rather than a transient flag:

- Permissive mode would be persistently enabled or disabled.
- All permissive-mode **outputs** (the observed lineages/approvals) would go to a
  **TOML file** instead of only the live TUI screen.
- When the permissive interface is entered, the TUI would **request the file and
  display its contents** (rather than an empty, in-memory list).

### #65 — Separate Program Instead of a Flag

The current design switches behavior with the `PERMISSIVE_MODE_ENABLED` boolean
read in the event loop. The stated best practice is to have **two separate
`egress_tc` programs** — a strict one and a permissive one — and **detach/attach**
whichever is active when the mode changes, rather than branching on a flag.

## Features

| Feature | Where | Notes |
|---|---|---|
| **Two-gate default-deny model** | eBPF + loader | App gate (process trust) and network gate (rules); deny at every layer. See [Overview](./overview.md). |
| **All-IPv6 blocked** | TC classifiers | IPv6 packets on enforced interfaces are dropped (`TC_ACT_SHOT`), so v6 cannot bypass the app or rule gates (which are IPv4-only). Unhandled ether types (ARP, VLAN, ...) still pass through. |
| **Process lineage verification** | loader event loop | Walks up to 10 ancestors via `/proc/<pid>/exe` + `PPid`; each level is hash-checked, so a trusted interpreter does not auto-trust an arbitrary script. |
| **SHA3-256 integrity checking** | shared `firewhal_core` helper, loader, daemon | Trust is `(path, hash)`; the running binary is re-hashed in-process and compared. A tampered binary is a different hash → untrusted. |
| **Stateful return traffic** | `CONNECTION_MAP` | An allowed egress tuple admits its reversed (return) traffic without re-checking. |
| **Per-connection trust states** | `PENDING` / `TRUSTED` maps | Connections are promoted as they are verified; stale trust is pruned. |
| **Socket-cookie trust (server)** | `TRUSTED_COOKIES` + `sock_ops` | An established server connection is trusted by cookie and fast-pathed. (Cleanup-on-close is a known gap — see [Data Paths](./data-paths.md#path-s4--server-fast-path-egress-tc-via-trusted_cookies--cleanup).) |
| **Rule wildcards** | `rule_matching` / `ingress_rule_matching` | Egress probes 6 most→least-specific keys; ingress 5. Zero fields = wildcards. |
| **Per-interface enforcement** | `LoadInterfaceState` + TC attach/detach | TC programs are attached only to the interfaces listed in `interface_state.toml`; the loader diffs the set to attach new / detach stale interfaces. |
| **Hash refresh** | daemon `correct_hash_for_app_id` | Re-hashes an app's current binary on demand (TUI *Hash* request) to keep stored hashes current. |
| **Discord block notifications** | `firewhal-discord-bot` | A `BlockEvent` is mirrored to a Discord DM of the configured user (serenity). |
| **Self-healing IPC** | `firewhal-ipc` + client tasks | Registration-gated routing, bounded pending buffers, dead-peer eviction, and router rebind all keep the mesh alive across restarts. |
| **Privilege separation** | daemon, ipc, bot | Root only where eBPF attach requires it; router and bot drop to `nobody`; socket restricted to the `firewhal-admin` group. |
| **Graceful shutdown** | daemon | Two-phase (SIGTERM, 5 s grace, then SIGKILL) coordinated shutdown of all children. |

## Known limitations & caveats

These are documented, open issues rather than design goals:

- **Byte-order inconsistency** in rule keys — outgoing rules are keyed with
  `from_le_bytes` while incoming rules use `from_be_bytes`, and the eBPF parser
  also uses `from_le_bytes` on big-endian header bytes. Symptom: "rules only work
  with reversed IP addresses." See [Data Paths §3](./data-paths.md#3-key-data-structures-firewhal-kernel-common) and the Final Report's Troubleshooting table.
- **Stale socket cookies** — `TRUSTED_COOKIES` is never cleaned on connection close
  (no close hook). See ticket #90 / #68.
- **`SOCKET_COOKIE_TRUST` map** is present but unused by the current code path.
- **TC load failure ⇒ fail-open** — if the TC classifiers fail to load, packets
  are never dropped. The root cause (non-whitelisted `SCHED_CLS` helper calls) and
  the fix are covered in [VM Enforcement Testing](./vm-enforcement-testing.md) and
  PR #97.
- **Config path sensitivity** — the daemon reads its three TOML files from
  `/opt/firewhal/bin/`, not `/opt/firewhal/config/`; a deploy that puts them in the
  "obvious" location starts the firewall with zero rules and no error.
