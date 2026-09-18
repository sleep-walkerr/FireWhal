# Data Paths

This document walks every path a packet or a connection attempt takes through
FireWhal, for both the **client** (a local app initiates an outgoing connection)
and the **server** (a remote peer connects to a local listener), in both the
**slow** (first-time, userspace-involving) and **fast** (steady-state, kernel-only)
forms. It is organized to match the seven B-side slides of the project deck.

Before the paths, this section defines the vocabulary: the eBPF **programs**, the
BPF **maps**, and the key **data structures**.

---

## 1. eBPF programs

All live in `firewhal-kernel-ebpf/src/main.rs`. "Client" and "server" below are
perspectives on the *local* machine.

| Program | Hook | Direction | Purpose |
|---|---|---|---|
| `firewhal_egress_connect4` | cgroup `sock_addr` on `connect(2)` (IPv4/TCP) | out | Instrument the connect; kick off app verification. Never blocks. |
| `firewhal_egress_sendmsg4` | cgroup `sock_addr` on `sendmsg(2)` (IPv4/UDP) | out | Same as above for UDP. |
| `firewhal_egress_bind4` | cgroup `sock_addr` on `bind(2)` (IPv4) | in (listener) | Record which process owns a listening port. |
| `firewhal_egress_tc` | TC classifier (egress) | out | **The enforcement point.** App gate + rule gate for every outgoing packet. |
| `firewhal_ingress_tc` | TC classifier (ingress) | in | Allow stateful return traffic; else stateless incoming rules. |
| `firewhal_sock_ops` | `sock_ops` | in (listener) | On passive (server) socket established, trust the connection by cookie. |

Two helper routines do most of the work:

- `app_tracking(prog_name, ctx)` (line 74) — shared by the three `sock_addr` hooks.
- `rule_matching(ctx, tuple, info)` (line 167, egress, 6-level wildcard) and
  `ingress_rule_matching(ctx, tuple)` (line 252, ingress, 5-level wildcard).

A recurring theme: **the cgroup hooks only record and verify; the TC classifiers
enforce.** A cgroup `sock_addr` hook always returns `OK` and leaves the actual
drop to `firewhal_egress_tc`.

## 2. BPF maps

| Map | Type | Key → Value | Written by | Read by |
|---|---|---|---|---|
| `EVENTS` | `PerfEventArray` | — → `KernelEvent` | eBPF | userspace loader (per-CPU) |
| `RULES` | `HashMap` (1024) | `RuleKey` → `RuleAction` | loader (`LoadRules`) | egress TC |
| `INCOMING_RULES` | `HashMap` (1024) | `RuleKey` → `RuleAction` | loader (`LoadRules`) | ingress TC |
| `CONNECTION_MAP` | `LruHashMap` (4096) | `ConnectionTuple` → `ConnectionInfo` | egress TC (on allow) | ingress TC (return traffic) |
| `TRUSTED_PIDS` | `HashMap` (4096) | `u32` tgid → `PidTrustInfo` | userspace loader | all TC paths |
| `PENDING_CONNECTIONS_MAP` | `HashMap` (4096) | `ConnectionKey` → `u32` tgid | cgroup hooks | egress TC |
| `TRUSTED_CONNECTIONS_MAP` | `HashMap` (4096) | `ConnectionKey` → `u32` tgid | egress TC | egress TC |
| `SOCKET_COOKIE_TRUST` | `HashMap` (4096) | `u64` → `u32` | — (legacy) | — (currently unused in the active flow) |
| `PERMISSIVE_MODE_ENABLED` | `Array<u32>` (1) | `0` → flag | loader | userspace loader |
| `PENDING_LISTENING_PORTS` | `HashMap` (1024) | `u32` port → `u32` tgid | `bind4` | egress TC (SYN-ACK) |
| `TRUSTED_LISTENING_PORTS` | `HashMap` (1024) | `u32` port → `u32` tgid | egress TC (promote) | `sock_ops`, egress TC |
| `TRUSTED_COOKIES` | `HashMap` (10000) | `u64` cookie → `u8` | `sock_ops` | egress TC (fast path) |
| `HANDSHAKE_ALLOWED` | `HashMap` (4096) | `ConnectionTuple` → `u64` | ingress TC (SYN allow) | egress TC (SYN-ACK), `sock_ops` (cleanup) |

## 3. Key data structures (`firewhal-kernel-common`)

| Type | Fields | Notes |
|---|---|---|
| `ConnectionTuple` | `saddr`, `daddr` (u32), `sport`, `dport` (u16), `protocol` (u8), `_pad` | 16 bytes. Addresses/ports are **network byte order**. Used as the stateful key. |
| `ConnectionKey` | same fields as `ConnectionTuple` (plus `_padding`) | 16 bytes. Used for the pending/trusted connection maps. |
| `RuleKey` | `protocol` (u32), `source_port`, `dest_port` (u16), `source_ip`, `dest_ip` (u32) | Rule match key; zero fields act as wildcards. |
| `RuleAction` | `action` (`Allow`/`Deny`), `rule_id` | |
| `PidTrustInfo` | `action`, `last_seen_ns` | Per-process trust decision. |
| `KernelEvent` | `event_type`, `pid`, `tgid`, `comm[16]`, `payload` (union) | Kernel → userspace event. |

> **Byte-order caveat.** The eBPF parser builds address `u32`s with
> `u32::from_le_bytes` on the raw big-endian header bytes
> (`firewhal-kernel-common/src/lib.rs:85`), while the userspace rule loader uses
> `from_le_bytes` for outgoing rules but `from_be_bytes` for incoming rules
> (`firewhal-kernel/src/main.rs:268` vs `:329`). This endianness inconsistency is
> the documented "rules only work with reversed IP addresses" bug — see the
> Final Report's Troubleshooting table and [VM Enforcement Testing](./vm-enforcement-testing.md).

---

# Client paths

*The local application is the connection initiator (e.g. a browser talking to a
website).*

## Path C1 — Client slow path: **syscall** (cgroup `connect4` / `sendmsg4`)

**Trigger:** the client process calls `connect(2)` (TCP) or `sendmsg(2)` (UDP).
The kernel runs `firewhal_egress_connect4` / `firewhal_egress_sendmsg4`, both of
which call `app_tracking()`.

**What happens** (`app_tracking`, `firewhal-kernel-ebpf/src/main.rs:74`):

1. Read `tgid`, destination IP, destination port, and protocol from the
   `SockAddrContext`.
2. Look up `TRUSTED_PIDS[tgid]`:
   - **Hit, action == Allow** → insert a *pending* connection key
     `ConnectionKey{daddr, dport, protocol}` (source fields zeroed) into
     `PENDING_CONNECTIONS_MAP[key] = tgid`. Done. The app is already trusted; the
     flow is just noted as pending.
   - **Miss (unverified)** → build a `ConnectionAttemptPayload{key}` and emit a
     `KernelEvent{ConnectionAttempt, pid, tgid, comm}` on the `EVENTS` perf
     array. *Also* insert the same pending key into `PENDING_CONNECTIONS_MAP`.
3. Return `SOCK_ADDR_OK` in both cases — **the cgroup hook never blocks**; it only
   records the attempt and triggers verification. (Comment in code: *"blocking
   delegated to tc egress program."*)

**Userspace half** (`firewhal-kernel` event loop, per-CPU `EVENTS` reader):

1. **Cache check** — if `tgid` is already in the userspace
   `active_process_cache`, skip (already decided).
2. Otherwise (cache miss) **walk the process lineage** up to 10 ancestors via
   `/proc/<pid>/exe` + `/proc/<pid>/status` (PPid), collecting each binary path.
3. Read `PERMISSIVE_MODE_ENABLED`:
   - **Permissive ON** → hash every binary in the lineage, package them into a
     `ProcessLineageTuple`, send `FireWhalMessage::PermissiveModeTuple` to the TUI,
     and decide **Allow** with a placeholder hash `"PERMISSIVE_ALLOW"`.
   - **Permissive OFF** → walk the lineage (root first); for each path in the
     allowlist, hash the on-disk binary with `firewhal-hashing` and compare to the
     stored hash. Path match + hash match → **Allow**; mismatch or no path match →
     **Deny**.
4. Record the decision: `TRUSTED_PIDS[tgid] = PidTrustInfo{action, last_seen_ns: 0}`
   and insert into the userspace cache.

**Result:** the application gate is decided; the pending connection is queued for
the TC layer. The expensive work (lineage walk + SHA3-256 hashing + a userspace
round-trip) happens **once, here**.

---

## Path C2 — Client slow path: **traffic** (first packet, egress TC)

**Trigger:** the first real packet of the connection hits `firewhal_egress_tc`.

**What happens** (`try_firewhal_egress_tc`, line 505), in order:

1. `parse_packet_tuple(&ctx)` → `ConnectionTuple`. Non-IPv4 / unsupported →
   parse error → **allow** (traffic type not yet handled).
2. **DHCP special case:** if `saddr == 0.0.0.0` and `daddr == 255.255.255.255`,
   record a broadcast tuple (zeroed addresses) in `CONNECTION_MAP` and **allow**.
3. Build keys: `full_key` (the whole tuple), `pending_key` (source-zeroed), and a
   `portless` variant.
4. **Cookie check:** `bpf_get_socket_cookie`. If `TRUSTED_COOKIES[cookie]` exists →
   **allow immediately** (that's the server fast path; client sockets usually
   aren't there yet).
5. **App gate / connection state** (most → least):
   - `TRUSTED_CONNECTIONS_MAP[full_key]` → hit means fast path (C3).
   - `PENDING_CONNECTIONS_MAP[pending_key]` (or portless) → get `tgid`, then
     `TRUSTED_PIDS[tgid]`:
     - `Allow` → **promote**: insert `TRUSTED_CONNECTIONS_MAP[full_key] = tgid`,
       remove the pending entry. Fall through to the rule gate.
     - `Deny` / tgid not in `TRUSTED_PIDS` → **block** (`TC_ACT_SHOT`).
   - Not in any map → **block** (*"Connection Not Found in Either Map"*).
6. **Rule gate** — `rule_matching(ctx, tuple, info)`:
   - Probe `RULES` with 6 keys, most → least specific:
     `(proto+dst_ip+dst_port)`, `(proto+dst_ip)`, `(proto+dst_port)`,
     `(dst_ip+dst_port)`, `(dst_ip)`, `(dst_port)`.
   - Match `Allow` → insert `CONNECTION_MAP[tuple] = info` (so **return traffic**
     passes) → `TC_ACT_OK`.
   - Match `Deny` → emit a `BlockEvent` → `TC_ACT_SHOT`.
   - **No match → default deny** → `TC_ACT_SHOT`.

**Result:** the first packet is gated on *both* app trust (from the pending entry
filled in C1) and the rule set. On success the connection is promoted to
`TRUSTED_CONNECTIONS_MAP` and the tuple is recorded in `CONNECTION_MAP`.

---

## Path C3 — Client fast path (subsequent packets, egress TC)

**Trigger:** any later packet on an already-verified connection hits
`firewhal_egress_tc`.

**What happens** (same function, earlier branch):

1. Parse tuple; not DHCP.
2. Cookie check → client socket not in `TRUSTED_COOKIES` → continue.
3. `TRUSTED_CONNECTIONS_MAP[full_key]` → **hit** (set in C2). Get `tgid`.
4. `TRUSTED_PIDS[tgid]`:
   - `Allow` → **refresh** the map entry. Fall through to the rule gate.
   - `Deny` → **block**.
   - tgid no longer in `TRUSTED_PIDS` → **stale** → remove the connection entry,
     **block**.
5. Rule gate (same as C2 step 6).

**Result:** **no userspace round-trip, no hashing, no lineage walk** — only map
lookups plus rule matching. This is the "fast" path: the one-time expensive
verification from C1 is already done. (It still runs `rule_matching`; the
rule-*skipping* fast path is the server cookie path, C7.)

---

# Server paths

*A remote peer connects to a local listener (e.g. `sshd` on port 22). The local
machine is the server.*

## Path S1 — Server slow path: **syscall** (`bind4`) + client **SYN** (ingress TC)

Two sub-steps.

**(a) `bind4`** (`firewhal_egress_bind4`, line 471): when the listener calls
`bind(2)`:

1. Compute the listening port.
2. Insert `PENDING_LISTENING_PORTS[port] = tgid` — record **which process owns
   the port**.
3. Call `app_tracking("bind4")` (may emit a `ConnectionAttempt` for verification).
4. Return allow (enforcement delegated to TC).

**(b) Client SYN** (`firewhal_ingress_tc` → `try_firewhal_ingress_tc`, line 348):
the remote SYN arrives on ingress.

1. `parse_packet_tuple`; build the **reversed** tuple (swap src/dst and ports) —
   ingress sees the *return* direction of the eventual connection. Also build a
   `portless` tuple (ICMP) and a `dhcp_response` tuple.
2. **Stateful check**, in order:
   - `CONNECTION_MAP[reversed_tuple]` → hit → **allow** (return traffic of an
     already-allowed egress connection).
   - `CONNECTION_MAP[dhcp_response]` → hit → allow.
   - `CONNECTION_MAP[portless_tuple]` → hit → allow.
   - **Miss** → **stateless fallback** `ingress_rule_matching`.
3. `ingress_rule_matching` (line 252):
   - Probe `INCOMING_RULES` with 5 keys, most → least specific, matching on the
     **source** of the incoming packet (the remote peer):
     `(proto+src_ip+src_port)`, `(proto+src_ip)`, `(src_ip)`, `(src_port)`,
     `(dst_port)`.
   - Match `Allow` → if TCP and the packet is a **SYN** (`tcp_header.syn() == 1`),
     insert `HANDSHAKE_ALLOWED[tuple] = 0` (a temporary "this handshake is OK"
     mark). → `TC_ACT_OK`.
   - Match `Deny` → emit block → `TC_ACT_SHOT`.
   - **No match → default deny** → `TC_ACT_SHOT`.

**Result:** the SYN is admitted (if an incoming rule allows the peer) and the
4-tuple is marked in `HANDSHAKE_ALLOWED`, so the server's SYN-ACK can be gated on
the *bound process's* trust.

---

## Path S2 — Server slow path: **traffic** (SYN-ACK, egress TC)

**Trigger:** the local server replies to the admitted SYN with a **SYN-ACK**, which
traverses `firewhal_egress_tc`.

**What happens** (in `try_firewhal_egress_tc`, the SYN-ACK block at line 585):

1. Parse tuple; not DHCP.
2. Cookie → not yet in `TRUSTED_COOKIES` (child socket not established) → continue.
3. `TRUSTED_CONNECTIONS_MAP[full_key]` → miss (new). `PENDING_CONNECTIONS_MAP` →
   miss (the server *responded*; it did not `connect()`).
4. Since `protocol == 6` (TCP), parse the TCP header. If `syn() != 0 && ack() != 0`
   (this **is** a SYN-ACK):
   - Build the **reversed** tuple (to match the `HANDSHAKE_ALLOWED` key inserted on
     ingress, which is the client's SYN tuple).
   - `HANDSHAKE_ALLOWED[reversed_tuple]`:
     - **Hit** (we allowed this SYN in S1) → now verify the **bound process**:
       - `TRUSTED_LISTENING_PORTS[reversed_tuple.dport]`:
         - **Hit** (port already trusted) → `TRUSTED_PIDS[tgid]`:
           `Allow` → `TC_ACT_OK`; `Deny` → remove port, `TC_ACT_SHOT`.
       - **Miss** → `PENDING_LISTENING_PORTS[reversed_tuple.dport]`:
         - **Hit** → `TRUSTED_PIDS[tgid]`:
           - `Allow` → **promote**: remove from `PENDING_LISTENING_PORTS`, insert
             into `TRUSTED_LISTENING_PORTS` → `TC_ACT_OK`.
           - `Deny` → remove from PENDING → `TC_ACT_SHOT`.
     - **Miss** (handshake not pre-allowed) → fall through → block.

**Result:** the SYN-ACK is allowed **only if the process bound to the listening
port is on the allowlist**. This is the key server-side security property — a
port can complete a handshake only if its owning app is trusted. On success the
port is promoted `PENDING → TRUSTED_LISTENING_PORTS`.

---

## Path S3 — Server slow path: **sock ops** (`PASSIVE_ESTABLISHED_CB`)

**Trigger:** the TCP three-way handshake completes; the server's child socket
transitions to ESTABLISHED. The `sock_ops` hook
(`firewhal_sock_ops` → `try_firewhal_sock_ops`, line 752) fires for
`BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`.

**What happens:**

1. Read `local_port`.
2. `TRUSTED_LISTENING_PORTS[local_port]`:
   - **Hit** (the port was trusted in S2):
     - `cookie = bpf_get_socket_cookie(ctx.ops)` — the **child socket's** cookie.
     - `TRUSTED_COOKIES[cookie] = 1` — whitelist this specific connection for TC.
     - **Cleanup:** build the handshake tuple and `HANDSHAKE_ALLOWED.remove(...)` —
       the handshake is done.
   - **Miss** → do nothing.
3. Return 0.

**Result:** the connection is marked fully trusted via its **socket cookie** —
this unlocks the fast path (C7). The temporary `HANDSHAKE_ALLOWED` entry is
removed.

> Note: the cookie is that of the *newly established child socket*, which is the
> stable identifier for the life of the connection. (See also `Progress.txt`: the
> cookie seen at `bind`/`connect` time can differ from the cookie of the actual
> connection.)

---

## Path S4 — Server fast path (egress TC via `TRUSTED_COOKIES`) + cleanup

**Trigger:** subsequent packets on the established server connection hit
`firewhal_egress_tc`.

**What happens** (the cookie check at line 576):

1. Parse tuple; not DHCP.
2. `cookie = bpf_get_socket_cookie`:
   - `cookie == 0` → no socket → continue.
   - `TRUSTED_COOKIES[cookie]` → **hit** (set in S3) → **`return TC_ACT_OK`
     immediately.**

This is the true fast path: **one** map lookup (cookie → trusted) and an immediate
allow — **no** app gate, **no** rule matching, **no** other map lookups.

**Map cleanup / known gaps:**

- `HANDSHAKE_ALLOWED` is cleaned up by `sock_ops` on establishment (S3).
- `TRUSTED_COOKIES` is **not** cleaned up on connection close — there is no
  socket-close hook (the `sock_ops` program only handles
  `PASSIVE_ESTABLISHED_CB`). Cookie entries accumulate (plain `HashMap`, max
  10000, not LRU). This is a known stale-cookie leak; see tickets #90 (socket
  cookie into the connect model) and #68 (monitor trusted programs closing).

---

# Cross-cutting behavior

## Stateful return traffic (client-initiated)

Once a client egress connection is allowed (C2), its **forward** tuple is inserted
into `CONNECTION_MAP`. When **return** packets from the remote server arrive on
ingress, `try_firewhal_ingress_tc` builds the reversed tuple, finds it in
`CONNECTION_MAP`, and allows it **immediately** — no stateless rule matching. This
is what makes FireWhal a stateful firewall: allow egress once, and the reverse
flow is implicitly permitted.

## DHCP special case

- **Egress:** a DHCP discover (`0.0.0.0 → 255.255.255.255`) is allowed and
  recorded as a broadcast tuple (zeroed addresses) in `CONNECTION_MAP` (C2 step 2).
- **Ingress:** a DHCP response (tuple matching `dhcp_response`, sport 68 / dport
  67) is allowed via `CONNECTION_MAP[dhcp_response]` (S1 step 2).

DHCP uses broadcast and doesn't fit the normal 4-tuple model, so it is handled
explicitly in both directions.

## The two gates, summarized

| Gate | Where | Decides | Default |
|---|---|---|---|
| Application gate | cgroup hooks (record) + userspace (verify) + egress TC (enforce) | Is the *process* trusted? | Deny |
| Network gate | egress / ingress TC `rule_matching` | Is the *destination/peer* allowed by a rule? | Deny |

A packet is allowed only if it passes the relevant gate(s); the server fast path
(S4) is the one shortcut that passes via the socket cookie alone.
