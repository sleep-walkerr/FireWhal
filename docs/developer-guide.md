# Developer Guide

Working guide for developing FireWhal solo: the two development loops, the
toolchain contract, where state lives, and the failure modes that are not
obvious from the code. The e2e runbook (`docs/vm-enforcement-testing.md`) and
the design doc (`docs/comprehensive-test-design.md`) carry the depth; this
page carries the *operational* knowledge.

## 1. The two loops

The host (this machine, CachyOS) is where you develop **and** enforce. The VM
(`/home/torch/fw-vm`) is the **test oracle** — it is where the gate runs to
prove changes are safe before/while they live on the host.

| Command | What it does | When |
|---|---|---|
| `just install` | version check, then `makepkg -si`: isolated source build (persistent cache in `~/.cache/firewhal-pkg`, incremental across runs) → pacman versioned install (binaries `/usr/bin`, units `/usr/lib/systemd/system`, config templates `/etc/firewhal`) | After a commit you want to *ship* to the host. Builds from the **committed** repo state — commit + push first. |
| `just dev` | Incremental `cargo build --release` + in-place copy of the 7 binaries into `/usr/bin` + `systemctl restart firewhal` | **Every code change** while working. No repack, no cleanroom — fast. (`pacman -Qk firewhal` will show the overwritten binaries as modified until the next `just install`.) |
| `just gate` | `tests/e2e/run-e2e.sh`: boots the VM, runs all 9 phases (readiness, enforcement differentials, D1 wire, S1+M1, C1, cleanup) | Before you trust a change. ~30–40 min, ends with the VM shut down. |

Versioning: two lines that must agree — `[workspace.package] version` in
`Cargo.toml` (drives the binaries' `--version`) and `pkgver` in the
PKGBUILD (drives the package). Hand-bump both to the same SemVer (2.0;
`0.x` until the first stable); `just install` runs a version-check that
fails loud if the two drift.

**First-run note:** a fresh package install is deliberately fail-closed —
no rules, empty allowlist, and `interface_state.toml` names `fw-none`
(a nonexistent interface, so nothing is enforced). Configure
`/etc/firewhal/*.toml` and create `/etc/firewhal/discord.env` before the
stack does anything useful; `systemctl status firewhal-health` tells you
what is degraded and why.

## 2. Toolchain contract (fail-loud by design)

- The eBPF side is pinned in `firewhal-kernel/build.rs` to
  **`nightly-2026-07-15`** (`aya-build` drives it via rustup). Do not "fix"
  the pin by switching to a floating nightly — the bpf-linker pairing
  depends on it.
- **`bpf-linker` 0.11.1** is a source build in `~/.local/bin`, built with
  `--features llvm-22` to pair with the host's libLLVM 22. The PKGBUILD
  checks this fail-loud (missing or wrong version = build fails, not a
  corrupt BPF object). When the distro ships LLVM 23: rebuild with the
  default `llvm-23` feature (see the follow-up ticket for packaging it).
- Build order that works: `cargo build --release --locked` at the workspace
  root. `firewhal-kernel-ebpf` is deliberately **not** a default member —
  it is compiled by `aya-build` inside `firewhal-kernel`'s `build.rs`.

## 3. Where state lives

| Location | What |
|---|---|
| `/etc/firewhal/` | **The** config directory (daemon, `firewhal-health`, bot token). Pacman config files — preserved on upgrade. |
| `/usr/bin/firewhal-*` | Packaged binaries. The daemon finds its children **next to its own executable** (sibling resolution) — that is also why the VM tarball layout (`/opt/firewhal/bin`) still works. |
| `/opt/firewhal/bin/` | Guest-VM install location (tarball flow, `tests/e2e/vm_deploy.sh`). |
| `/tmp/firewhal-daemon.{out,err}` | Daemon stdout/stderr (hardcoded). |
| `/var/log/firewhal/config-alert.log` | C1 alarm bundle (persistent). |
| `/var/log/firewhal/config-health.state` | C1 health state (survives restarts; recovery alarms need it). |
| guest `/tmp` | **Not durable** — `fw-vm stop` hard-kills qemu; unflushed guest `/tmp` does not survive the power cycle. |

## 4. Failure modes that are not obvious from the code

### Enforcement is TCX, not `tc filter`
On the guest kernel (6.8+), aya 0.14 attaches TC via **TCX**.
`tc filter show` on an enforced interface is **always empty** — that is not
a bug. The authoritative view is `sudo bpftool link show type tcx`
(2 links per enforced interface). The gate asserts via `bpftool prog show`.

### Attach severs the in-flight session
Existing connections are re-evaluated at the attach moment. When the gate
attaches the enforcement leg, the *in-flight* ssh session (the one running
the script) is severed; **fresh** connections work immediately. The gate
therefore dispatches the attach detached (`setsid`) and polls
`c1-status` from the host with fresh short probes (raw ssh,
`ConnectTimeout=5`, `ServerAliveInterval=5`/`ServerAliveCountMax=3`).
If a host-side ssh client wedges during a leg, kill the **host** client —
do not try to rescue the severed guest session.

### The `wait-start` race
A long-lived `wait-start` ssh session inside the guest dies when the
interfaces leg attaches — a silent spurious FAIL if the gate keeps polling
that session. The fix is the host-side `c1_ssh_probe` poll loop: never
trust a pre-attach session to report post-attach state.

### C1 posture matrix (what "degraded" means)
Config-path failures are never fatal and never silent — the stack stays up
in the safe posture and announces (alarm log + `wall` + TUI, and
`firewhal-health` exits 1):

| Config | Failure | Posture |
|---|---|---|
| rules toml | missing/malformed | empty rule set — **default-deny everything** |
| `interface_state.toml` | missing/malformed/**empty** | attach TC to **all non-loopback interfaces** |
| `app_identity.toml` | missing | bootstrap an empty allowlist — **egress denied at the app gate** |
| allowlist | **empty (even if valid)** | degraded by definition — all egress denied at the app gate |

Consequence: **an empty `interface_state.toml` attaches to every
non-loopback interface.** That is why the package ships the `fw-none`
placeholder (a named-but-nonexistent interface fails to attach loudly and
enforces nothing) instead of an empty list, and why a dev config that
shouldn't enforce must *name* a dead interface, never be empty.

### Clock skew
Host is UTC-5, guest is UTC. Host timestamps in logs/artifacts are 5 h
**behind** guest times. Don't "fix" one side to match the other — compare
times across the boundary with the offset in mind.

### Rules byte-order quirk (known limitation)
Outgoing rules are keyed with `from_le_bytes`, incoming with
`from_be_bytes`, and the eBPF parser uses `from_le_bytes` on big-endian
header bytes. Symptom: "rules only work with reversed IP addresses."
Documented in `docs/modes-and-features.md` (Known limitations) — not
something to silently fix mid-work.

### Journal lossiness
The guest journal is capped at 8 MiB and lossy. For anything you need to
replay later, the alarm log (`/var/log/firewhal/config-alert.log`) and the
gate log are the durable records — not `journalctl`.

## 5. Standing rules (owner directives)

- **VM work happens inside the VM.** Never attach BPF or enforce on the
  host as part of testing; host enforcement is the operator's deliberate
  act.
- `AGENTS.md` / `opencode.json` stay untracked; secrets (`.env`, tokens)
  never get committed and never ship in a package.
- Merge flow: branch → PR (`--body-file` for bodies with apostrophes) →
  squash-merge via `gh api -X PUT .../pulls/N/merge -f merge_method=squash`
  (`gh pr merge` is blocked by branch protection) → verify tree identity →
  delete the branch.
- Every future e2e test lands as a **named phase** in `tests/e2e/` + a
  runbook line + a probe-table row (scope rule from #106). No ad-hoc
  scripts.
