# Maintainer: FireWhal
#
# FireWhal — eBPF application + rule firewall.
#
# Toolchain prerequisites (checked fail-loud in build(), #136):
#   - bpf-linker 0.11.1 on PATH (source build paired with the host's
#     libLLVM 22; no suitable distro package yet — see the follow-up ticket
#     for making it a proper package)
#   - rustup toolchain nightly-2026-07-15 — the pinned eBPF toolchain
#     (firewhal-kernel/build.rs); installed by prepare() if absent
#
# Versioning: pkgver is derived from the [workspace.package] version in
# Cargo.toml (single source of truth). Hand-bump it there, commit, push,
# then `just install`.

pkgname=firewhal
pkgdesc="FireWhal — eBPF-based application + rule firewall (daemon, kernel loader, TUI, IPC router, config validator)"
pkgver() {
    sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1
}
pkgrel=1
arch=(x86_64)
url="https://github.com/sleep-walkerr/FireWhal"
license=("MIT OR Apache-2.0")
source=("git+${url}.git")
sha256sums=(SKIP)
makedepends=(rust git)
# bpf-linker is a source build on this host (~/.local/bin) — no distro
# package; verified fail-loud in build() instead.

prepare() {
    # The eBPF build (aya-build in firewhal-kernel/build.rs) drives a pinned
    # nightly via rustup; make it available in the cleanroom build env.
    if ! rustup toolchain list | grep -q "nightly-2026-07-15"; then
        rustup toolchain install nightly-2026-07-15 --profile minimal
    fi
}

build() {
    # --- toolchain contract (fail loud, never a half-built BPF object) ---
    command -v bpf-linker >/dev/null || {
        echo "FATAL: bpf-linker not on PATH (expected the 0.11.1 source build)" >&2
        exit 1
    }
    bpf-linker --version | grep -q "0.11.1" || {
        echo "FATAL: bpf-linker is not 0.11.1: $(bpf-linker --version)" >&2
        exit 1
    }

    cargo build --release --locked
}

package() {
    local src bin d
    # The git checkout lands in $pkgname-<commit>; glob it.
    for d in "$srcdir/$pkgname"-*; do src="$d"; done
    [ -d "$src" ] || { echo "FATAL: source checkout not found" >&2; return 1; }

    # --- binaries (children resolve next to the daemon — sibling layout,
    #     so /usr/bin here and /opt/firewhal/bin in the VM both work) ---
    for bin in firewhal-daemon firewhal-ipc firewhal-kernel firewhal-health \
               firewhal-tui firewhal-discord-bot; do
        install -Dm755 "$src/target/release/$bin" "$pkgdir/usr/bin/$bin"
    done
    install -Dm755 "$src/target/release/examples/ipc_smoke" "$pkgdir/usr/bin/ipc_smoke"

    # --- systemd units ---
    install -Dm644 "$src/firewhal.service" "$pkgdir/usr/lib/systemd/system/firewhal.service"
    install -Dm644 "$src/firewhal-health.service" "$pkgdir/usr/lib/systemd/system/firewhal-health.service"

    # --- config templates (pacman config files: preserved on upgrade,
    #     .pacnew on conflict). Deliberately fail-closed: no rules, no
    #     allowlist, and a placeholder interface that does not exist, so a
    #     fresh install enforces nothing and announces its degraded
    #     posture (C1) until the operator configures it. ---
    install -dm755 "$pkgdir/etc/firewhal"

    cat > "$pkgdir/etc/firewhal/firewall_rules.toml" <<'EOF'
# FireWhal rules (packaged template — no rules = default-deny everything).
# Add rules, then reload from the TUI (or restart the stack).
#
# [[outgoing_rules]]
# action = "Allow"
# protocol = "Tcp"
# dest_port = 443
# description = "HTTPS"
EOF

    cat > "$pkgdir/etc/firewhal/app_identity.toml" <<'EOF'
# FireWhal application allowlist (packaged template — empty allowlist =
# all egress denied at the app gate, fail-closed, announced by C1).
# Add entries (path + sha3-256 hash), then reload from the TUI.
#
# [apps.curl]
# path = "/usr/bin/curl"
# hash = "<sha3-256 hex>"
EOF

    cat > "$pkgdir/etc/firewhal/interface_state.toml" <<'EOF'
# FireWhal enforced interfaces (packaged template).
#
# SAFETY: this template names an interface that does not exist. The loader
# fails to attach it (loudly, in the daemon log) and nothing is enforced —
# a fresh install must never silently enforce your real interfaces.
# Replace "fw-none" with your real interface(s), then reload/restart.
enforced_interfaces = [
    "fw-none",
]
EOF

    # NOTE: the Discord token is deliberately NOT shipped. Create
    # /etc/firewhal/discord.env (DISCORD_TOKEN=...) for the bot to run;
    # the firewall itself does not need it.
}
