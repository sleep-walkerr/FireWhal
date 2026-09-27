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
# Versioning: static pkgver, on purpose. A dynamic pkgver() function is
# not usable on this distro's makepkg — it lints the pkgver variable
# before the function can run and rejects the empty one ("pkgver is not
# allowed to be empty"; reproduced with a minimal probe PKGBUILD).
# Hand-bump this AND [workspace.package].version in Cargo.toml together;
# `just install` runs a version-check that fails loud if the two drift.

pkgname=firewhal
pkgdesc="FireWhal — eBPF-based application + rule firewall (daemon, kernel loader, TUI, IPC router, config validator)"
pkgver=0.1.0
pkgrel=3
arch=(x86_64)
url="https://github.com/sleep-walkerr/FireWhal"
license=("MIT OR Apache-2.0")
source=("git+${url}.git")
sha256sums=(SKIP)
makedepends=(rust git)
# Scriptlets live in a separate file — pacman's mechanism is the install=
# directive (NOT functions in the PKGBUILD; see PKGBUILD(5)). makepkg
# copies it into the package as .INSTALL (lint verifies it exists).
# Creates the firewhal-admin group the IPC router requires.
install=firewhal.install
# bpf-linker is a source build on this host (~/.local/bin) — no distro
# package; verified fail-loud in build() instead.

# makepkg's cleanroom masks HOME — point rustup/cargo at the real machine
# homes so the pinned nightly and the dependency cache are reused (local
# packaging on this host; same convention as the justfile). Top-level so
# it reaches every function subshell.
export RUSTUP_HOME=/home/torch/.rustup
export CARGO_HOME=/home/torch/.cargo

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

    # Build IN the source checkout, never from $srcdir: a bare `cargo build`
    # from $srcdir finds no manifest and walks up to the outer repo (when
    # the build dir sits inside it), compiling into that repo's shared dev
    # target dir — lock contention with the dev loop and stale-artifact
    # link failures (observed: undefined ring asm symbols). The checkout's
    # own target dir keeps the package build isolated. The checkout dir is
    # named after the source entry (FireWhal), not $pkgname (firewhal).
    local srcname
    srcname=$(basename "${source[0]#git+}" .git)
    cd "$srcdir/$srcname" || {
        echo "FATAL: source checkout $srcdir/$srcname not found" >&2
        exit 1
    }
    # Clear the distro's C/C++/linker flags before building: makepkg exports
    # CFLAGS/CXXFLAGS/LDFLAGS from /etc/makepkg.conf into the build env, and
    # cc-rs (ring, zeromq-sys, … build scripts) honors them. CachyOS's
    # CFLAGS carry -flto=auto, which turned ring's asm objects into LTO
    # bitcode the non-LTO final link cannot resolve (observed: undefined
    # ring_core_* symbols at the firewhal-discord-bot link). Rust flags come
    # from the Cargo.toml profiles; the C build scripts want none of these.
    # Clear the distro's C/C++/linker flags for the cargo build (a plain
    # `VAR=x { ... }` prefix is not valid bash — only simple commands take
    # an assignment prefix, so use a subshell instead):
    (
        CFLAGS= CXXFLAGS= LDFLAGS= cargo build --release --locked
        # ipc_smoke is a firewhal-core example — a plain `cargo build` does
        # not build examples (the justfile dev recipe builds it explicitly).
        CFLAGS= CXXFLAGS= LDFLAGS= cargo build --release --locked --example ipc_smoke -p firewhal-core
    )
}

package() {
    local src bin srcname
    # The git source lands in $srcdir/<source-entry-name> (FireWhal — the
    # repo name, NOT $pkgname), e.g. $srcdir/FireWhal.
    srcname=$(basename "${source[0]#git+}" .git)
    src="$srcdir/$srcname"
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
