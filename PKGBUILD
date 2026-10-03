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
pkgrel=8
arch=(x86_64)
url="https://github.com/sleep-walkerr/FireWhal"
license=("MIT OR Apache-2.0")
source=("git+${url}.git")
sha256sums=(SKIP)
makedepends=(rust git)
# Config-file registration (pacman "backup" semantics — PKGBUILD(5),
# pacman(8) "Handling Config Files"): makepkg does NOT auto-mark files
# under /etc — the backup array is the only mechanism (verified on the
# host: system packages ship /etc files with empty or partial backup
# lists, e.g. gawk marks none, openssl only openssl.cnf; only explicit
# entries get config semantics). Without these entries pacman treats the
# templates as plain files and silently overwrites user edits on
# upgrade/removal (no .pacnew, no .pacsave, no warning — the observed
# behavior of every 0.1.0-1..-6 transaction on this host).
backup=(
    'etc/firewhal/app_identity.toml'
    'etc/firewhal/firewall_rules.toml'
    'etc/firewhal/interface_state.toml'
)
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
    #     allowlist, and a placeholder interface that does not exist.
    #     NOTE (verified on the host): a nonexistent interface maps to
    #     C1's fail-closed DEFAULT — TC on ALL non-loopback interfaces,
    #     default-deny — the first time the stack is started (observed:
    #     DNS + web blocked until `systemctl stop`). The unit ships
    #     disabled, so a fresh install enforces nothing until the
    #     operator deliberately starts it; the template comments state
    #     the warning the operator reads in /etc/firewhal. ---
    install -dm755 "$pkgdir/etc/firewhal"

    cat > "$pkgdir/etc/firewhal/firewall_rules.toml" <<'EOF'
# FireWhal rules (packaged template — no rules = default-deny everything).
#
# The default_* fields are emitted explicitly (#159): the fallback verdict
# for traffic matching no explicit rule. Block (fail-closed) is the safe
# value; Allow must be a deliberate, operator-made change. (A file missing
# the keys still parses — the serde default is Block — but a generated
# template never relies on that; AGENTS.md: the default is a backstop.)
default_incoming = "Block"
default_outgoing = "Block"
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
# This is a pacman config file: your edits survive upgrades (a changed
# template is offered as interface_state.toml.pacnew) and are saved as
# interface_state.toml.pacsave if the package is removed.
#
# NOTE: this template names an interface that does not exist. C1 maps
# that to the fail-closed DEFAULT: starting the stack attaches TC to ALL
# non-loopback interfaces and, with the empty rule set, DENIES ALL
# traffic — including your management path (observed on the host: DNS
# and web were blocked until the stack was stopped).
#
# The package installs the unit disabled, so nothing is enforced until
# you deliberately start it. Before that, replace "fw-none" with your
# real interface(s) and add the rules you need in firewall_rules.toml.
# Recovery from an unconfigured start: sudo systemctl stop firewhal.
enforced_interfaces = [
    "fw-none",
]
EOF

    # NOTE: the Discord token is deliberately NOT shipped. Create
    # /etc/firewhal/discord.env (DISCORD_TOKEN=...) for the bot to run;
    # the firewall itself does not need it.
}
