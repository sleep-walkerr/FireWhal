# FireWhal dev commands — `just --list` for the menu.
#
# Two loops (see docs/developer-guide.md):
#   just install  — versioned, pacman-tracked (full cleanroom build)
#   just dev      — inner loop: incremental build + in-place update

set shell := ["bash", "-euo pipefail", "-c"]
# bpf-linker (source build) lives here on the dev host
export PATH := "/home/torch/.local/bin:" + env_var("PATH")

# Version gate: PKGBUILD's pkgver must equal the workspace Cargo.toml
# version (hand-bump both together — see the PKGBUILD header on why
# pkgver() is not used here).
version-check:
    pv=$(sed -n 's/^pkgver=//p' PKGBUILD | head -n 1) && wv=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1) && { [ -n "$pv" ] && [ "$pv" = "$wv" ] || { echo "FATAL: version drift — PKGBUILD pkgver=${pv:-none} vs Cargo.toml ${wv:-none} — bump both to the same SemVer"; exit 1; }; }; echo "version check OK: $pv"

# Full package build + versioned install. Builds from the committed repo
# state (makepkg clones the repo), so commit + push first.
install: version-check
    makepkg -si --nodeps

# Inner dev loop: incremental cargo build + in-place binary update +
# restart. No repack; until you run `just install` again, `pacman -Qk
# firewhal` will show the overwritten binaries as modified.
dev:
    cargo build --release --locked
    cargo build --release --locked --example ipc_smoke -p firewhal-core
    sudo cp target/release/firewhal-daemon target/release/firewhal-ipc \
        target/release/firewhal-kernel target/release/firewhal-health \
        target/release/firewhal-tui target/release/firewhal-discord-bot /usr/bin/
    sudo cp target/release/examples/ipc_smoke /usr/bin/
    sudo systemctl restart firewhal

# Full e2e gate: boots the VM and runs all phases (the test oracle).
gate:
    bash tests/e2e/run-e2e.sh
