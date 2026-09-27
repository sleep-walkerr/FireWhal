#!/usr/bin/env bash
# FireWhal host-side package contract test: the firewhal-admin group (#155).
#
# The IPC socket is 0770 root:firewhal-admin (firewhal-ipc/src/lib.rs),
# so the operator — the user who installed the package — must be a member
# of that group to reach the TUI/health client. This test proves both
# facts from a clean slate:
#   1. the package's scriptlet CREATES the group on (re)install
#   2. the package's scriptlet ADDS the installing user ($SUDO_USER)
#
# Usage:  sudo bash tests/package/test-ipc-group.sh [package-file]
#   - run via sudo: the scriptlet reads $SUDO_USER, and that is the user
#     the test then asserts on
#   - the package file defaults to the newest staged
#     firewhal-*-x86_64.pkg.tar.zst in the repo root
#
# Requires the stack STOPPED: the group is deleted and recreated, so
# nothing may hold the gid (a running router is setgid to it).
set -euo pipefail

[ -n "${SUDO_USER:-}" ] || { echo "FATAL: run via sudo (sudo bash $0) — the scriptlet adds \$SUDO_USER and the test asserts on it"; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG="${1:-}"
if [ -z "$PKG" ]; then
    PKG="$(ls -1 "$REPO_ROOT"/firewhal-*-x86_64.pkg.tar.zst 2>/dev/null | sort -V | tail -n 1 || true)"
fi
[ -n "$PKG" ] && [ -f "$PKG" ] || { echo "FATAL: no staged package found (pass one as the first argument)"; exit 1; }

say() { printf '[pkg-test] %s\n' "$*"; }
fail() { say "FAIL: $*"; exit 1; }

echo "package:       $PKG"
echo "installing as: $SUDO_USER"

# --- clean slate: strip members, then delete the group, so that group
# --- creation (not a pre-existing group) is what the install must prove
if getent group firewhal-admin >/dev/null 2>&1; then
    members="$(getent group firewhal-admin | cut -d: -f4)"
    for m in $members; do
        say "removing $m from firewhal-admin (clean slate)"
        gpasswd -d "$m" firewhal-admin >/dev/null
    done
    say "deleting existing firewhal-admin group (clean slate)"
    groupdel firewhal-admin
else
    say "firewhal-admin group absent (already a clean slate)"
fi

# --- reinstall: the scriptlet runs as part of this transaction ---
say "reinstalling: pacman -U --noconfirm $PKG"
pacman -U --noconfirm "$PKG" || fail "pacman -U failed"

# --- 1. the scriptlet created the group ---
if getent group firewhal-admin >/dev/null 2>&1; then
    say "PASS 1/2: firewhal-admin group exists: $(getent group firewhal-admin)"
else
    fail "firewhal-admin group missing after install — the scriptlet did not create it"
fi

# --- 2. the scriptlet added the installing user ---
if id -nG "$SUDO_USER" | tr ' ' '\n' | grep -qx firewhal-admin; then
    say "PASS 2/2: $SUDO_USER is a member of firewhal-admin"
else
    fail "$SUDO_USER is not a member of firewhal-admin after install"
fi

say "ALL PASS — firewhal-admin contract holds (installed: firewhal $(pacman -Qi firewhal 2>/dev/null | awk -F': ' '/^Version/ {print $2}'))"
