#!/usr/bin/env bash
# FireWhal VM e2e regression gate — one command, from the host.
#
# Usage:  tests/e2e/run-e2e.sh
# Env:    FW_VM_DIR  rig directory holding fw-vm + the disk images
#                 (default: /home/torch/fw-vm; see test-vm/README.md)
#
# Phases:
#   1. rig      VM reachable — if it is down, recreate the overlay and boot
#   2. build    cargo build --release + the ipc_smoke sample (host)
#   3. deploy   tarball -> guest /opt/firewhal/bin, generated test config
#               (curl hash computed IN the guest), start the daemon
#   4. ready    3 processes, all FireWhal BPF programs including both TC
#               classifiers (the fail-open regression guard), and all three
#               config pushes in the daemon log (no silent zero-rules start)
#   5. probes   ipc_smoke router round-trip + allow / rule-block / app-block
#
# After a run the VM is left running with the stack up; the next run tears
# down whatever it finds. Exit code: 0 iff every check passed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_DIR="$REPO_ROOT/tests/e2e"
FW_VM_DIR="${FW_VM_DIR:-/home/torch/fw-vm}"
FW_VM="$FW_VM_DIR/fw-vm"

STAGE="$(mktemp -d /tmp/fw-e2e.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT

say() { printf '[e2e] %s\n' "$*"; }
die() { say "FATAL: $*"; exit 1; }

[ -x "$FW_VM" ] || die "fw-vm not found at $FW_VM (set FW_VM_DIR to your rig directory)"

# ---------- 1. rig ----------
if "$FW_VM" ssh true 2>/dev/null; then
    say "phase 1/5 rig: VM reachable"
else
    if [ -f "$FW_VM_DIR/fw-test.pid" ] && kill -0 "$(cat "$FW_VM_DIR/fw-test.pid")" 2>/dev/null; then
        die "VM process is alive but SSH is unreachable — stop the VM, check $FW_VM_DIR/fw-test-serial.log, retry"
    fi
    say "phase 1/5 rig: VM down — recreating overlay and booting"
    "$FW_VM" reset
    "$FW_VM" boot
    up=""
    for i in $(seq 1 36); do
        sleep 5
        if "$FW_VM" ssh true 2>/dev/null; then up="$i"; break; fi
    done
    [ -n "$up" ] || die "VM did not accept SSH within 180s (check $FW_VM_DIR/fw-test-serial.log)"
    say "VM up after $((up * 5))s"
fi

# ---------- 2. build ----------
say "phase 2/5 build: cargo build --release"
(cd "$REPO_ROOT" && cargo build --release 2>&1 | tail -n 1)
(cd "$REPO_ROOT" && cargo build --release --example ipc_smoke -p firewhal-core 2>&1 | tail -n 1)

mkdir -p "$STAGE/bin"
for b in firewhal-daemon firewhal-ipc firewhal-kernel firewhal-tui firewhal-discord-bot; do
    cp "$REPO_ROOT/target/release/$b" "$STAGE/bin/"
done
cp "$REPO_ROOT/target/release/examples/ipc_smoke" "$STAGE/bin/"
tar -czf "$STAGE/deploy.tar.gz" -C "$STAGE" bin
say "packaged: $(ls "$STAGE/bin" | tr '\n' ' ')"

# ---------- 3. deploy ----------
say "phase 3/5 deploy: shipping tarball + guest scripts"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-deploy.tar.gz' < "$STAGE/deploy.tar.gz"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-vm_deploy.sh' < "$E2E_DIR/vm_deploy.sh"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-vm_probes.sh' < "$E2E_DIR/vm_probes.sh"
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_deploy.sh'

# ---------- 4+5. ready + probes (inside the guest) ----------
say "phase 4/5 ready + phase 5/5 probes: running in guest"
set +e
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_probes.sh'
rc=$?
set -e

if [ "$rc" -eq 0 ]; then
    say "RESULT: ALL CHECKS PASSED — stack left running on the VM"
else
    say "RESULT: FAILURES (see output above); stack left running for inspection"
fi
exit "$rc"
