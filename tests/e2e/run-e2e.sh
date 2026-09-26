#!/usr/bin/env bash
# FireWhal VM e2e regression gate — one command, from the host.
#
# Usage:  tests/e2e/run-e2e.sh
# Env:    FW_VM_DIR  rig directory holding fw-vm + the disk images
#                 (default: /home/torch/fw-vm; see test-vm/README.md)
#
# Phases:
#   preflight  dependency freshness: Cargo.lock core set vs crates.io
#              (report-only; never fails the gate — ticket #106)
#   1. rig      VM reachable — if it is down, recreate the overlay and boot
#   2. build    cargo build --release + the ipc_smoke sample (host)
#   3. deploy   tarball -> guest /opt/firewhal/bin, generated test config
#               (curl hash computed IN the guest), start the daemon
#   4. ready    3 processes, all FireWhal BPF programs including both TC
#               classifiers (the fail-open regression guard), and all three
#               config pushes in the daemon log (no silent zero-rules start)
#   5. probes   ipc_smoke router round-trip + the enforcement differentials
#               (log-signal based)
#   6. data     D1 data-level enforcement (wire-outcome based): baseline
#               (stack down) -> allow -> block, host listener on
#               127.0.0.1:9999 + guest tcpdump/tshark capture per leg
#   7. cleanup  power the VM off (state stays in the overlay; the next run
#               recreates the overlay and boots from scratch in phase 1)
#
# Exit code: 0 iff every check passed.

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

# ---------- preflight: dependency freshness (host, report-only) ----------
say "preflight: dependency freshness (report-only, never fails the gate)"
if ! python3 "$E2E_DIR/dep_freshness.py" "$REPO_ROOT/Cargo.lock"; then
    say "warning: dep-freshness check errored (continuing; it is report-only)"
fi

# ---------- 1. rig ----------
if "$FW_VM" ssh true 2>/dev/null; then
    say "phase 1/7 rig: VM reachable"
else
    if [ -f "$FW_VM_DIR/fw-test.pid" ] && kill -0 "$(cat "$FW_VM_DIR/fw-test.pid")" 2>/dev/null; then
        die "VM process is alive but SSH is unreachable — stop the VM, check $FW_VM_DIR/fw-test-serial.log, retry"
    fi
    say "phase 1/7 rig: VM down — recreating overlay and booting"
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
say "phase 2/7 build: cargo build --release"
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
say "phase 3/7 deploy: shipping tarball + guest scripts"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-deploy.tar.gz' < "$STAGE/deploy.tar.gz"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-vm_deploy.sh' < "$E2E_DIR/vm_deploy.sh"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-vm_probes.sh' < "$E2E_DIR/vm_probes.sh"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-vm_data_probe.sh' < "$E2E_DIR/vm_data_probe.sh"
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_deploy.sh'

# ---------- 4+5. ready + probes (inside the guest) ----------
say "phase 4/7 ready + phase 5/7 probes: running in guest"
set +e
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_probes.sh'
rc=$?
set -e

# ---------- 6. data-level (D1): baseline -> allow -> block, wire-verified ----------
say "phase 6/7 data: data-level enforcement (host listener + guest wire capture)"
D1_OUT="$STAGE/d1-listener.out"
rm -f "$D1_OUT"
python3 - "$D1_OUT" <<'PYEOF' &
import socket, sys
out = open(sys.argv[1], "w")
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9999))
srv.listen(5)
srv.settimeout(240)
for leg in ("baseline", "allow"):
    try:
        c, _ = srv.accept()
        data = c.recv(512)
        out.write("%s RECEIVED: %r\n" % (leg, data))
        out.flush()
        c.close()
    except Exception as e:
        out.write("%s LISTENER ERROR: %r\n" % (leg, e))
        out.flush()
        break
out.close()
PYEOF
D1_PID=$!
sleep 1

D1_TOTAL=0
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_data_probe.sh baseline' || D1_TOTAL=$((D1_TOTAL + 1))
say "data: redeploying the stack for the allow + block legs"
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_deploy.sh' || D1_TOTAL=$((D1_TOTAL + 1))
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_data_probe.sh allow' || D1_TOTAL=$((D1_TOTAL + 1))
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_data_probe.sh block' || D1_TOTAL=$((D1_TOTAL + 1))

sleep 1
kill "$D1_PID" 2>/dev/null || true
if grep -q "baseline RECEIVED: .*FW-D1-BASELINE" "$D1_OUT" 2>/dev/null \
    && grep -q "allow RECEIVED: .*FW-D1-ALLOW" "$D1_OUT" 2>/dev/null; then
    say "PASS: data: host listener received both payloads (byte-level delivery)"
else
    say "FAIL: data: host listener did not receive both payloads:"
    sed 's/^/        | /' "$D1_OUT" 2>/dev/null || true
    D1_TOTAL=$((D1_TOTAL + 1))
fi
rc=$((rc + D1_TOTAL))

# ---------- 7. cleanup: power the VM off ----------
say "phase 7/7 cleanup: shutting the VM down"
if ! "$FW_VM" stop >/dev/null 2>&1; then
    say "warning: VM did not stop (check $FW_VM_DIR/fw-test.pid)"
fi

if [ "$rc" -eq 0 ]; then
    say "RESULT: ALL CHECKS PASSED — VM shut down"
else
    say "RESULT: FAILURES (see output above); VM shut down"
    say "to inspect the failed state: $FW_VM boot  (next run recreates the overlay)"
fi
exit "$rc"
