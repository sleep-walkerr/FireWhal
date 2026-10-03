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
#   3. deploy   tarball -> guest /opt/firewhal/bin, generated test config in /etc/firewhal
#               (curl hash computed IN the guest), start the daemon
#   4. ready    3 processes, all FireWhal BPF programs including both TC
#               classifiers (the fail-open regression guard), and all three
#               config pushes in the daemon log (no silent zero-rules start)
#   5. probes   ipc_smoke router round-trip + the enforcement differentials
#               (log-signal based)
#   6. data     D1 data-level enforcement (wire-outcome based): baseline
#               (stack down) -> allow -> block, host listener on
#               127.0.0.1:9999 + guest tcpdump/tshark capture per leg
#   7. dv       DV default-verdict legs (ticket #159): ZERO explicit rules in
#               every leg — the per-direction default itself is the policy.
#               egress-allow / egress-block run self-contained in the guest
#               (wire + verdict; byte-level via the host listener);
#               incoming-allow / incoming-block are host-driven (ssh 2223
#               up / down 3/3, the ingress-tap wire oracle — the guest never
#               replies — and the S1 mgmt collateral guard on the block leg).
#               Ends with a full redeploy of the standard rig config.
#   8. ssh-block S1 deliberate SSH block on the enforced path (2223) + M1
#               mgmt collateral guard (2222 stays up the whole window); the
#               VM-local self-expiry sleeper (detached guest process, default
#               120 s, FW_S1_WINDOW overridable) restores the rule;
#               wire-verified
#   9. c1       C1 config-path regression (design doc §2.4): three legs,
#               each moving one config toml aside, restarting the stack
#               (degraded starts must still come up), and asserting the
#               fail-closed posture ON THE WIRE — rules: default-deny holds;
#               interfaces: the all-non-loopback default keeps enforcement
#               active (and mgmt 2222 still reachable); apps: egress denied
#               at the app gate. Each leg restores the file and verifies the
#               CONFIG ALERT + CONFIG RECOVERED lines in the persistent
#               alarm log; the firewhal-health validator (same parse as the
#               daemon) must exit 1 while misplaced and 0 after restore
#   10. cleanup  power the VM off (state stays in the overlay; the next run
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

SSH_KEY="$HOME/.ssh/id_ed25519_fwvm"
# One-shot ssh to the OOB/enforced path (2223 hostfwd -> enp0s3:22). Shared
# by the DV (default-verdict) and S1 (ssh-block) phases.
ssh_2223() {
    ssh -i "$SSH_KEY" -p 2223 -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=3 \
        ubuntu@127.0.0.1 true 2>/dev/null
}

# ---------- preflight: dependency freshness (host, report-only) ----------
say "preflight: dependency freshness (report-only, never fails the gate)"
if ! python3 "$E2E_DIR/dep_freshness.py" "$REPO_ROOT/Cargo.lock"; then
    say "warning: dep-freshness check errored (continuing; it is report-only)"
fi

# ---------- 1. rig ----------
if "$FW_VM" ssh true 2>/dev/null; then
    say "phase 1/10 rig: VM reachable"
else
    if [ -f "$FW_VM_DIR/fw-test.pid" ] && kill -0 "$(cat "$FW_VM_DIR/fw-test.pid")" 2>/dev/null; then
        die "VM process is alive but SSH is unreachable — stop the VM, check $FW_VM_DIR/fw-test-serial.log, retry"
    fi
    say "phase 1/10 rig: VM down — recreating overlay and booting"
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
say "phase 2/10 build: cargo build --release"
(cd "$REPO_ROOT" && cargo build --release 2>&1 | tail -n 1)
(cd "$REPO_ROOT" && cargo build --release --example ipc_smoke -p firewhal-core 2>&1 | tail -n 1)

mkdir -p "$STAGE/bin"
for b in firewhal-daemon firewhal-ipc firewhal-kernel firewhal-tui firewhal-discord-bot firewhal-health; do
    cp "$REPO_ROOT/target/release/$b" "$STAGE/bin/"
done
cp "$REPO_ROOT/target/release/examples/ipc_smoke" "$STAGE/bin/"
tar -czf "$STAGE/deploy.tar.gz" -C "$STAGE" bin
say "packaged: $(ls "$STAGE/bin" | tr '\n' ' ')"

# ---------- 3. deploy ----------
say "phase 3/10 deploy: shipping tarball + guest scripts"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-deploy.tar.gz' < "$STAGE/deploy.tar.gz"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-vm_deploy.sh' < "$E2E_DIR/vm_deploy.sh"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-vm_probes.sh' < "$E2E_DIR/vm_probes.sh"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-vm_data_probe.sh' < "$E2E_DIR/vm_data_probe.sh"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-vm_s1.sh' < "$E2E_DIR/vm_s1.sh"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-vm_c1.sh' < "$E2E_DIR/vm_c1.sh"
"$FW_VM" ssh 'cat > /tmp/fw-e2e-vm_dv.sh' < "$E2E_DIR/vm_dv.sh"
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_deploy.sh'

# ---------- 4+5. ready + probes (inside the guest) ----------
say "phase 4/10 ready + phase 5/10 probes: running in guest"
set +e
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_probes.sh'
rc=$?
set -e

# ---------- 6. data-level (D1): baseline -> allow -> block, wire-verified ----------
say "phase 6/10 data: data-level enforcement (host listener + guest wire capture)"
D1_OUT="$STAGE/d1-listener.out"
rm -f "$D1_OUT"
# Preflight: the byte-level leg needs the host listener to co-bind
# 127.0.0.1:9999 with slirp's hostfwd socket (same port). Recent kernels
# (>= ~6.x) require SO_REUSEPORT on BOTH sockets for co-listeners, and
# slirp's hostfwd socket only sets SO_REUSEADDR — so on such kernels the
# bind fails and the byte-level leg is skipped (the wire-level checks below
# still run and still fail the gate). Older kernels allow the co-bind.
if python3 -c '
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 9999)); s.listen(1)
' 2>/dev/null; then
    D1_LISTENER_OK=1
else
    D1_LISTENER_OK=0
    say "data: SKIP byte-level host-listener check: 127.0.0.1:9999 is not"
    say "       bindable next to the slirp hostfwd socket on this kernel (co-"
    say "       listeners require SO_REUSEPORT on both; slirp sets only"
    say "       SO_REUSEADDR). Wire-level D1 checks below are unaffected."
fi
if [ "$D1_LISTENER_OK" = 1 ]; then
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
fi

D1_TOTAL=0
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_data_probe.sh baseline' || D1_TOTAL=$((D1_TOTAL + 1))
say "data: redeploying the stack for the allow + block legs"
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_deploy.sh' || D1_TOTAL=$((D1_TOTAL + 1))
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_data_probe.sh allow' || D1_TOTAL=$((D1_TOTAL + 1))
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_data_probe.sh block' || D1_TOTAL=$((D1_TOTAL + 1))

sleep 1
[ "$D1_LISTENER_OK" = 1 ] && kill "$D1_PID" 2>/dev/null || true
if [ "$D1_LISTENER_OK" = 1 ]; then
    if grep -q "baseline RECEIVED: .*FW-D1-BASELINE" "$D1_OUT" 2>/dev/null \
        && grep -q "allow RECEIVED: .*FW-D1-ALLOW" "$D1_OUT" 2>/dev/null; then
        say "PASS: data: host listener received both payloads (byte-level delivery)"
    else
        say "FAIL: data: host listener did not receive both payloads:"
        sed 's/^/        | /' "$D1_OUT" 2>/dev/null || true
        D1_TOTAL=$((D1_TOTAL + 1))
    fi
fi
rc=$((rc + D1_TOTAL))

# ---------- 7. dv: default-verdict legs (ticket #159) ----------
# First phase that exercises the per-direction DEFAULT verdicts (#159) on
# the wire. Every leg runs with ZERO explicit rules (vm_dv.sh writes the
# leg's config, both rule arrays empty) — whatever crosses or is cut is the
# configured default, not a rule. egress legs are self-contained in the
# guest (write + restart + capture + probe + assert); the incoming legs are
# host-driven (arm -> ssh 2223 probes -> stop-capture -> verify), with the
# S1 mgmt collateral guard on the block leg (2222 must stay up — the DV
# config only ever touches the enforced enp0s3 path).
say "phase 7/10 dv: default-verdict legs (zero rules — the default is the policy)"
DV_TOTAL=0
# Byte-level host listener for the egress-allow leg (D1-style: slirp maps
# guest 10.0.3.2 -> host loopback; the phase-6 listener is gone, but the
# slirp hostfwd socket still co-binds 9999, so the same SO_REUSEPORT
# preflight applies).
DV_OUT="$STAGE/dv-listener.out"
rm -f "$DV_OUT"
DV_LISTENER_OK=0
if python3 -c '
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 9999)); s.listen(1)
' 2>/dev/null; then
    DV_LISTENER_OK=1
else
    say "dv: SKIP byte-level host-listener check (same SO_REUSEPORT co-bind"
    say "     constraint as phase 6; the wire-level checks are unaffected)"
fi
DV_PID=""
if [ "$DV_LISTENER_OK" = 1 ]; then
python3 - "$DV_OUT" <<'PYEOF' &
import socket, sys
out = open(sys.argv[1], "w")
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9999))
srv.listen(5)
srv.settimeout(240)
try:
    c, _ = srv.accept()
    data = c.recv(512)
    out.write("dv RECEIVED: %r\n" % (data,))
    out.flush()
    c.close()
except Exception as e:
    out.write("dv LISTENER ERROR: %r\n" % (e,))
    out.flush()
PYEOF
DV_PID=$!
sleep 1
fi

if "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_dv.sh run egress-allow'; then
    say "PASS: dv egress-allow: guest leg green (frames on the wire + verdict)"
else
    say "FAIL: dv egress-allow: guest leg failed"
    DV_TOTAL=$((DV_TOTAL + 1))
fi
if "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_dv.sh run egress-block'; then
    say "PASS: dv egress-block: guest leg green (cut at the boundary + verdict)"
else
    say "FAIL: dv egress-block: guest leg failed"
    DV_TOTAL=$((DV_TOTAL + 1))
fi
if [ "$DV_LISTENER_OK" = 1 ]; then
    [ -n "$DV_PID" ] && kill "$DV_PID" 2>/dev/null || true
    if grep -q "dv RECEIVED: .*FW-DV-ALLOW" "$DV_OUT" 2>/dev/null; then
        say "PASS: dv: host listener received the egress-allow payload (byte-level delivery, zero rules in effect)"
    else
        say "FAIL: dv: host listener did not receive the payload:"
        sed 's/^/        | /' "$DV_OUT" 2>/dev/null || true
        DV_TOTAL=$((DV_TOTAL + 1))
    fi
fi

# incoming legs (host-driven; the ssh 2223 probes ride the enforced enp0s3
# path, so the default INCOMING verdict is what lets them through or not)
if "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_dv.sh arm incoming-allow'; then
    up=0
    for i in 1 2 3; do
        if ssh_2223; then
            up=$((up + 1))
        else
            say "FAIL: dv incoming-allow: ssh 2223 down (attempt $i) — the default Allow did not open the path"
            DV_TOTAL=$((DV_TOTAL + 1))
        fi
        sleep 2
    done
    if [ "$up" -eq 3 ]; then
        say "PASS: dv incoming-allow: 2223 up 3/3 under the default (zero rules at all)"
    fi
    "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_dv.sh stop-capture incoming-allow' || DV_TOTAL=$((DV_TOTAL + 1))
    "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_dv.sh verify incoming-allow' || DV_TOTAL=$((DV_TOTAL + 1))
else
    say "FAIL: dv incoming-allow: guest arm failed"
    DV_TOTAL=$((DV_TOTAL + 1))
fi
if "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_dv.sh arm incoming-block'; then
    down=0
    mgmt=0
    for i in 1 2 3; do
        if ssh_2223; then
            say "FAIL: dv incoming-block: ssh 2223 SUCCEEDED (attempt $i) — the default Block did not hold"
            DV_TOTAL=$((DV_TOTAL + 1))
        else
            down=$((down + 1))
        fi
        if "$FW_VM" ssh true 2>/dev/null; then
            mgmt=$((mgmt + 1))
        else
            say "FAIL: dv incoming-block (M1): mgmt 2222 down (attempt $i) — collateral lockout"
            DV_TOTAL=$((DV_TOTAL + 1))
        fi
        sleep 2
    done
    if [ "$down" -eq 3 ]; then
        say "PASS: dv incoming-block: 2223 down 3/3 under the default (no rule anywhere)"
    fi
    if [ "$mgmt" -eq 3 ]; then
        say "PASS: dv incoming-block (M1): mgmt 2222 up 3/3 (collateral guard held)"
    fi
    "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_dv.sh stop-capture incoming-block' || DV_TOTAL=$((DV_TOTAL + 1))
    "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_dv.sh verify incoming-block' || DV_TOTAL=$((DV_TOTAL + 1))
else
    say "FAIL: dv incoming-block: guest arm failed"
    DV_TOTAL=$((DV_TOTAL + 1))
fi
# restore the standard rig config for the remaining phases (S1 expects the
# allow-22 rule; C1 expects the canonical three tomls)
say "dv: redeploying the standard rig config"
"$FW_VM" ssh 'bash /tmp/fw-e2e-vm_deploy.sh' || DV_TOTAL=$((DV_TOTAL + 1))
rc=$((rc + DV_TOTAL))

# ---------- 8. S1: deliberate SSH block + M1 mgmt collateral guard ----------
# Design doc §2.2 (inverted for this rig: the block targets the ENFORCED path —
# incoming tcp/22 on enp0s3, i.e. the 2223 hostfwd — because FireWhal only
# enforces `enforced_interfaces`; the unenforced mgmt path 2222 must stay up,
# which is exactly the M1 guard, §2.3). The VM owns its own unlock: a VM-local
# self-expiry sleeper (a detached guest process — see vm_s1.sh for why a
# systemd one-shot does not work on this guest) restores the config and
# restarts the stack after the window. If the block regresses (no cut), 2223
# stays up and the "must be down" checks fail — the test can never lock us
# out of itself (2222 is never at risk).
say "phase 8/10 ssh-block (S1): block the enforced-path SSH, keep mgmt up, self-expiry recovery"
S1_TOTAL=0
S1_WINDOW="${FW_S1_WINDOW:-120}"
T0=0
if ssh_2223; then
    say "S1 baseline: 2223 (OOB, via the enforced enp0s3 path) up"
else
    say "FAIL: S1 baseline: 2223 not up before the block (prior phase state is wrong)"
    S1_TOTAL=$((S1_TOTAL + 1))
fi
if "$FW_VM" ssh true 2>/dev/null; then
    say "S1 baseline: 2222 (mgmt, unenforced enp0s2) up"
else
    say "FAIL: S1 baseline: mgmt 2222 not up"
    S1_TOTAL=$((S1_TOTAL + 1))
fi

if [ "$S1_TOTAL" -eq 0 ]; then
    # arm + block (in-guest): self-expiry sleeper, wire capture, config swap, restart
    if "$FW_VM" ssh "FW_S1_WINDOW=$S1_WINDOW bash /tmp/fw-e2e-vm_s1.sh block"; then
        T0=$(date +%s)
    else
        say "FAIL: S1: the guest block sequence did not complete"
        S1_TOTAL=$((S1_TOTAL + 1))
        T0=$(date +%s)
    fi
fi

if [ "$S1_TOTAL" -eq 0 ]; then
    # the window: 2223 must fail 100% (the block cut SSH, as configured);
    # mgmt 2222 must stay up 100% (M1: no collateral lockout)
    down=0
    mgmt_ok=0
    for i in 1 2 3 4 5; do
        if ssh_2223; then
            say "FAIL: S1 window: ssh 2223 SUCCEEDED (attempt $i) — the block did not hold"
            S1_TOTAL=$((S1_TOTAL + 1))
        else
            down=$((down + 1))
        fi
        if "$FW_VM" ssh true 2>/dev/null; then
            mgmt_ok=$((mgmt_ok + 1))
        else
            say "FAIL: S1 window (M1): mgmt 2222 DOWN (attempt $i) — collateral lockout"
            S1_TOTAL=$((S1_TOTAL + 1))
        fi
        sleep 3
    done
    if [ "$down" -eq 5 ]; then
        say "PASS: S1 window: 2223 down 5/5 during the block (the rule cut SSH)"
    fi
    if [ "$mgmt_ok" -eq 5 ]; then
        say "PASS: M1: mgmt 2222 up 5/5 during the block (collateral guard held)"
    fi
    # record the window in the guest timeline (design §2.2 step 5).
    # date -u: the timeline is guest-UTC; the host is not.
    "$FW_VM" ssh "echo \"[$(date -u '+%H:%M:%S')] window: 2223 down ${down}/5, mgmt 2222 up ${mgmt_ok}/5\" >> /var/lib/fw-e2e/fw-s1-timeline" >/dev/null 2>&1 || true
    # stop the block capture; pre-arm the recovery capture (mgmt is still up)
    "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_s1.sh stop-capture block' || S1_TOTAL=$((S1_TOTAL + 1))
    "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_s1.sh start-recover-capture' || S1_TOTAL=$((S1_TOTAL + 1))

    # wait for the self-expiry (fires at T0+window, late on this rig — the
    # guest's NTP slewing makes real-time delays (the sleeper's sleep, the
    # systemd-timer runs that preceded it) run +6..+43 s over, measured) and
    # the recovery; the deadline absorbs the observed lag
    RECOVERED=0
    RECOVER_AT=0
    deadline=$((T0 + S1_WINDOW + 120))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if ssh_2223; then
            RECOVERED=1
            RECOVER_AT=$(date +%s)
            break
        fi
        sleep 5
    done
    if [ "$RECOVERED" -eq 1 ]; then
        say "PASS: S1 recovery: 2223 back +$((RECOVER_AT - T0))s after the block — the VM unlocked itself (no outside intervention)"
    else
        say "FAIL: S1 recovery: 2223 still down $(date +%s | awk -v t="$T0" -v w="$S1_WINDOW" '{print $1 - t - w}')s past the expected unlock"
        say "      manual recovery from mgmt: $FW_VM ssh 'sudo bash /var/lib/fw-e2e/fw-e2e-s1-unlock.sh'"
        S1_TOTAL=$((S1_TOTAL + 1))
    fi
    "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_s1.sh stop-capture recover' || S1_TOTAL=$((S1_TOTAL + 1))

    # guest-side verification: config restore, readiness, verdict, wire, timeline
    "$FW_VM" ssh 'bash /tmp/fw-e2e-vm_s1.sh verify' || S1_TOTAL=$((S1_TOTAL + 1))
fi
rc=$((rc + S1_TOTAL))

# ---------- 8. C1: config-path regression (design doc §2.4) ----------
# A missing/malformed config toml must leave the stack UP in the fail-closed
# default (a dead firewall is fail-open — the worst case) and loudly
# announced (alarm bundle + TUI + the oneshot validator). Each leg asserts
# the posture ON THE WIRE (D1-style capture) and verifies the alarm log
# records both the degradation and the recovery.
say "phase 9/10 c1: config-path regression (3 legs + validator)"
C1_TOTAL=0
health_rc() { # the firewhal-health validator's exit code (0 healthy, 1 degraded)
    "$FW_VM" ssh "bash -c '/opt/firewhal/bin/firewhal-health >/tmp/fw-c1-health.out 2>&1; echo RC=\$?'" \
        | grep -o 'RC=[0-9]*' | cut -d= -f2
}
# Fresh short mgmt ssh with liveness probes: a probe whose channel is
# severed at the attach moment (interfaces leg, by design) self-terminates
# in ~20 s instead of hanging forever.
c1_ssh_probe() {
    ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 \
        -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
        ubuntu@127.0.0.1 "$@" 2>/dev/null
}
for LEG in rules interfaces apps; do
    say "c1 leg $LEG: moving the toml aside"
    if "$FW_VM" ssh "bash /tmp/fw-e2e-vm_c1.sh move $LEG"; then
        say "PASS: c1 $LEG: toml moved aside"
    else
        say "FAIL: c1 $LEG: moving the toml aside failed"
        C1_TOTAL=$((C1_TOTAL + 1))
    fi
    HR=$(health_rc || true)
    if [ "${HR:-x}" = 1 ]; then
        say "PASS: c1 $LEG: firewhal-health rc=1 while misplaced (never green on a broken config)"
    else
        say "FAIL: c1 $LEG: firewhal-health rc=${HR:-?} while misplaced (expected 1)"
        C1_TOTAL=$((C1_TOTAL + 1))
    fi
    # degraded start: the stack must still come up (fail-closed, not dead).
    # `start` is dispatched detached (the in-flight ssh session may be
    # severed by the attach — by design). Poll the outcome from the HOST
    # with fresh short probes: the interfaces leg's attach goes to the mgmt
    # path, so a probe spanning the attach moment is severed (its channel
    # dies mid-poll); ServerAliveInterval bounds such a probe to ~20 s and
    # the loop converges once the window has passed.
    "$FW_VM" ssh "bash /tmp/fw-e2e-vm_c1.sh start" || C1_TOTAL=$((C1_TOTAL + 1))
    start_reported=""
    for attempt in $(seq 1 30); do
        st=$(c1_ssh_probe "bash /tmp/fw-e2e-vm_c1.sh c1-status" | head -n 1)
        case "$st" in
            READY|FAILED) start_reported="$st"; break ;;
        esac
        sleep 5
    done
    if [ "$start_reported" = READY ]; then
        say "PASS: c1 $LEG: detached start reported READY"
    else
        say "FAIL: c1 $LEG: detached start reported ${start_reported:-nothing within ~5 min}"
        C1_TOTAL=$((C1_TOTAL + 1))
    fi
    # wire assertion for this leg's posture
    "$FW_VM" ssh "bash /tmp/fw-e2e-vm_c1.sh probe $LEG" || C1_TOTAL=$((C1_TOTAL + 1))
    if [ "$LEG" = interfaces ]; then
        # M1-under-the-default: the mgmt path (2222) is now enforced too —
        # it must stay reachable because the test rules allow tcp/22
        mgmt_up=0
        for i in 1 2 3; do
            if "$FW_VM" ssh true 2>/dev/null; then mgmt_up=$((mgmt_up + 1)); fi
            sleep 2
        done
        if [ "$mgmt_up" -eq 3 ]; then
            say "PASS: c1 interfaces: mgmt 2222 reachable 3/3 under the all-non-loopback default"
        else
            say "FAIL: c1 interfaces (M1): mgmt 2222 reachable ${mgmt_up}/3 under the default — management locked out"
            C1_TOTAL=$((C1_TOTAL + 1))
        fi
    fi
    # restore the file (restarts the stack healthy) and verify the alarms
    "$FW_VM" ssh "bash /tmp/fw-e2e-vm_c1.sh restore $LEG" || C1_TOTAL=$((C1_TOTAL + 1))
    HR=$(health_rc || true)
    if [ "${HR:-x}" = 0 ]; then
        say "PASS: c1 $LEG: firewhal-health rc=0 after restore"
    else
        say "FAIL: c1 $LEG: firewhal-health rc=${HR:-?} after restore (expected 0)"
        C1_TOTAL=$((C1_TOTAL + 1))
    fi
    "$FW_VM" ssh "bash /tmp/fw-e2e-vm_c1.sh verify $LEG" || C1_TOTAL=$((C1_TOTAL + 1))
done
rc=$((rc + C1_TOTAL))

# ---------- 9. cleanup: power the VM off ----------
say "phase 10/10 cleanup: shutting the VM down"
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
