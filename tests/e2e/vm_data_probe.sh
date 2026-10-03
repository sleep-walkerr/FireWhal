#!/usr/bin/env bash
# FireWhal e2e D1 — data-level enforcement probes (ticket #106, design doc
# §2.1). The first phase that asserts WIRE OUTCOMES instead of log signals:
# while the probe runs, the guest captures the enforced interface (tcpdump on
# enp0s3 — the capture point sits downstream of every enforcement layer in
# both directions), and the host listens on 127.0.0.1:9999 (slirp maps
# guest 10.0.3.2 -> host loopback) to verify the exact bytes. tshark asserts
# frame presence/absence in the capture; the daemon log still carries the
# verdict lines.
#
# Egress is forced through the test NIC with --interface (both slirp NICs
# share the guest IP, so the interface flag picks the NIC).
#
# Legs (each with its own capture and its own assertions):
#   baseline  stack DOWN — the raw path must deliver the payload (if it does
#             not, the network is broken, not the firewall). Also verifies
#             the teardown leaves no residual FireWhal BPF behind.
#   allow     stack UP, rule allows :9999 — payload arrives at the listener,
#             probe frames present on the wire, "Rule N ALLOWED ..." verdict
#   block     stack UP, no rule for :8080 — connect fails, NO probe frames on
#             the wire (cut at the boundary, not lost downstream), "No rule
#             matched; default OUTGOING = Block. Blocking ..." verdict (#159:
#             the rig config's fail-closed default is what does the cutting)
set -uo pipefail

LEG="${1:?usage: vm_data_probe.sh baseline|allow|block}"
LOG=/tmp/firewhal-daemon.err
IFACE=enp0s3
PEER=10.0.3.2
PORT=9999
# block leg: no rule matches :8080 (and nothing listens there on the host)
if [ "$LEG" = block ]; then
    PORT=8080
fi
MARK="FW-D1-$(printf '%s' "$LEG" | tr a-z A-Z)"
CAP=/tmp/d1-${LEG}.pcap
PASS=0
FAIL=0

say() { printf '[data] %s\n' "$*"; }
check() { # $1=name  $2=haystack  $3=ERE pattern
    if printf '%s\n' "$2" | grep -qE "$3"; then
        say "PASS: $1"
        PASS=$((PASS + 1))
    else
        say "FAIL: $1 (expected pattern: $3)"
        printf '%s\n' "$2" | head -n 10 | sed 's/^/        | /'
        FAIL=$((FAIL + 1))
    fi
}
frames() { # $1=dst port -> TCP frames to that port in the capture
    local n
    n=$(sudo tshark -r "$CAP" -Y "tcp and tcp.dstport==$1" 2>/dev/null | wc -l)
    if [ "$n" -eq 0 ]; then
        say "diag: 0 frames for dst port $1" >&2
        say "diag: $(ls -la "$CAP" 2>&1 | tail -1)" >&2
        if [ -s "${CAP}.err" ]; then
            say "diag: tcpdump stderr:" >&2
            sed 's/^/diag: | /' "${CAP}.err" >&2
        fi
        if sudo pgrep -a tcpdump >/dev/null 2>&1; then
            say "diag: a tcpdump process is still running (stray): $(sudo pgrep -a tcpdump | tr '\n' ' ')" >&2
        fi
    fi
    echo "$n"
}
start_capture() {
    # sudo rm: the previous leg's capture is tcpdump-owned in the sticky
    # /tmp, a plain rm -f gets "Operation not permitted"
    sudo rm -f "$CAP" "${CAP}.err"
    sudo tcpdump -i "$IFACE" -w "$CAP" 2>"$CAP.err" &
    TCPPID=$!
    # Wait for the real "listening on" line, not a fixed sleep: under load
    # (right after a redeploy) startup can exceed 1 s and the fixed sleep
    # raced the probe, whose whole exchange is <100 ms.
    local _i
    for _i in $(seq 1 25); do
        if grep -q "listening on" "$CAP.err" 2>/dev/null; then return 0; fi
        sleep 0.2
    done
    say "FAIL: tcpdump did not reach 'listening on' within 5s (see ${CAP}.err)"
    return 0
}
stop_capture() {
    sleep 1
    kill "$TCPPID" 2>/dev/null
    wait "$TCPPID" 2>/dev/null
    if [ ! -s "$CAP" ]; then
        say "FAIL: capture file missing/empty (tcpdump did not run)"
        sed 's/^/        | /' "$CAP.err" 2>/dev/null || true
        FAIL=$((FAIL + 1))
    fi
}

# ---------- leg: baseline (stack down; the raw path must deliver) ----------
if [ "$LEG" = baseline ]; then
    say "leg: baseline (tearing down the stack first)"
    for name in firewhal-daemon firewhal-ipc firewhal-kernel firewhal-discor; do
        sudo pkill -9 "$name" 2>/dev/null || true
    done
    sleep 2
    if sudo pgrep 'firewhal-(daemon|ipc|kernel|discor)' >/dev/null 2>&1; then
        say "FAIL: baseline: firewhal processes survived the teardown"
        exit 1
    fi
    residual=$(sudo bpftool prog show 2>/dev/null | grep -c 'firewhal' || true)
    if [ "${residual:-0}" -ne 0 ]; then
        say "FAIL: baseline: $residual firewhal BPF program(s) survived the teardown"
        exit 1
    fi
    say "stack torn down cleanly (no residual FireWhal BPF)"

    start_capture
    curl --interface "$IFACE" --max-time 8 -s -o /dev/null -X POST --data "$MARK" "http://${PEER}:${PORT}" || true
    stop_capture
    if [ "$FAIL" -eq 0 ]; then
        n=$(frames "$PORT")
        if [ "$n" -ge 1 ]; then
            say "PASS: baseline: probe frames present on the wire ($n frames — raw path delivers)"
            PASS=$((PASS + 1))
        else
            say "FAIL: baseline: no probe frames on the wire (the network path itself is broken)"
            FAIL=$((FAIL + 1))
        fi
    fi
    say "results: $PASS passed, $FAIL failed"
    [ "$FAIL" -eq 0 ]
    exit 0
fi

# ---------- legs: allow / block (stack up) ----------
off=$(wc -l < "$LOG" 2>/dev/null || echo 0)

start_capture
if [ "$LEG" = allow ]; then
    curl --interface "$IFACE" --max-time 8 -s -o /dev/null -X POST --data "$MARK" "http://${PEER}:${PORT}" || true
else
    curl --interface "$IFACE" --max-time 8 -s -o /dev/null "http://${PEER}:${PORT}" || true
fi
stop_capture
hay=$(tail -n +$((off + 1)) "$LOG" 2>/dev/null || true)
n=$(frames "$PORT")

if [ "$LEG" = allow ]; then
    if [ "$n" -ge 1 ]; then
        say "PASS: allow: probe frames present on the wire ($n frames)"
        PASS=$((PASS + 1))
    else
        say "FAIL: allow: no probe frames on the wire"
        FAIL=$((FAIL + 1))
    fi
    check "allow: rule allowed the connection (verdict line)" \
        "$hay" "Rule [0-9]+ ALLOWED connection to ${PEER}:${PORT}"
else
    if [ "$n" -eq 0 ]; then
        say "PASS: block: no probe frames on the wire (cut at the boundary, not lost downstream)"
        PASS=$((PASS + 1))
    else
        say "FAIL: block: $n probe frames found on the wire — the block did not hold"
        FAIL=$((FAIL + 1))
    fi
    check "block: no rule matched, default cut it (verdict line)" \
        "$hay" "No rule matched; default OUTGOING = Block. Blocking connection to ${PEER}:${PORT}"
fi

say "results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
