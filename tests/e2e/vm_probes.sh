#!/usr/bin/env bash
# FireWhal e2e probes — runs INSIDE the fw-test VM (invoked by run-e2e.sh).
#
# Assertions are LOG-SIGNAL based, not wire-outcome based: enp0s3 is an
# isolated slirp network with nothing listening, so the HTTP probes never
# complete on the wire. The firewhal-kernel verdict lines are the truth:
#   allow:      "Rule N ALLOWED connection to <ip>:<port>"
#   rule block: "No rule matched. Blocking connection to <ip>:<port>"
#   app block:  "Inserted trust for PID N: Deny"
#               "Pending Connection Blocked (PID Denied) N"
# Egress is forced through the test NIC with SO_BINDTODEVICE (both slirp NICs
# share the guest IP, so the interface flag / bind device picks the NIC).
set -uo pipefail

LOG=/tmp/firewhal-daemon.err
IFACE=enp0s3
PASS=0
FAIL=0

say() { printf '[probe] %s\n' "$*"; }

newlog_since() { tail -n +$(( $1 + 1 )) "$LOG"; }

check() { # $1=name  $2=haystack  $3=ERE pattern
    if printf '%s\n' "$2" | grep -qE "$3"; then
        say "PASS: $1"
        PASS=$((PASS + 1))
    else
        say "FAIL: $1 (expected pattern: $3)"
        printf '%s\n' "$2" | head -n 20 | sed 's/^/        | /'
        FAIL=$((FAIL + 1))
    fi
}

# ---------- phase: ipc_smoke (router round-trip) ----------
say "phase: ipc_smoke (DEALER connect, TUI registration, ping/pong)"
SMOKE_OUT=$(sudo /opt/firewhal/bin/ipc_smoke 2>&1 || true)
if printf '%s\n' "$SMOKE_OUT" | grep -q "SUCCESS: router round-trip verified"; then
    say "PASS: ipc_smoke"
    PASS=$((PASS + 1))
else
    say "FAIL: ipc_smoke"
    printf '%s\n' "$SMOKE_OUT" | sed 's/^/        | /'
    FAIL=$((FAIL + 1))
fi

say "phase: enforcement"

# --- P1 allow: trusted curl (in the allowlist) -> allowed port :80
off=$(wc -l < "$LOG")
curl --interface "$IFACE" --max-time 5 -s -o /dev/null http://10.0.2.2:80 || true
sleep 2
check "allow: trusted curl -> 10.0.2.2:80 permitted by the rules" \
    "$(newlog_since "$off")" "Rule [0-9]+ ALLOWED connection to 10.0.2.2:80"

# --- P2 rule block: trusted curl -> :8080 (no rule matches)
off=$(wc -l < "$LOG")
curl --interface "$IFACE" --max-time 5 -s -o /dev/null http://10.0.2.2:8080 || true
sleep 2
check "rule-block: trusted curl -> 10.0.2.2:8080 blocked (no matching rule)" \
    "$(newlog_since "$off")" "No rule matched. Blocking connection to 10.0.2.2:8080"

# --- P3 app block: untrusted python3 (not in the allowlist) -> allowed port :443
off=$(wc -l < "$LOG")
sudo timeout 10 python3 - "$IFACE" <<'PYEOF' || true
import socket, sys
s = socket.socket()
s.bind(("10.0.2.15", 0))
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, sys.argv[1].encode() + b"\x00")
s.settimeout(5)
try:
    s.connect(("10.0.2.2", 443))
except Exception as e:
    print("connect failed (expected on this dead-end net):", e)
PYEOF
sleep 2
hay=$(newlog_since "$off")
check "app-block: untrusted python3 -> 10.0.2.2:443 denied at the app gate" \
    "$hay" "Inserted trust for PID [0-9]+: Deny"
check "app-block: pending connection dropped (PID Denied)" \
    "$hay" "Pending Connection Blocked \(PID Denied\)"

say "results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
