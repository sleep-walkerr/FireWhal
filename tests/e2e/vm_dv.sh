#!/usr/bin/env bash
# FireWhal e2e DV — default-verdict legs (ticket #159). The first phase that
# exercises the per-direction DEFAULT verdicts (the `ufw default` analogue)
# as the policy itself: every leg runs with ZERO explicit rules (both rule
# arrays empty), so whatever crosses or is cut is the configured default,
# not a rule. Wire-verified D1-style: the egress tap sits downstream of the
# TC egress drop (frames present == crossed, 0 == cut), and the ingress tap
# sits UPSTREAM of the TC ingress drop (S1 finding: blocked SYNs are visible
# at the tap), so the ingress oracle is "the guest never replies" — no
# frame with the ACK flag for the probe flow.
#
# Leg matrix (write_config emits the leg's firewall_rules.toml; the stack
# restarts per leg and must pass the full readiness gate):
#   egress-allow   in=Block out=Allow   guest curl POST :9999 -> frames +
#                  verdict line (the payload reaches the host listener the
#                  gate arms, byte-level)
#   egress-block   in=Block out=Block   guest curl :8080 -> 0 frames +
#                  verdict line (cut at the boundary)
#   incoming-allow in=Allow out=Allow   host ssh 2223 up -> guest replies on
#                  the wire (ACK frames for :22) + verdict line
#                  (out=Allow is deliberate: the sshd's replies are egress
#                  and must cross for the handshake to complete)
#   incoming-block in=Block out=Allow   host ssh 2223 down -> no guest reply
#                  (0 ACK frames for :22; the blocked SYNs are visible at
#                  the tap) + verdict line. out=Allow isolates INCOMING as
#                  the only variable.
#
# Subcommands (all in-guest; the gate drives the incoming legs from the host
# between arm and verify, S1-style):
#   run <egress-leg>          write config, restart, capture, probe, assert
#   arm <incoming-leg>        write config, restart, arm the capture
#   stop-capture <leg>        stop that leg's capture
#   verify <incoming-leg>     assert the wire oracle + the verdict line
#
# No self-expiry sleeper (unlike S1): the worst leg only blocks the OOB
# 2223 path, and the unenforced mgmt 2222 (enp0s2) stays up, so the gate
# always keeps control; it redeploys the standard rig config at the end.
set -uo pipefail

CMD="${1:?usage: vm_dv.sh run <egress-leg> | arm <incoming-leg> | stop-capture <leg> | verify <incoming-leg>}"
LEG="${2:?missing leg name}"

LOG_OUT=/tmp/firewhal-daemon.out
LOG_ERR=/tmp/firewhal-daemon.err
IFACE=enp0s3
PEER=10.0.3.2
CAP=/tmp/dv-${LEG}.pcap
TCPPID=""
PASS=0
FAIL=0

say() { printf '[dv] %s\n' "$*"; }
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

# Per-leg defaults. ZERO rules in every leg — the default IS the policy.
# Return format: "out|in" (outgoing first).
cfg_for() { # leg -> "out|in"
    case "$1" in
        egress-allow)   echo 'Allow|Block' ;;
        egress-block)   echo 'Block|Block' ;;
        incoming-allow) echo 'Allow|Allow' ;;
        incoming-block) echo 'Allow|Block' ;;
        *) say "FATAL: unknown leg '$1' (expected egress-allow|egress-block|incoming-allow|incoming-block)"; exit 2 ;;
    esac
}

write_config() { # $1=leg
    local defs out in
    defs=$(cfg_for "$1")
    out=${defs%%|*}
    in=${defs##*|}
    sudo tee /etc/firewhal/firewall_rules.toml >/dev/null <<EOF
# e2e DV leg: $1 — ZERO rules; the per-direction defaults are the policy.
default_incoming = "$in"
default_outgoing = "$out"
incoming_rules = []
outgoing_rules = []
EOF
    say "wrote /etc/firewhal/firewall_rules.toml (leg $1: incoming=$in outgoing=$out, zero rules)"
}

teardown() {
    # Match by process name (comm), not command line: a -f pattern would
    # appear in the sudo wrapper's own cmdline and pkill would kill its parent.
    for name in firewhal-daemon firewhal-ipc firewhal-kernel firewhal-discor; do
        sudo pkill -9 "$name" 2>/dev/null || true
    done
    sleep 2
    if sudo pgrep 'firewhal-(daemon|ipc|kernel|discor)' >/dev/null 2>&1; then
        say "FATAL: firewhal processes survived the teardown"
        return 1
    fi
    sudo rm -f "$LOG_OUT" "$LOG_ERR"
}

# The same readiness criteria as vm_deploy.sh / vm_c1.sh: 3 processes, all
# FireWhal BPF programs including both TC classifiers, and all three config
# pushes in the daemon log (the loaded zero-rules config still pushes, as
# "(configured)" — only the fail-closed fallback pushes the degraded form).
wait_ready() {
    local i procs bpf tc cg so
    for i in $(seq 1 24); do
        sleep 5
        procs=$(sudo pgrep -cf 'firewhal-(daemon|ipc|kernel)' || true)
        bpf="$(sudo bpftool prog show 2>/dev/null || true)"
        tc=$(printf '%s\n' "$bpf" | grep -c 'sched_cls.*firewhal' || true)
        cg=$(printf '%s\n' "$bpf" | grep -c 'cgroup_sock_addr.*firewhal' || true)
        so=$(printf '%s\n' "$bpf" | grep -c 'sock_ops.*firewhal' || true)
        if [ "${procs:-0}" -ge 3 ] && [ "${tc:-0}" -ge 2 ] && [ "${cg:-0}" -ge 1 ] && [ "${so:-0}" -ge 1 ] \
            && sudo grep -q 'C1: rules sent' "$LOG_OUT" \
            && sudo grep -q 'C1: app ids sent' "$LOG_OUT" \
            && sudo grep -q 'C1: interface state sent' "$LOG_OUT"; then
            say "stack ready after $((i * 5))s: $procs procs, ${tc} sched_cls, ${cg} cgroup_sock_addr, ${so} sock_ops"
            return 0
        fi
    done
    say "FATAL: stack not ready within 120s"
    sudo tail -n 40 "$LOG_OUT" 2>/dev/null || true
    sudo tail -n 40 "$LOG_ERR" 2>/dev/null || true
    return 1
}

start_capture() {
    # sudo rm: the previous leg's capture is tcpdump-owned in the sticky
    # /tmp, a plain rm -f gets "Operation not permitted" (same trap as D1)
    #
    # stdout MUST be redirected (S1's .out pattern): a backgrounded tcpdump
    # that inherits the ssh session's stdout holds the pipe open and hangs
    # the caller — the first DV run hung the gate on the incoming-allow arm
    # exactly this way (guest side finished, the arm call never returned).
    #
    # The pid is saved to a file: stop-capture runs in a SEPARATE ssh call
    # for the incoming legs (S1-style), where $TCPPID is not inherited —
    # the first DV run's no-op cross-call kill let tcpdumps accumulate
    # (3+ survivors per leg, one since the hung run).
    sudo rm -f "$CAP" "${CAP}.err" "${CAP}.out" "${CAP}.pid"
    sudo tcpdump -i "$IFACE" -w "$CAP" >"$CAP.out" 2>"$CAP.err" &
    TCPPID=$!
    echo "$TCPPID" > "$CAP.pid"
    local i
    for i in $(seq 1 25); do
        if grep -q "listening on" "$CAP.err" 2>/dev/null; then return 0; fi
        sleep 0.2
    done
    say "FATAL: tcpdump did not reach 'listening on' within 5s (see ${CAP}.err)"
    sed 's/^/       | /' "$CAP.err" 2>/dev/null || true
    return 1
}

stop_capture() {
    # $TCPPID is only set when start_capture ran in THIS shell (the egress
    # `run` legs); the incoming legs arm in a separate ssh call, so fall
    # back to the pid file. The kill must be real: a SIGTERM'd tcpdump
    # exits cleanly and flushes its stdio-buffered pcap (libpcap fully
    # buffers file output — a small capture sits in the 4KB buffer and the
    # file looks empty until a flush, which a dead-but-unflushed tcpdump
    # never does).
    local pid="${TCPPID:-}" i
    if [ -z "$pid" ] && [ -f "$CAP.pid" ]; then
        pid=$(cat "$CAP.pid" 2>/dev/null || true)
    fi
    sleep 1
    if [ -n "$pid" ]; then
        sudo kill "$pid" 2>/dev/null || true
        for i in $(seq 1 10); do
            sudo kill -0 "$pid" 2>/dev/null || break
            sleep 0.5
        done
    fi
    rm -f "$CAP.pid"
    if [ ! -s "$CAP" ]; then
        say "FATAL: capture file missing/empty (tcpdump did not run)"
        sed 's/^/       | /' "${CAP}.err" 2>/dev/null || true
        return 1
    fi
}

frames() { # $1=dst port -> TCP frame count to that port in the capture
    local n
    n=$(sudo tshark -r "$CAP" -Y "tcp and tcp.dstport==$1" 2>/dev/null | wc -l)
    if [ "$n" -eq 0 ]; then
        say "diag: 0 frames for dst port $1" >&2
        say "diag: $(sudo ls -la "$CAP" 2>&1 | tail -1)" >&2
    fi
    echo "$n"
}

case "$CMD" in
  run) # egress legs: self-contained (config, restart, capture, probe, assert)
      case "$LEG" in egress-allow|egress-block) ;; *) say "FATAL: run takes an egress leg (egress-allow|egress-block)"; exit 2 ;; esac
      write_config "$LEG"
      teardown || exit 1
      sudo /opt/firewhal/bin/firewhal-daemon
      wait_ready || exit 1
      off=$(wc -l < "$LOG_ERR" 2>/dev/null || echo 0)
      start_capture || exit 1
      if [ "$LEG" = egress-allow ]; then
          curl --interface "$IFACE" --max-time 8 -s -o /dev/null -X POST --data "FW-DV-ALLOW" "http://${PEER}:9999" || true
          PORT=9999
      else
          curl --interface "$IFACE" --max-time 8 -s -o /dev/null "http://${PEER}:8080" || true
          PORT=8080
      fi
      sleep 1
      stop_capture || exit 1
      hay=$(tail -n +$((off + 1)) "$LOG_ERR" 2>/dev/null || true)
      n=$(frames "$PORT")
      if [ "$LEG" = egress-allow ]; then
          if [ "$n" -ge 1 ]; then
              say "PASS: egress-allow: $n frames on the wire — the default let the traffic cross (zero rules in effect)"
              PASS=$((PASS + 1))
          else
              say "FAIL: egress-allow: 0 frames — the default Allow did not let the traffic cross"
              FAIL=$((FAIL + 1))
          fi
          check "egress-allow: verdict line (default OUTGOING = Allow)" \
              "$hay" "No rule matched; default OUTGOING = Allow\. Allowing connection to ${PEER}:${PORT}"
      else
          if [ "$n" -eq 0 ]; then
              say "PASS: egress-block: 0 frames — the default cut it at the boundary (egress tap downstream)"
              PASS=$((PASS + 1))
          else
              say "FAIL: egress-block: $n frames — the default Block did not hold"
              FAIL=$((FAIL + 1))
          fi
          check "egress-block: verdict line (default OUTGOING = Block)" \
              "$hay" "No rule matched; default OUTGOING = Block\. Blocking connection to ${PEER}:${PORT}"
      fi
      say "results: $PASS passed, $FAIL failed"
      [ "$FAIL" -eq 0 ]
      ;;

  arm) # incoming legs: config + restart + capture; the gate runs the ssh
       # probes from the host, then stop-capture + verify
      case "$LEG" in incoming-allow|incoming-block) ;; *) say "FATAL: arm takes an incoming leg (incoming-allow|incoming-block)"; exit 2 ;; esac
      write_config "$LEG"
      teardown || exit 1
      sudo /opt/firewhal/bin/firewhal-daemon
      wait_ready || exit 1
      start_capture || exit 1
      say "armed leg $LEG (capture running on $CAP; run the host ssh probes, then: $0 stop-capture $LEG; $0 verify $LEG)"
      ;;

  stop-capture)
      stop_capture || exit 1
      say "capture stopped"
      ;;

  verify)
      case "$LEG" in incoming-allow|incoming-block) ;; *) say "FATAL: verify takes an incoming leg"; exit 2 ;; esac
      # fresh log: the arm's teardown removed it, the daemon truncated it on
      # start — everything in the file is from the leg's window, so read the
      # WHOLE file (a tail window misses the SYN verdict once the post-
      # handshake cgroup relay noise from the probes outgrows it — the first
      # post-fix run lost the line this way, 3 full SSH sessions of noise)
      hay=$(cat "$LOG_ERR" 2>/dev/null || true)
      if [ ! -s "$CAP" ]; then
          say "FAIL: verify: capture missing for $LEG (stop-capture never ran cleanly)"
          FAIL=$((FAIL + 1))
      else
      syns=$(sudo tshark -r "$CAP" -Y 'tcp and tcp.dstport==22' 2>/dev/null | wc -l)
      acks=$(sudo tshark -r "$CAP" -Y 'tcp and tcp.dstport==22 and tcp.ack==1' 2>/dev/null | wc -l)
      if [ "$LEG" = incoming-allow ]; then
          if [ "$acks" -ge 1 ]; then
              say "PASS: incoming-allow: $acks reply frame(s) for :22 — the handshake crossed (guest replied)"
              PASS=$((PASS + 1))
          else
              say "FAIL: incoming-allow: 0 ACK frames for :22 — the guest never replied (the default Allow did not open the path)"
              FAIL=$((FAIL + 1))
          fi
          check "incoming-allow: verdict line (default INCOMING = Allow)" \
              "$hay" "No ingress rule matched; default INCOMING = Allow\. Allowing connection from 10\.0\.3\.2:[0-9]+"
      else
          if [ "$acks" -eq 0 ]; then
              say "PASS: incoming-block: no guest reply in the capture (0 ACK frames for :22; ${syns} frame(s) visible at the tap — the ingress tap sits upstream of the TC drop, S1 finding)"
              PASS=$((PASS + 1))
          else
              say "FAIL: incoming-block: $acks ACK frames for :22 — the guest replied, the default Block did not hold"
              sudo tshark -r "$CAP" -Y 'tcp and tcp.dstport==22 and tcp.ack==1' \
                  -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags 2>/dev/null \
                  | head -n 10 | sed 's/^/       | /'
              FAIL=$((FAIL + 1))
          fi
          check "incoming-block: verdict line (default INCOMING = Block)" \
              "$hay" "No ingress rule matched; default INCOMING = Block\. Blocking connection from 10\.0\.3\.2:[0-9]+"
      fi
      fi
      say "results: $PASS passed, $FAIL failed"
      [ "$FAIL" -eq 0 ]
      ;;

  *)
      say "FATAL: unknown command '$CMD' (expected run|arm|stop-capture|verify)"
      exit 2
      ;;
esac
