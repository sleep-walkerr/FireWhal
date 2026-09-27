#!/usr/bin/env bash
# FireWhal e2e C1 — config-path regression (ticket #106, design doc §2.4).
#
# Each leg moves one config toml aside, restarts the stack (WITHOUT the
# happy-path readiness gate — the degraded start must still come up), and
# asserts the resulting posture ON THE WIRE (D1-style capture):
#
#   rules       firewall_rules.toml missing -> empty rule set: default-deny,
#               probe :9999 cut (0 frames) — fail-closed
#   interfaces  interface_state.toml missing -> fail-closed default: TC hooks
#               on ALL non-loopback interfaces; enforcement still active
#               (:8080 cut, :9999 allowed) — the "not left unattached" check
#   apps        app_identity.toml missing -> bootstrapped empty allowlist:
#               egress denied at the app gate (:9999 cut) — fail-closed
#
# The daemon stays up in every leg (a dead firewall = no firewall =
# fail-open). It announces the degraded state in /var/log/firewhal/
# config-alert.log (CONFIG ALERT / CONFIG RECOVERED lines), which verify
# asserts. The `firewhal-health` validator (same parse as the daemon) is
# exercised by the gate directly: rc=1 while misplaced, 0 after restore.
#
# The recovery alarm survives the restore's stack restart because the daemon
# persists its health state (/var/log/firewhal/config-health.state) — a
# fresh process reads the previous (degraded) state and fires RECOVERED.
#
# `start` is dispatched DETACHED (setsid) and polled via `wait-start`:
# on the interfaces leg the new enforcement attaches to the mgmt interface
# mid-session, which severs the in-flight ssh session the moment the hook
# attaches (pre-existing connections are re-evaluated under the new stack —
# fresh connections work, verified). A detached runner + fresh-connection
# polling is immune to that.
#
# State: /var/lib/fw-e2e/c1-backup/ (never /tmp for the backups — S1
# forensics proved /tmp non-durable). The wire capture + start logs go to
# /tmp (the root-owned state dir would break the tcpdump stderr redirect).
set -uo pipefail

CMD="${1:?usage: vm_c1.sh move|start|wait-start|probe|restore|verify <leg>}"
LEG="${2:-}"

STATE=/var/lib/fw-e2e
C1DIR="$STATE/c1-backup"
LOG_OUT=/tmp/firewhal-daemon.out
LOG_ERR=/tmp/firewhal-daemon.err
IFACE=enp0s3
PEER=10.0.3.2
CAP=/tmp/c1-probe.pcap
START_LOG=/tmp/fw-c1-start.log
START_STATUS=/tmp/fw-c1-start.status
TCPPID=""
PASS=0
FAIL=0

say() { printf '[c1] %s\n' "$*"; }
check() { # $1=name  $2=condition (0/1)
    if [ "$2" -eq 0 ]; then
        say "PASS: $1"
        PASS=$((PASS + 1))
    else
        say "FAIL: $1"
        FAIL=$((FAIL + 1))
    fi
}

toml_for() { # leg -> toml path under /opt/firewhal/bin
    case "$1" in
        rules) echo /opt/firewhal/bin/firewall_rules.toml ;;
        interfaces) echo /opt/firewhal/bin/interface_state.toml ;;
        apps) echo /opt/firewhal/bin/app_identity.toml ;;
        *) say "FATAL: unknown leg '$1'"; exit 2 ;;
    esac
}

# Wait for stack readiness. C1 variant of the deploy readiness check: it
# works for HEALTHY and DEGRADED starts alike (the daemon always pushes the
# effective config — loaded or fail-closed default — and logs the C1 push
# lines either way).
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

teardown() {
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

start_internal() { # the actual start; runs detached from any ssh session
    rm -f "$START_STATUS"
    teardown || { echo FAILED > "$START_STATUS"; return 1; }
    sudo /opt/firewhal/bin/firewhal-daemon
    if wait_ready; then
        echo READY > "$START_STATUS"
        return 0
    else
        echo FAILED > "$START_STATUS"
        return 1
    fi
}

start_capture() {
    # sudo rm: the previous leg's capture is tcpdump-owned in the sticky /tmp,
    # a plain rm -f gets "Operation not permitted" (same trap as D1)
    sudo rm -f "$CAP" "${CAP}.err"
    sudo tcpdump -i "$IFACE" -w "$CAP" 2>"$CAP.err" &
    TCPPID=$!
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
    sleep 1
    kill "$TCPPID" 2>/dev/null
    wait "$TCPPID" 2>/dev/null
    if [ ! -s "$CAP" ]; then
        say "FATAL: capture file missing/empty (tcpdump did not run)"
        sed 's/^/       | /' "$CAP.err" 2>/dev/null || true
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
  move)
      f=$(toml_for "$LEG")
      sudo install -d -m 755 "$C1DIR"
      sudo rm -f "$C1DIR/$(basename "$f").bak"
      sudo mv "$f" "$C1DIR/$(basename "$f").bak"
      say "moved $f -> $C1DIR/"
      ;;

  start)
      say "dispatching detached start (the new enforcement may sever this ssh session — by design)"
      rm -f "$START_LOG" "$START_STATUS"
      # setsid: new session -> the runner survives this ssh connection dying
      setsid bash "$0" __start-internal >>"$START_LOG" 2>&1 < /dev/null &
      # brief grace: give the runner a moment to begin, then report dispatch
      # success to the caller. The real outcome is polled via wait-start.
      sleep 2
      say "start dispatched; poll with: $0 wait-start"
      ;;

  __start-internal)
      start_internal
      ;;

  c1-status)
      # Non-blocking status read for the gate's host-side polling (each
      # probe is a fresh short connection — a probe spanning the attach
      # moment may be severed, by design; the poller tolerates it).
      if [ -f "$START_STATUS" ]; then
          cat "$START_STATUS"
          sed 's/^/[c1] | /' "$START_LOG" 2>/dev/null || true
      else
          echo PENDING
      fi
      ;;

  wait-start)
      # Poll from a FRESH connection (fresh connections survive the attach;
      # the dispatched runner's own session may have been severed).
      i=0
      while [ "$i" -lt 30 ]; do
          if [ -f "$START_STATUS" ]; then
              st=$(cat "$START_STATUS")
              sed 's/^/[c1] | /' "$START_LOG" 2>/dev/null || true
              if [ "$st" = READY ]; then
                  say "start completed: READY"
                  exit 0
              else
                  say "start completed: $st"
                  exit 1
              fi
          fi
          i=$((i + 1))
          sleep 5
      done
      say "FATAL: start did not report within 150s"
      sed 's/^/[c1] | /' "$START_LOG" 2>/dev/null || true
      exit 1
    ;;

  probe)
      start_capture || exit 1
      case "$LEG" in
        rules)
            # default-deny: the D1 probe port (allowed under normal config)
            # must be cut at the rule layer
            curl --interface "$IFACE" --max-time 8 -s -o /dev/null "http://${PEER}:9999" || true
            ;;
        interfaces)
            # enforcement must be ACTIVE under the all-non-loopback default:
            # no-rule port cut, allowed port delivered
            curl --interface "$IFACE" --max-time 8 -s -o /dev/null "http://${PEER}:8080" || true
            curl --interface "$IFACE" --max-time 8 -s -o /dev/null "http://${PEER}:9999" || true
            ;;
        apps)
            # empty allowlist: curl is untrusted -> denied at the app gate
            curl --interface "$IFACE" --max-time 8 -s -o /dev/null "http://${PEER}:9999" || true
            ;;
        *) say "FATAL: unknown leg '$LEG'"; exit 2 ;;
      esac
      sleep 1
      stop_capture || exit 1
      n=$(frames 9999)
      m=$(frames 8080)
      say "probe $LEG: $n frames for :9999, $m frames for :8080"
      case "$LEG" in
        rules)
            check "rules: default-deny held on the wire (:9999 cut, 0 frames)" $([ "$n" -eq 0 ] && echo 0 || echo 1)
            ;;
        interfaces)
            check "interfaces: enforcement active under the default (:8080 cut, 0 frames)" $([ "$m" -eq 0 ] && echo 0 || echo 1)
            check "interfaces: allowed port still delivered under the default (:9999, frames present)" $([ "$n" -ge 1 ] && echo 0 || echo 1)
            ;;
        apps)
            check "apps: egress denied at the app gate (:9999 cut, 0 frames)" $([ "$n" -eq 0 ] && echo 0 || echo 1)
            # the daemon must have bootstrapped the empty allowlist file
            if sudo test -f /opt/firewhal/bin/app_identity.toml; then
                check "apps: empty allowlist file bootstrapped by the daemon" 0
            else
                check "apps: empty allowlist file bootstrapped by the daemon" 1
            fi
            ;;
      esac
      say "results: $PASS passed, $FAIL failed"
      [ "$FAIL" -eq 0 ]
      ;;

  restore)
      f=$(toml_for "$LEG")
      if ! sudo mv "$C1DIR/$(basename "$f").bak" "$f" 2>/dev/null; then
          say "FATAL: no backup to restore for $LEG"
          exit 1
      fi
      say "restored $f; restarting the stack (mgmt path no longer enforced — this session survives)"
      teardown || exit 1
      sudo /opt/firewhal/bin/firewhal-daemon
      wait_ready || exit 1
      ;;

  verify)
      f=$(toml_for "$LEG")
      base=$(basename "$f")
      ALARM=/var/log/firewhal/config-alert.log
      if sudo test -f "$ALARM"; then
          say "PASS: verify: alarm log present ($ALARM)"
          PASS=$((PASS + 1))
      else
          say "FAIL: verify: alarm log missing ($ALARM)"
          FAIL=$((FAIL + 1))
      fi
      if sudo grep -q "CONFIG ALERT ${base}" "$ALARM"; then
          say "PASS: verify: CONFIG ALERT for $base logged"
          PASS=$((PASS + 1))
      else
          say "FAIL: verify: no CONFIG ALERT line for $base"
          FAIL=$((FAIL + 1))
      fi
      if sudo grep -q "CONFIG RECOVERED ${base}" "$ALARM"; then
          say "PASS: verify: CONFIG RECOVERED for $base logged"
          PASS=$((PASS + 1))
      else
          say "FAIL: verify: no CONFIG RECOVERED line for $base"
          FAIL=$((FAIL + 1))
      fi
      # the stack must be fully healthy again: all three C1 push lines with
      # the configured variants (no fail-closed defaults)
      if sudo grep -q "C1: rules sent (configured)" "$LOG_OUT" \
         && sudo grep -q "C1: app ids sent (configured)" "$LOG_OUT" \
         && sudo grep -q "C1: interface state sent (configured)" "$LOG_OUT"; then
          say "PASS: verify: stack healthy (all three configs pushed as configured)"
          PASS=$((PASS + 1))
      else
          say "FAIL: verify: stack not fully healthy after restore"
          sudo grep 'C1: .* sent' "$LOG_OUT" 2>/dev/null | sed 's/^/       | /' || true
          FAIL=$((FAIL + 1))
      fi
      say "alarm log tail:"
      sudo tail -n 8 "$ALARM" 2>/dev/null | sed 's/^/       | /' || true
      say "results: $PASS passed, $FAIL failed"
      [ "$FAIL" -eq 0 ]
      ;;

  *)
      say "FATAL: unknown command '$CMD' (expected move|start|wait-start|probe|restore|verify <leg>)"
      exit 2
      ;;
esac
