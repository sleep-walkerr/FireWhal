#!/usr/bin/env bash
# FireWhal e2e S1 — deliberate SSH block (ticket #106, design doc
# docs/comprehensive-test-design.md §2.2) + the M1 mgmt collateral guard (§2.3).
#
# Inverted for this rig (documented in §2.2): FireWhal enforces only on
# `enforced_interfaces` (enp0s3 here), so a block rule targeting the mgmt NIC
# (enp0s2) would be a no-op. The block therefore targets the *enforced* path —
# incoming tcp/22 on enp0s3, i.e. the 2223 hostfwd — while the unenforced mgmt
# path (2222) must stay up (M1). The VM owns its own unlock: a VM-local
# self-expiry sleeper (a detached sleep-and-restore, /var/lib/fw-e2e/s1-*)
# restores the config and restarts the stack after the window, independent of
# SSH state. (Not a systemd timer: this guest's systemd 255 rejected
# KillMode=main — see the runbook's S1 forensics — and a one-shot systemd
# service under the default kill mode SIGTERMs the restarted daemon the moment
# the unit completes. A detached guest process avoids the whole mechanism.)
#
# Subcommands (all in-guest; the host drives them over the 2222 mgmt path):
#   block                    baseline sanity, arm the self-expiry sleeper,
#                            start the block wire capture, drop the incoming
#                            :22 rule, restart the stack, wait for readiness
#   start-recover-capture    pre-arm the recovery-leg wire capture (before the
#                            self-expiry fires)
#   stop-capture <name>      stop a running capture (block|recover)
#   verify                   assert config restore, readiness, the block verdict
#                            line, both wire captures (tshark) and the timeline
#
# All S1 state lives in /var/lib/fw-e2e (not /tmp: this guest does not keep
# /tmp contents across boot/cleanup cycles — see the runbook's S1 forensics).
#
# Safety (design §2.2): the only path to losing SSH is the *passing* path, and
# the self-expiry restores it. If the block regresses (no cut), 2223 stays up
# and the gate fails on "2223 must be down" — the test can never lock us out
# of itself (2222 is never at risk).
set -uo pipefail

CMD="${1:?usage: vm_s1.sh block|start-recover-capture|stop-capture <block|recover>|verify}"
LOG=/tmp/firewhal-daemon.err
LOG_OUT=/tmp/firewhal-daemon.out
IFACE=enp0s3
RULES=/etc/firewhal/firewall_rules.toml
STATE=/var/lib/fw-e2e
BACKUP="$STATE/fw-e2e-rules.bak"
TIMELINE="$STATE/fw-s1-timeline"
UNLOCK="$STATE/fw-e2e-s1-unlock.sh"
SNAP="$STATE/s1-block-daemon.log"
WINDOW="${FW_S1_WINDOW:-120}"
PASS=0
FAIL=0

say() { printf '[s1] %s\n' "$*"; }
ts() { date '+%H:%M:%S'; }
tl() { echo "[$(ts)] $*" >> "$TIMELINE"; }

# Readiness — the same criteria as vm_deploy.sh: 3 processes, all FireWhal BPF
# programs including both TC classifiers (the fail-open regression guard), and
# all three config pushes in the daemon log (no silent zero-rules start).
stack_ready() {
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
            return 0
        fi
    done
    return 1
}

teardown_stack() {
    # Match by process name (comm), not command line: a -f pattern would appear
    # in the sudo wrapper's own cmdline and pkill would kill its parent.
    for name in firewhal-daemon firewhal-ipc firewhal-kernel firewhal-discor; do
        sudo pkill -9 "$name" 2>/dev/null || true
    done
    sleep 2
    if sudo pgrep 'firewhal-(daemon|ipc|kernel|discor)' >/dev/null 2>&1; then
        say "FATAL: firewhal processes survived the teardown"
        return 1
    fi
    return 0
}

# Wait for the real "listening on" line, not a fixed sleep (D1 pattern).
wait_for_capture() { # $1=pcap path
    local i
    for i in $(seq 1 25); do
        if grep -q "listening on" "$1.err" 2>/dev/null; then return 0; fi
        sleep 0.2
    done
    say "FATAL: tcpdump did not reach 'listening on' within 5s (see $1.err)"
    sed 's/^/       | /' "$1.err" 2>/dev/null || true
    return 1
}

# setsid: the capture must outlive the ssh session that started it (the host
# drives the window probes from outside, and the block restart is in between).
start_capture() { # $1=block|recover
    local cap="$STATE/s1-$1.pcap"
    sudo rm -f "$cap" "${cap}.out" "${cap}.err"
    # The .out/.err redirects must happen as root: the state dir is
    # root-owned and the outer (ubuntu) shell cannot create files in it —
    # the first dry run of the /var/lib move failed exactly here
    # ("Permission denied" on $cap.out, tcpdump never started). sh -c
    # returns immediately; the setsid'ed tcpdump (its own session, no
    # controlling tty) is left behind.
    sudo sh -c "setsid tcpdump -i $IFACE -w $cap > $cap.out 2> $cap.err < /dev/null &"
    wait_for_capture "$cap"
}

case "$CMD" in
  block)
      # --- baseline sanity: the rule we are about to drop is present, stack up
      if ! grep -q 'dest_port = 22' "$RULES"; then
          say "FATAL: incoming :22 rule not present in the current config (prior phase state is wrong)"
          exit 1
      fi
      procs=$(sudo pgrep -cf 'firewhal-(daemon|ipc|kernel)' || true)
      if [ "${procs:-0}" -lt 3 ]; then
          say "FATAL: stack not up (${procs:-0} firewhal processes); run the deploy phase first"
          exit 1
      fi
      # S1 state lives in /var/lib/fw-e2e, not /tmp (this guest does not keep
      # /tmp contents across boot/cleanup cycles — runbook S1 forensics). The
      # timeline is root:ubuntu 662 so the ubuntu-side appends (this script,
      # the gate's window line) and the root-side appends (the self-expiry)
      # both work.
      sudo install -d -m 755 -o root -g root "$STATE"
      sudo cp "$RULES" "$BACKUP"
      sudo install -m 662 -o root -g ubuntu /dev/null "$TIMELINE"
      tl "baseline: incoming :22 rule confirmed; stack up; block starting (window=${WINDOW}s)"

      # --- wire capture for the block window (guest-side; the capture point
      #     sits downstream of every enforcement layer, design doc §1)
      start_capture block || exit 1

      # --- self-expiry: the VM owns its own unlock (independent of SSH state).
      #     Written BEFORE the swap so the unlock exists even if the swap/restart
      #     below wedges — the sleeper restores from the backup either way.
      #
      #     Mechanism: a detached sleeper (setsid => its own session, no
      #     controlling tty; ssh-spawned processes provably outlive the ssh
      #     session in this rig) sleeps out the window, then runs the unlock
      #     as root. Deliberately NOT a systemd timer/service: this guest's
      #     systemd 255 rejects KillMode=main (the parse error is logged and
      #     the value silently dropped — reproduced with systemd-analyze on
      #     the intact unit), so a one-shot service under the default
      #     control-group kill mode SIGTERMs the daemon the unlock just
      #     restarted the moment the unit completes (observed: the stack was
      #     dead for the whole verify window; the "recovered" port was
      #     fail-open, not rule-restored).
      sudo tee "$UNLOCK" >/dev/null <<'EOF'
#!/usr/bin/env bash
# FireWhal e2e S1 self-expiry — runs as root (invoked by the sleeper via
# sudo), independent of SSH. Snapshot the block-window log (the daemon
# truncates it on restart), restore the backed-up rules, restart the stack,
# wait for readiness.
set -uo pipefail
LOG=/tmp/firewhal-daemon.err
LOG_OUT=/tmp/firewhal-daemon.out
STATE=/var/lib/fw-e2e
RULES=/etc/firewhal/firewall_rules.toml
BACKUP="$STATE/fw-e2e-rules.bak"
TIMELINE="$STATE/fw-s1-timeline"
ts() { date '+%H:%M:%S'; }
echo "[$(ts)] rule-down (self-expiry): snapshotting block log; restoring config" >> "$TIMELINE"
cp "$LOG" "$STATE/s1-block-daemon.log" 2>/dev/null || true
cp "$LOG_OUT" "$STATE/s1-block-daemon.out" 2>/dev/null || true
cp "$BACKUP" "$RULES"
for name in firewhal-daemon firewhal-ipc firewhal-kernel firewhal-discor; do
    pkill -9 "$name" 2>/dev/null || true
done
sleep 2
/opt/firewhal/bin/firewhal-daemon
for i in $(seq 1 24); do
    sleep 5
    procs=$(pgrep -cf 'firewhal-(daemon|ipc|kernel)' || true)
    bpf="$(bpftool prog show 2>/dev/null || true)"
    tc=$(printf '%s\n' "$bpf" | grep -c 'sched_cls.*firewhal' || true)
    cg=$(printf '%s\n' "$bpf" | grep -c 'cgroup_sock_addr.*firewhal' || true)
    so=$(printf '%s\n' "$bpf" | grep -c 'sock_ops.*firewhal' || true)
    if [ "${procs:-0}" -ge 3 ] && [ "${tc:-0}" -ge 2 ] && [ "${cg:-0}" -ge 1 ] && [ "${so:-0}" -ge 1 ] \
        && grep -q 'C1: rules sent' "$LOG_OUT" \
        && grep -q 'C1: app ids sent' "$LOG_OUT" \
        && grep -q 'C1: interface state sent' "$LOG_OUT"; then
        echo "[$(ts)] rule-up restored; stack ready (self-expiry recovery complete)" >> "$TIMELINE"
        exit 0
    fi
done
echo "[$(ts)] FATAL: self-expiry recovery failed (stack not ready within 120s)" >> "$TIMELINE"
exit 1
EOF
      sudo chmod 755 "$UNLOCK"
      # Spawn the sleeper: detach (setsid => own session, no controlling tty,
      # so the ssh session's end cannot signal it), sleep out the window,
      # then run the unlock as root. No log redirect in the wrapper: the
      # inner shell is unprivileged and cannot create files in the root-owned
      # state dir (the redirect would EACCES and the unlock would be skipped
      # — caught in the first dry run of the /var/lib move). The unlock
      # records itself in the timeline; the daemon writes its own logs. The
      # [k] in the check pattern keeps pgrep from matching its own command
      # line.
      setsid /usr/bin/bash -c "sleep ${WINDOW}; /usr/bin/sudo /usr/bin/bash ${UNLOCK}" </dev/null >/dev/null 2>&1 &
      echo $! | sudo tee "$STATE/s1-unlock.pid" >/dev/null 2>&1 || true
      sleep 1
      if ! pgrep -f 'fw-e2e-s1-unloc[k]' >/dev/null 2>&1; then
          say "FATAL: the self-expiry sleeper did not stay alive after start"
          exit 1
      fi
      tl "self-expiry armed: VM-local sleeper restores the config in ${WINDOW}s (independent of SSH state)"

      # --- config swap: drop the incoming :22 rule (the 2223 path). The
      #     outgoing rules stay exactly as vm_deploy.sh generated them.
      sudo tee "$RULES" >/dev/null <<EOF
incoming_rules = []

[[outgoing_rules]]
action = "Allow"
protocol = "Tcp"
dest_port = 443
description = "e2e: allow probe (HTTPS)"

[[outgoing_rules]]
action = "Allow"
protocol = "Tcp"
dest_port = 80
description = "e2e: allow probe (HTTP)"

[[outgoing_rules]]
action = "Allow"
protocol = "Tcp"
dest_port = 9999
description = "e2e: data-level probe (D1; host listener on 127.0.0.1:9999)"
EOF
      if grep -q 'dest_port = 22' "$RULES"; then
          say "FATAL: the :22 rule survived the config swap"
          exit 1
      fi

      # --- restart the stack under the blocked config
      teardown_stack || exit 1
      sudo /opt/firewhal/bin/firewhal-daemon
      if ! stack_ready; then
          say "FATAL: stack not ready under the blocked config"
          sudo tail -n 40 "$LOG_OUT" 2>/dev/null || true
          sudo tail -n 40 "$LOG" 2>/dev/null || true
          exit 1
      fi
      tl "block active: incoming :22 rule dropped; stack ready under the blocked config"
      say "block active (window ${WINDOW}s); self-expiry armed; block capture running"
      ;;

  start-recover-capture)
      start_capture recover || exit 1
      say "recovery capture armed (pre-armed before the self-expiry fires)"
      ;;

  stop-capture)
      name="${2:?usage: stop-capture block|recover}"
      cap="$STATE/s1-${name}.pcap"
      sudo pkill -x tcpdump 2>/dev/null || true
      sleep 1
      if sudo pgrep -x tcpdump >/dev/null 2>&1; then
          say "FATAL: a tcpdump process survived the stop"
          exit 1
      fi
      if [ ! -s "$cap" ]; then
          say "FATAL: capture $cap missing/empty"
          sed 's/^/       | /' "$cap.err" 2>/dev/null || true
          exit 1
      fi
      say "capture stopped: $cap ($(sudo wc -c < "$cap") bytes)"
      ;;

  verify)
      # --- config restored byte-for-byte
      if diff -q "$RULES" "$BACKUP" >/dev/null 2>&1; then
          say "PASS: verify: config restored (identical to the pre-block backup)"
          PASS=$((PASS + 1))
      else
          say "FAIL: verify: config not restored"
          diff "$RULES" "$BACKUP" 2>&1 | head -n 10 | sed 's/^/       | /'
          FAIL=$((FAIL + 1))
      fi

      # --- stack ready under the restored config
      if stack_ready; then
          say "PASS: verify: stack ready (3 procs, all BPF hooks incl. both TC classifiers, 3 config pushes)"
          PASS=$((PASS + 1))
      else
          say "FAIL: verify: stack not ready"
          FAIL=$((FAIL + 1))
      fi

      # --- block verdict line. The daemon truncates its log on every start, so
      #     the block window's log lives in the snapshot the self-expiry took
      #     before its restart (fallback: the live log, if the unlock never ran).
      #     Grep the file directly — no $(cat) into a variable, no pipe (the
      #     first full gate run failed this check even though the matching line
      #     was present in the printed haystack; the direct-file form removes
      #     the substitution/pipe mechanism class entirely).
      SRC=""
      [ -s "$SNAP" ] && SRC="$SNAP"
      [ -n "$SRC" ] || SRC="$LOG"
      if [ -s "$SRC" ] && sudo grep -qE 'No ingress rule matched\. Blocking connection from 10\.0\.3\.2:[0-9]+' "$SRC"; then
          say "PASS: verify: block verdict logged (ingress :22 cut at the rule layer)"
          PASS=$((PASS + 1))
      else
          say "FAIL: verify: no ingress block verdict found in the block-window log"
          sudo tail -n 20 "$SRC" 2>/dev/null | sed 's/^/       | /'
          FAIL=$((FAIL + 1))
      fi

      # --- block wire. Direction-dependent capture semantics (pinned on the
      #     first run): the INGRESS AF_PACKET tap sits UPSTREAM of the TC ingress
      #     drop, so blocked SYNs are visible in the capture (the egress tap is
      #     downstream — D1's block leg proves it: 0 frames). The ingress oracle
      #     is therefore: the guest never replies — no frame with the ACK flag
      #     (no SYN-ACK, no data) may be present, even though the blocked SYNs
      #     are.
      cap="$STATE/s1-block.pcap"
      if [ ! -s "$cap" ]; then
          say "FAIL: verify: block capture missing (it was never stopped cleanly)"
          FAIL=$((FAIL + 1))
      else
          syns=$(sudo tshark -r "$cap" -Y 'tcp and tcp.dstport==22' 2>/dev/null | wc -l)
          n=$(sudo tshark -r "$cap" -Y 'tcp and tcp.dstport==22 and tcp.ack==1' 2>/dev/null | wc -l)
          if [ "$n" -eq 0 ]; then
              say "PASS: verify: no guest reply in the block capture (0 ACK frames for :22; ${syns} blocked SYNs visible at the tap — cut at the rule layer)"
              PASS=$((PASS + 1))
          else
              say "FAIL: verify: $n ACK frames for :22 in the block capture — the block did not hold at the wire"
              sudo tshark -r "$cap" -Y 'tcp and tcp.dstport==22 and tcp.ack==1' \
                  -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags 2>/dev/null \
                  | head -n 10 | sed 's/^/       | /'
              FAIL=$((FAIL + 1))
          fi
      fi

      # --- recovery wire: :22 traffic crossed the boundary again after the
      #     self-expiry (the path is open again — frames present)
      cap="$STATE/s1-recover.pcap"
      if [ ! -s "$cap" ]; then
          say "FAIL: verify: recovery capture missing (it was never stopped cleanly)"
          FAIL=$((FAIL + 1))
      else
          n=$(sudo tshark -r "$cap" -Y 'tcp and tcp.dstport==22' 2>/dev/null | wc -l)
          if [ "$n" -ge 1 ]; then
              say "PASS: verify: $n frames for :22 in the recovery capture (the path is open again)"
              PASS=$((PASS + 1))
          else
              say "FAIL: verify: 0 frames for :22 in the recovery capture"
              FAIL=$((FAIL + 1))
          fi
      fi

      # --- timeline: the record & reconnect (design §2.2 step 5)
      for entry in "block active" "rule-down (self-expiry)" "rule-up restored"; do
          if grep -q "$entry" "$TIMELINE"; then
              say "PASS: verify: timeline records '$entry'"
              PASS=$((PASS + 1))
          else
              say "FAIL: verify: timeline missing '$entry'"
              sed 's/^/       | /' "$TIMELINE" 2>/dev/null | head -n 20
              FAIL=$((FAIL + 1))
          fi
      done

      # --- cleanup: in the normal flow the sleeper has already fired; stop a
      #     still-pending wrapper best-effort. If only the wrapper dies, the
      #     sleep it spawned re-parents to PID 1 and the unlock still fires —
      #     the self-expiry is the fail-safe, so we do not fight it. The [k]
      #     keeps pkill from matching its own command line. The S1 state
      #     (timeline, snapshots, pcaps) stays in $STATE for inspection; the
      #     overlay is discarded on the next run anyway.
      sudo pkill -f 'fw-e2e-s1-unloc[k]' 2>/dev/null || true
      tl "verify: done — self-expiry state kept in $STATE"
      sed 's/^/[s1:timeline] /' "$TIMELINE" 2>/dev/null || true

      say "results: $PASS passed, $FAIL failed"
      [ "$FAIL" -eq 0 ]
      ;;

  *)
      say "unknown subcommand: $CMD"
      exit 2
      ;;
esac
