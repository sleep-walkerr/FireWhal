#!/usr/bin/env bash
# FireWhal e2e deploy — runs INSIDE the fw-test VM (invoked by run-e2e.sh).
#
# Tears down any previous stack, installs the release build, writes the test
# config (with the curl hash computed from the guest's own /usr/bin/curl, so
# nothing goes stale), starts the daemon, and waits until the stack is fully
# ready: processes up, all FireWhal BPF programs attached — including both TC
# classifiers, which the original fail-open bug failed to load — and all
# three config pushes confirmed in the daemon log.
set -euo pipefail

TARBALL=/tmp/fw-e2e-deploy.tar.gz
IFACE=enp0s3
LOG_OUT=/tmp/firewhal-daemon.out
LOG_ERR=/tmp/firewhal-daemon.err

say() { printf '[deploy] %s\n' "$*"; }

say "tearing down any previous stack"
# Match by process name (comm), not command line: a -f pattern would appear
# in the sudo wrapper's own cmdline and pkill would kill its parent.
for name in firewhal-daemon firewhal-ipc firewhal-kernel firewhal-discor; do
    sudo pkill -9 "$name" 2>/dev/null || true
done
sleep 2
if sudo pgrep 'firewhal-(daemon|ipc|kernel|discor)' >/dev/null 2>&1; then
    say "FATAL: firewhal processes survived the kill"; exit 1
fi
sudo rm -f /tmp/firewhal-daemon.out /tmp/firewhal-daemon.err

say "installing binaries to /opt/firewhal/bin"
sudo mkdir -p /opt/firewhal/bin
sudo tar xzf "$TARBALL" -C /opt/firewhal
sudo rm -f /opt/firewhal/bin/firewhal-hashing || true

say "computing sha3-256 of the guest's /usr/bin/curl (in-guest, so it cannot go stale)"
CURL_HASH=$(sudo python3 -c 'import hashlib;print(hashlib.sha3_256(open("/usr/bin/curl","rb").read()).hexdigest())')
say "curl hash: $CURL_HASH"

# The daemon loads all three tomls from /opt/firewhal/bin/ (not config/).
sudo tee /opt/firewhal/bin/app_identity.toml >/dev/null <<EOF
[apps.curl]
path = "/usr/bin/curl"
hash = "$CURL_HASH"
EOF

sudo tee /opt/firewhal/bin/interface_state.toml >/dev/null <<EOF
enforced_interfaces = [
    "$IFACE",
]
EOF

sudo tee /opt/firewhal/bin/firewall_rules.toml >/dev/null <<EOF
[[incoming_rules]]
action = "Allow"
protocol = "Tcp"
dest_port = 22
description = "e2e: SSH"

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
EOF

sudo chmod 755 /opt/firewhal/bin/*

say "starting the release daemon (daemonizes; logs -> $LOG_OUT / $LOG_ERR)"
sudo /opt/firewhal/bin/firewhal-daemon

say "waiting for readiness"
for i in $(seq 1 24); do
    sleep 5
    procs=$(sudo pgrep -cf 'firewhal-(daemon|ipc|kernel)' || true)
    bpf="$(sudo bpftool prog show 2>/dev/null || true)"
    tc=$(printf '%s\n' "$bpf" | grep -c 'sched_cls.*firewhal' || true)
    cg=$(printf '%s\n' "$bpf" | grep -c 'cgroup_sock_addr.*firewhal' || true)
    so=$(printf '%s\n' "$bpf" | grep -c 'sock_ops.*firewhal' || true)
    if [ "${procs:-0}" -ge 3 ] && [ "${tc:-0}" -ge 2 ] && [ "${cg:-0}" -ge 1 ] && [ "${so:-0}" -ge 1 ] \
        && sudo grep -q 'Rules successfully sent to firewall' "$LOG_OUT" \
        && sudo grep -q 'App IDs successfully sent to firewall' "$LOG_OUT" \
        && sudo grep -q 'Interface state successfully sent to firewall' "$LOG_OUT"; then
        say "ready after $((i * 5))s: $procs procs, ${tc} sched_cls, ${cg} cgroup_sock_addr, ${so} sock_ops; rules/apps/interfaces pushed"
        exit 0
    fi
done

say "FATAL: stack not ready within 120s"
sudo tail -n 40 "$LOG_OUT" 2>/dev/null || true
sudo tail -n 40 "$LOG_ERR" 2>/dev/null || true
exit 1
