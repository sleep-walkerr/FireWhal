#!/bin/bash
# FireWhal golden-image rebuild — strict, verified.
#
# Builds a fresh seed ISO (with a UNIQUE instance-id so cloud-init always
# treats it as a clean seed), boots a throwaway overlay over the pristine
# noble base, waits for FULL provisioning, verifies the result, and ONLY
# then promotes the overlay to golden.qcow2.
#
# It refuses to promote if anything is off:
#   * not all provisioning markers are present
#   * rustup / tcpdump / tshark are not actually installed
#   * the promoted image is implausibly small (< 2.5 GiB)
# On any failure the VM is left running and the overlay kept for inspection.
#
# Usage:
#   test-vm/rebuild-golden.sh            # build + verify + promote
#   FW_VM_DIR=/path test-vm/rebuild-golden.sh
#
# This is the manual runbook step in README.md ("Building the rig from
# scratch", step 4). The e2e gate does NOT call this — it boots from the
# already-promoted golden.

set -uo pipefail
RIG="${FW_VM_DIR:-/home/torch/fw-vm}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEEDSRC="$REPO/test-vm/seedroot"
SERIAL="$RIG/fw-rebuild-serial.log"
PIDF="$RIG/fw-rebuild.pid"
RUN="$RIG/rebuild.qcow2"
GOLDEN="$RIG/golden.qcow2"
Noble="$RIG/noble.img"

# Minimum plausible size of a fully-provisioned golden (base + apt + rustup).
MIN_GOLDEN_BYTES=$((2500 * 1024 * 1024))

say() { printf '[rebuild] %s\n' "$*"; }
fail() {
    say "FATAL: $*"
    say "leaving the VM + overlay in place for inspection (pidfile $PIDF, overlay $RUN)"
    exit 1
}

# ---- 0. preconditions -----------------------------------------------------
[ -x "$RIG/fw-vm" ] || fail "fw-vm not found in $RIG"
[ -f "$Noble" ]     || fail "pristine base $Noble missing"
[ -f "$SEEDSRC/user-data" ] || fail "seed source missing at $SEEDSRC"
command -v xorriso >/dev/null || fail "xorriso not on PATH"
command -v qemu-img >/dev/null || fail "qemu-img not on PATH"

# rig must be idle (no fw-test, no leftover rebuild)
if [ -f "$RIG/fw-test.pid" ] && kill -0 "$(cat "$RIG/fw-test.pid")" 2>/dev/null; then
    fail "fw-test VM is running — stop it first (fw-vm stop)"
fi
if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
    fail "a rebuild VM is already running (pid $(cat "$PIDF"))"
fi

# ---- 1. build a seed ISO with a UNIQUE instance-id ------------------------
# A unique instance-id forces cloud-init to treat every rebuild as a clean
# seed (per-instance-once modules + runcmd all re-run). The repo's seedroot is
# left untouched; we stage a copy.
STAGE="$(mktemp -d /tmp/fw-seed.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT
cp -a "$SEEDSRC"/. "$STAGE"/
INSTANCE_ID="fw-test-prov-$(date +%Y%m%d-%H%M%S)"
printf 'instance-id: %s\n' "$INSTANCE_ID" > "$STAGE/meta-data"
say "seeding with unique instance-id: $INSTANCE_ID"

say "building seed ISO from staged seed"
xorriso -as mkisofs -V cidata -o "$RIG/seed.iso" "$STAGE" >/dev/null 2>&1 \
    || fail "xorriso seed build failed"

# ---- 2. one-off provisioning boot from the pristine base ------------------
say "creating provisioning overlay over $(basename "$Noble")"
rm -f "$RUN"
qemu-img create -f qcow2 -F qcow2 -b "$Noble" "$RUN" >/dev/null \
    || fail "qemu-img create failed"
rm -f "$SERIAL"
qemu-system-x86_64 -name fw-rebuild -machine q35 -accel kvm -cpu host -m 4096 -smp 4 \
    -drive file="$RUN",if=virtio,format=qcow2 \
    -cdrom "$RIG/seed.iso" \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 \
    -device virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56 \
    -netdev user,id=n1 \
    -device virtio-net-pci,netdev=n1,mac=52:54:00:12:34:57 \
    -serial file:"$SERIAL" -daemonize -pidfile "$PIDF" \
    || fail "qemu failed to start"
say "rebuild VM started (pid $(cat "$PIDF")); provisioning takes ~12 min"

sshcmd() {
    ssh -i "$HOME/.ssh/id_ed25519_fwvm" -p 2222 -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 ubuntu@127.0.0.1 "$@" 2>/dev/null
}

# ---- 3. wait for SSH, then for FULL provisioning --------------------------
up=""
for i in $(seq 1 72); do        # up to 18 min
    sleep 15
    sshcmd true && { up=$i; break; }
done
[ -n "$up" ] || fail "no SSH within 18 min (check $SERIAL)"
say "SSH up after $((up * 15))s — waiting for full provisioning (runcmd)"

done_flag=""
for i in $(seq 1 180); do       # up to 45 min for apt + rustup (slow
                                 # connections observed: 12 min on a good
                                 # link, >24 min on a slow one)
    if sshcmd 'grep -q PROVISION_DONE /var/log/provision.log 2>/dev/null'; then
        done_flag=$i; break
    fi
    sleep 15
done
[ -n "$done_flag" ] || fail "PROVISION_DONE not seen within 45 min; last log lines: $(sshcmd 'tail -15 /var/log/provision.log' 2>/dev/null | tr '\n' ' ')"

# ---- 4. verify the provisioning actually happened -------------------------
say "verifying provisioning (markers + packages)"
missing=""
for marker in PW_OK DISK_DONE APT_OK RUST_OK FWDIR_OK NET_OK PROVISION_DONE; do
    if ! sshcmd "grep -q $marker /var/log/provision.log"; then
        missing="$missing $marker"
    fi
done
[ -z "$missing" ] || fail "missing provisioning markers:$missing"
say "all markers present"

# the packages the seed must have installed
pkgcheck() { sshcmd "command -v $1 >/dev/null && dpkg -s $1 2>/dev/null | grep -q 'Status: install ok'"; }
for pkg in tcpdump tshark curl; do
    pkgcheck "$pkg" || fail "package not properly installed: $pkg"
done
say "packages OK (tcpdump, tshark, curl)"

# rustup: the seed installs it for root (runcmd runs as root), so check via
# sudo (the seed gives ubuntu NOPASSWD sudo).
sshcmd 'command -v rustc >/dev/null || sudo -n test -x /root/.cargo/bin/rustc' \
    || fail "rustup/rustc not found after provisioning"
say "rustc OK"

# ---- 5. promote only when verified ---------------------------------------
size=$(sshcmd 'sync; du -sb / 2>/dev/null | cut -f1' 2>/dev/null)
say "stopping rebuild VM and promoting overlay to golden.qcow2"
kill "$(cat "$PIDF")" 2>/dev/null
sleep 3
rm -f "$PIDF"
rm -f "$RIG/golden-new.qcow2"
qemu-img convert -f qcow2 -O qcow2 "$RUN" "$RIG/golden-new.qcow2" \
    || { fail "qemu-img convert failed"; }

new_size=$(stat -c %s "$RIG/golden-new.qcow2")
if [ "$new_size" -lt "$MIN_GOLDEN_BYTES" ]; then
    rm -f "$RIG/golden-new.qcow2"
    fail "promoted image is only $new_size bytes (< $MIN_GOLDEN_BYTES); refusing to replace the existing golden"
fi
say "promoted image is $new_size bytes (sane)"
mv "$RIG/golden-new.qcow2" "$GOLDEN"
rm -f "$RUN"
say "golden promoted"

# ---- 6. sanity boot from the NEW golden ----------------------------------
say "sanity boot from the new golden"
"$RIG/fw-vm" reset >/dev/null || fail "fw-vm reset failed"
"$RIG/fw-vm" boot >/dev/null || fail "fw-vm boot failed"
up=""
for i in $(seq 1 36); do        # up to 3 min
    sleep 5
    sshcmd true && { up=$i; break; }
done
[ -n "$up" ] || fail "sanity boot did not reach SSH (check $RIG/fw-test-serial.log)"
say "sanity boot up after $((up * 5))s"
sshcmd 'command -v tcpdump >/dev/null && tshark -v 2>&1 | head -1' >/dev/null 2>&1 \
    || fail "tcpdump/tshark missing from the new golden"
say "SANITY OK: tcpdump + tshark present in the new golden"
say "GOLDEN REBUILD COMPLETE — VM left running for the e2e gate"
