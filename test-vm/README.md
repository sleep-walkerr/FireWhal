# FireWhal Test VM Rig (`fw-test`)

A disposable raw-qemu KVM VM for running FireWhal under test. All eBPF
loading and firewall enforcement happens **here** — never on the host.

Layout (images are local-only, git-ignored; everything in this directory that
is small and textual is committed):

```
fw-vm            manager script (this repo's copy is canonical)
seedroot/        NoCloud cloud-init seed (meta-data + user-data)
seed.iso         built from seedroot/ (local)
noble.img        pristine Ubuntu 24.04 cloud base, resized (local, ~11.5G)
golden.qcow2     golden disk = provisioned state (local, ~11.5G virtual)
run.qcow2        throwaway write-overlay over golden (local; recreated each reset)
fw-test.pid / fw-test-serial.log / *.sock / console*.py   local runtime artifacts
```

## Prerequisites (host)

- `qemu-system-x86_64` with `/dev/kvm` access (run as a normal user; no root)
- `ssh-keygen` key at `~/.ssh/id_ed25519_fwvm` (the one referenced by `fw-vm ssh`)
- `xorriso` to build the seed ISO
- Rust: `stable` (host build) + the dated `nightly` toolchain pinned in
  `firewhal-kernel/build.rs` (the eBPF crate is built with
  `cargo <pinned nightly> -Z build-std=core`) + **`bpf-linker`** on PATH
  (aya's BPF object linker, found via `which bpf-linker`)

### Toolchain gotchas (learned on the 2026-09-26 rebuild)

1. **bpf-linker must match the system LLVM *and* be built with the matching
   `llvm-NN` feature.** The eBPF build emits LLVM bitcode whose major version
   must be readable by bpf-linker's linked libLLVM. On the 2026-09-26 host
   (CachyOS, libLLVM 22), the stock repo bpf-linker (built without the
   `llvm-22` feature) treated LLVM-22's benign "libcalls" diagnostics as fatal
   and a too-new nightly emitted LLVM-23 bitcode the linker cannot parse.
   Working combination there:
   ```
   cargo install bpf-linker --version 0.11.1 --no-default-features \
     --features llvm-22 --root $HOME/.local     # -> ~/.local/bin/bpf-linker
   ```
2. **The eBPF toolchain is pinned in-repo** (`firewhal-kernel/build.rs` uses
   `aya_build::Toolchain::Custom("nightly-2026-07-15")`). The dated nightly
   must simply be *installed* on the build host:
   ```
   rustup toolchain install nightly-2026-07-15 --component rust-src
   ```
   (The pin is a date because the nightly's emitted LLVM bitcode version must
   be readable by bpf-linker's libLLVM — see gotcha 1. Before this pin, the
   workaround was symlinking `~/.rustup/.../nightly-*` over the `nightly`
   name; that hack is no longer needed.)
3. **When the distro ships a newer LLVM (e.g. 23 on rolling-release):**
   `sudo pacman -Suu` → rebuild bpf-linker with the matching feature
   (default `llvm-23`) → update the pin in `build.rs` to a dated nightly
   whose bitcode the new libLLVM parses → re-run the e2e gate. As of
   2026-09-26 the working pair on this host is LLVM 22 +
   `nightly-2026-07-15` (newer nightlies emit LLVM-23 bitcode).

## Building the rig from scratch

1. Download the Ubuntu 24.04 (noble) cloud image → `noble.img`. The cloud
   image's content is qcow2 (qemu detects by content; the name doesn't matter).
   Then resize it to ~11.5G *before* first boot:
   ```
   qemu-img resize noble.img +8G
   ```
   The stock image is ~3.5G; provisioning (apt + rustup) needs the headroom or
   the guest fails with "No space left on device". The guest grows its root
   partition automatically on first boot.
2. Build the seed ISO from the committed seed:
   ```
   xorriso -as mkisofs -V cidata -o seed.iso seedroot
   ```
3. First boot: `fw-vm reset && fw-vm boot`. The seed's `user-data`
   provisions the guest (toolchain, sudoers for `ubuntu`, the `firewhal-admin`
   group, `/opt/firewhal`, netplan for the test NIC). Watch
   `fw-test-serial.log` for `=== PROVISION_DONE ===` in `/var/log/provision.log`.
4. Once provisioned, stop the VM and promote the overlay to the golden image.
   Do **not** convert directly onto `golden.qcow2` — the overlay's backing file
   *is* `golden.qcow2`, so qemu refuses with "Failed to get write lock":
   ```
   qemu-img convert -f qcow2 -O qcow2 run.qcow2 golden-new.qcow2
   mv golden-new.qcow2 golden.qcow2
   ```
   (The existing `golden.qcow2` in the rig directory was produced this way;
   keep it as the pristine provisioned state — never modify it in place.)
5. From then on every run is: `fw-vm reset && fw-vm boot` → fresh overlay,
   same provisioned state, zero drift between runs.

## Usage

```
fw-vm reset          # recreate the throwaway overlay (VM must be stopped)
fw-vm boot           # boot (mgmt NIC gets SSH via hostfwd 127.0.0.1:2222)
fw-vm ssh [cmd...]   # ssh ubuntu@127.0.0.1:2222 (key ~/.ssh/id_ed25519_fwvm; passwordless sudo)
fw-vm stop           # stop
```

## Networking inside the VM

- `enp0s2` (MAC `52:54:00:12:34:56`) — slirp mgmt NIC, hostfwd `2222→22`.
  Always up. **Not** the interface under test.
- `enp0s3` (MAC `52:54:00:12:34:57`) — isolated slirp test NIC. The interface
  FireWhal guards in tests. It has no reachable peers: enforcement outcomes
  are asserted from the kernel's verdict log lines, not from traffic (see
  `tests/e2e/README.md`).

## Seed `user-data` gotchas (cloud-init 26.1)

- `runcmd` items are plain scalars — no `: ` (colon+space) anywhere in the
  line, even inside shell strings. Put file contents in `write_files`.
- `chpasswd.raw` is no longer supported; set passwords via
  `echo "user:pass" | chpasswd` in runcmd or `users[].password`.
- Do not use `#pre` (breaks multipart parsing → the whole user-data is rejected).
- A leading `#config` netplan section triggers a (harmless) schema warning.
- A new `instance-id` in `meta-data` forces all once-per-instance modules +
  runcmd to re-run.
- SSH host keys rotate on instance-id change; `fw-vm ssh` already ignores
  known_hosts.
