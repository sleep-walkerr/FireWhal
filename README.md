To run eBPF program: RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' --
mutagen sync create --name=firewhal-dir-syncing --sync-mode=one-way-replica {directory to send} {user}@{ip or hostname}:{target directory} -i target
