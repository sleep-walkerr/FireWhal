use anyhow::Context;
use aya::{
    maps::{HashMap as AyaHashMap, perf::AsyncPerfEventArray},
    include_bytes_aligned,
    programs::{CgroupAttachMode, CgroupSockAddr, Xdp, XdpFlags},
    Ebpf, // <-- CHANGED: Use Ebpf instead of Bpf
    util::online_cpus,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn, LevelFilter};
use std::{
    fs::File,
    net::Ipv4Addr,
    sync::Arc,
};
use tokio::{
    signal,
    sync::{mpsc, Mutex},
};

use firewhal_core::{
    BlockAddressRule, DebugMessage, FireWhalMessage, StatusUpdate,
};
use firewhal_kernel_common::LogRecord;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: String,
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .init();

    // --- ZMQ IPC Setup ---
    let (to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(128);
    let (from_zmq_tx, mut from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
    let zmq_handle = tokio::spawn(firewhal_core::zmq_client_connection(to_zmq_rx, from_zmq_tx.clone()));

    let ident_msg = FireWhalMessage::Status(StatusUpdate {
        component: "Firewall".to_string(),
        is_healthy: true,
        message: "Ready".to_string(),
    });
    to_zmq_tx.send(ident_msg).await?;

    // --- eBPF Setup ---
    info!("[Kernel] Loading and attaching eBPF programs...");
    let bpf = Arc::new(Mutex::new(Ebpf::load(include_bytes_aligned!(concat!( // <-- CHANGED
        env!("OUT_DIR"),
        "/firewhal-kernel"
    )))?));

    if let Err(e) = EbpfLogger::init(&mut *bpf.lock().await) { // <-- THE FIX IS HERE
        warn!("[Kernel] Failed to initialize eBPF logger: {}", e);
    }

    // --- Attach eBPF Programs ---
    {
        let mut bpf_guard = bpf.lock().await;
        let prog: &mut Xdp = bpf_guard.program_mut("firewhal_xdp").unwrap().try_into()?;
        prog.load()?;
        prog.attach(&opt.iface, XdpFlags::default())
            .context("failed to attach XDP program")?;
    }
    info!("[Kernel] Attached XDP filter program to interface {}.", opt.iface);

    {
        let cgroup_file = File::open(&opt.cgroup_path)?;
        let mut bpf_guard = bpf.lock().await;
        let prog: &mut CgroupSockAddr = bpf_guard.program_mut("firewhal_ingress_recvmsg4").unwrap().try_into()?;
        prog.load()?;
        prog.attach(&cgroup_file, CgroupAttachMode::Single)?;
    }
    info!("[Kernel] Attached cgroup ingress recvmsg4 program.");

    {
        let cgroup_file = File::open(&opt.cgroup_path)?;
        let mut bpf_guard = bpf.lock().await;
        let prog: &mut CgroupSockAddr = bpf_guard.program_mut("firewhal_egress_connect4").unwrap().try_into()?;
        prog.load()?;
        prog.attach(&cgroup_file, CgroupAttachMode::Single)?;
    }
    info!("[Kernel] Attached cgroup egress connect4 program.");

    {
        let cgroup_file = File::open(&opt.cgroup_path)?;
        let mut bpf_guard = bpf.lock().await;
        let prog: &mut CgroupSockAddr = bpf_guard.program_mut("firewhal_egress_bind4").unwrap().try_into()?;
        prog.load()?;
        prog.attach(&cgroup_file, CgroupAttachMode::Single)?;
    }
    info!("[Kernel] Attached cgroup egress bind4 program.");
    
    {
        let cgroup_file = File::open(&opt.cgroup_path)?;
        let mut bpf_guard = bpf.lock().await;
        let prog: &mut CgroupSockAddr = bpf_guard.program_mut("firewhal_egress_sendmsg4").unwrap().try_into()?;
        prog.load()?;
        prog.attach(cgroup_file, CgroupAttachMode::Single)?;
    }
    info!("[Kernel] Attached cgroup egress sendmsg4 program.");


    // --- Initial Rule Setup ---
    {
        let mut bpf_guard = bpf.lock().await;
        let icmp_map = bpf_guard.map_mut("ICMP_BLOCK_ENABLED").unwrap();
        let mut icmp_block: AyaHashMap<_, u8, u8> = AyaHashMap::try_from(icmp_map)?;
        icmp_block.insert(1, 1, 0)?;
        info!("[Kernel] [Rule] Blocking all incoming ICMP traffic via XDP.");

        let blocklist_map = bpf_guard.map_mut("BLOCKLIST").unwrap();
        let mut blocklist: AyaHashMap<_, u32, u32> = AyaHashMap::try_from(blocklist_map)?;
        let block_addr: u32 = Ipv4Addr::new(9, 9, 9, 9).into();
        blocklist.insert(block_addr, 0, 0)?;
        info!("[Kernel] [Rule] Blocking outgoing connections to 9.9.9.9");
    }

    // --- Perf Event Handling ---
    for cpu_id in online_cpus().map_err(|(msg, err)| anyhow::anyhow!("{}: {}", msg, err))? {
        let bpf_clone = Arc::clone(&bpf);
        let zmq_tx_clone = to_zmq_tx.clone();

        tokio::spawn(async move {
            // --- THE FIX STARTS HERE ---
            // 1. Lock the mutex and keep the guard for the lifetime of this task.
            let mut bpf_guard = bpf_clone.lock().await;
            
            // 2. Get the necessary map and create the perf buffer.
            //    These variables will remain valid because `bpf_guard` is never dropped.
            let logs_map = bpf_guard.map_mut("LOGS").unwrap();
            let mut perf_array = AsyncPerfEventArray::try_from(logs_map).unwrap();
            let mut buf = perf_array.open(cpu_id, None).unwrap();

            let mut buffers = vec![BytesMut::with_capacity(std::mem::size_of::<LogRecord>())];

            loop {
                // Now this is safe, because `bpf_guard` is still in scope.
                let events = match buf.read_events(&mut buffers).await {
                    Ok(e) => e,
                    Err(err) => {
                        warn!("[Kernel] Perf event error on CPU {}: {}", cpu_id, err);
                        continue;
                    }
                };

                for i in 0..events.read {
                    let buf = &buffers[i];
                    let log_record = unsafe { *(buf.as_ptr() as *const LogRecord) };

                    let message_content = log_record.message.split(|&b| b == 0).next()
                        .map(|s| String::from_utf8_lossy(s).to_string())
                        .unwrap_or_else(|| "Invalid UTF-8".to_string());

                    let ipc_msg = FireWhalMessage::Debug(DebugMessage {
                        source: "Firewall".to_string(),
                        content: format!("[eBPF/PID {}] {}", log_record.pid, message_content),
                    });

                    if zmq_tx_clone.send(ipc_msg).await.is_err() {
                        eprintln!("[Kernel] ZMQ channel closed, cannot send perf event log.");
                        return; // Exit the task
                    }
                }
            }
            // `bpf_guard` is automatically dropped here when the task finishes.
        });
    }

    info!("[Kernel] ✅ Firewall is active. Waiting for shutdown signal...");

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;

    // --- Main Event Loop ---
    loop {
        tokio::select! {
            // Handle incoming commands from TUI/Discord/etc.
            Some(message) = from_zmq_rx.recv() => {
                match message {
                    FireWhalMessage::RuleAddBlock(BlockAddressRule { address, .. }) => {
                        info!("[Kernel] Received command to block address: {}", address);
                        match address.parse::<Ipv4Addr>() {
                            Ok(ip) => {
                                let mut bpf_guard = bpf.lock().await;
                                let blocklist_map = bpf_guard.map_mut("BLOCKLIST").unwrap();
                                let mut blocklist: AyaHashMap<_, u32, u32> = AyaHashMap::try_from(blocklist_map).unwrap();
                                
                                let ip_u32: u32 = ip.into();
                                if let Err(e) = blocklist.insert(ip_u32, 1, 0) {
                                    warn!("[Kernel] Failed to update BLOCKLIST map: {}", e);
                                } else {
                                    info!("[Kernel] Successfully blocked {}", ip);
                                }
                            }
                            Err(e) => {
                                warn!("[Kernel] Could not parse IP address '{}': {}", address, e);
                            }
                        }
                    }
                    _ => { /* Ignore other message types for now. */ }
                }
            }

            // Handle shutdown signals
            _ = signal::ctrl_c() => {
                info!("[Kernel] Ctrl-C (SIGINT) received. Shutting down.");
                break;
            },
            _ = sigterm.recv() => {
                info!("[Kernel] SIGTERM received. Shutting down.");
                break;
            },
        };
    }

    // --- Shutdown ---
    info!("[Kernel] 🧹 Detaching eBPF programs and exiting...");
    drop(to_zmq_tx);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), zmq_handle).await;

    Ok(())
}