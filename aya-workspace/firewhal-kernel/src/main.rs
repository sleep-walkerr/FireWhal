use aya::maps::RingBuf;
use firewhal_kernel_common::{BlockEvent, BlockReason};
use anyhow::Context;
use aya::{
    maps::{HashMap as AyaHashMap, perf::AsyncPerfEventArray},
    include_bytes_aligned,
    programs::{CgroupAttachMode, CgroupSockAddr, Xdp, XdpFlags},
    Ebpf, 
    util::online_cpus,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn, LevelFilter};
use std::{
    fs::File,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::{
    signal,
    sync::{mpsc, Mutex},
};

use firewhal_core::{
    BlockAddressRule, DebugMessage, FireWhalMessage, StatusUpdate, FirewallConfig, Rule
};
use firewhal_kernel_common::LogRecord;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: String,
    #[clap(short, long, default_value = "wlp5s0")]
    iface: String,
}
async fn apply_ruleset(bpf: Arc<Mutex<Ebpf>>, config: FirewallConfig) {
    let mut bpf_guard = bpf.lock().await;

    for rule in config.rules {
        if let Some(IpAddr::V4(ip)) = rule.dest_ip {
            // Use fully qualified syntax to resolve the type mismatch
            if let Some(blocklist_map_ref) = aya::Ebpf::map_mut(&mut bpf_guard, "BLOCKLIST") {
                if let Ok(mut blocklist) = AyaHashMap::<_, u32, u32>::try_from(blocklist_map_ref) {
                    let ip_u32: u32 = ip.into();

                    if matches!(rule.action, firewhal_core::Action::Deny) {
                        if let Err(e) = blocklist.insert(ip_u32, 1, 0) {
                            warn!("[Kernel] Failed to insert IP {} into BLOCKLIST: {}", ip, e);
                        } else {
                            info!("[Kernel] [Rule] Applied: Block IP {}", ip);
                        }
                    }
                } else {
                    warn!("[Kernel] Failed to get HashMap handle for 'BLOCKLIST'");
                }
            } else {
                warn!("[Kernel] Could not find eBPF map named 'BLOCKLIST'");
            }
        }
    }
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
    let bpf = Arc::new(Mutex::new(Ebpf::load(include_bytes_aligned!(concat!( 
        env!("OUT_DIR"),
        "/firewhal-kernel"
    )))?));

    if let Err(e) = EbpfLogger::init(&mut *bpf.lock().await) { 
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

    // --- Block Event Handling ---
    let bpf_clone = Arc::clone(&bpf);
    let zmq_tx_clone = to_zmq_tx.clone();

    tokio::spawn(async move {
        // We need to keep the BPF guard alive to access the map.
        let mut bpf_guard = bpf_clone.lock().await;

        // Get a handle to the EVENTS RingBuf map.
        let mut events_map = bpf_guard.map_mut("EVENTS").unwrap();
        let mut events = RingBuf::try_from(events_map).unwrap();

        info!("[Events] Started listening for block events from the kernel.");
        loop {
            // Wait for an event from the RingBuf
            if let Some(buf) = events.next() {
                // The buffer contains the raw bytes of our BlockEvent struct.
                // We read it directly from the pointer.
                let ptr = buf.as_ptr() as *const BlockEvent;
                let event = unsafe { ptr.read_unaligned() };

                // Convert the data into a human-readable format.
                let dest_ip = event.dest_addr;
                let dest_port = u16::from_be(event.dest_port);

                let content = format!(
                    "Blocked {:?} -> PID: {}, Dest: {}:{}",
                    event.reason,
                    event.pid,
                    dest_ip,
                    dest_port,
                );

                info!("[Events] {}", content);

                // Create a message and send it over ZMQ to your UI.
                // You might want to create a new `FireWhalMessage` variant for this
                // instead of using `Debug`, but this works for now.
                let ipc_msg = FireWhalMessage::Debug(DebugMessage {
                    source: "FirewallEvent".to_string(),
                    content,
                });

                if zmq_tx_clone.send(ipc_msg).await.is_err() {
                    warn!("[Events] ZMQ channel closed, cannot send block event. Exiting task.");
                    break; // Exit the loop and the task.
                }
            } else {
                // If there are no events, yield to the scheduler briefly.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    });

    info!("[Kernel] ✅ Firewall is active. Waiting for shutdown signal...");

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;

    // --- Main Event Loop ---
    loop {
        tokio::select! {
            // Handle incoming commands from TUI/Discord/etc.
            Some(message) = from_zmq_rx.recv() => {
                match message {
                    // NEW LOAD RULE PROCESSING
                    FireWhalMessage::LoadRules(config) => {
                        info!("[Kernel] Received LoadRules message: {:?}", config);
                        apply_ruleset(Arc::clone(&bpf), config).await;
                    }
                    // END LOAD RULE PROCESSING
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