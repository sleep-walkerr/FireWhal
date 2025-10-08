use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::{HashMap as AyaHashMap, RingBuf},
    programs::{CgroupAttachMode, CgroupSockAddr, Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, LevelFilter};
use std::{
    fs::File,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, atomic::{AtomicBool, Ordering}},
};
use tokio::{
    signal,
    sync::{mpsc, Mutex},
    task, time,
};

use firewhal_core::{
    zmq_client_connection, BlockAddressRule, DebugMessage, FireWhalMessage, FirewallConfig, Rule,
    StatusUpdate,
};
use firewhal_kernel_common::{BlockEvent, RuleAction, RuleKey};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: String,
    #[clap(short, long, default_value = "wlp5s0")]
    iface: String,
}

fn read_from_buffer<T: Copy>(buf: &[u8]) -> Result<T, &'static str> {
    let size = mem::size_of::<T>();
    if buf.len() < size { return Err("Buffer is smaller than the struct size"); }
    let mut data = MaybeUninit::<T>::uninit();
    let ptr = data.as_mut_ptr() as *mut u8;
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, size);
        Ok(data.assume_init())
    }
}

async fn apply_ruleset(bpf: Arc<Mutex<Ebpf>>, config: FirewallConfig) -> Result<(), anyhow::Error> {
    info!("[Kernel] [Rule] Applying ruleset...");
    let mut bpf_guard = bpf.lock().await;

    if let Ok(mut blocklist) = AyaHashMap::<_, RuleKey, RuleAction>::try_from(bpf_guard.map_mut("RULES").unwrap()) {

    for rule in config.rules {
        let dest_is_v4 = rule.dest_ip.as_ref().is_some_and(|ip| ip.is_ipv4());
        let src_is_v4 = rule.source_ip.as_ref().is_some_and(|ip| ip.is_ipv4());

        if dest_is_v4 || src_is_v4 { //This will be used to decide which map to insert the rule into in the future
            // Convert src and dst IP addresses
            let src_ip_u32: u32;
            let dst_ip_u32: u32;
            if let Some(IpAddr::V4(source_ip)) = rule.source_ip {
                src_ip_u32 = u32::from_le_bytes(source_ip.octets());
            } else { src_ip_u32 = 0; }
            if let Some(IpAddr::V4(destination_ip)) = rule.dest_ip {
                dst_ip_u32 = u32::from_le_bytes(destination_ip.octets());
            } else { dst_ip_u32 = 0; }
            

            // Create Key from Rule
            let new_key = RuleKey {
                protocol: rule.protocol as u32,
                dest_ip: dst_ip_u32, 
                dest_port: rule.dest_port.unwrap_or(0), // Wildcard port if not specified
                source_ip: src_ip_u32,
                source_port: rule.source_port.unwrap_or(0), // Wildcard port if not specified,
            };

            let action = RuleAction {
                action: firewhal_kernel_common::Action::Block,
                rule_id: 123,
            };

            if matches!(rule.action, firewhal_core::Action::Deny) {
                if let Err(e) = blocklist.insert(&new_key, &action, 0) {
                    warn!("[Kernel] Failed to insert rule: {}", e);
                } else {
                    info!("[Kernel] [Rule] Applied: Block traffic to Protocol: {}, Destination IP: {}, Destination Port: {}, Source IP: {}, Source Port: {}",
                    new_key.protocol, Ipv4Addr::from(u32::from_be(new_key.dest_ip)), new_key.dest_port, Ipv4Addr::from(u32::from_be(new_key.source_ip)), new_key.source_port);
                }
            }
        }
    }
}
    Ok(()) // Return Ok to signify success.
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::Builder::new().filter_level(LevelFilter::Info).init();
    let (to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(128);
    let (from_zmq_tx, mut from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
    let zmq_handle = tokio::spawn(firewhal_core::zmq_client_connection(to_zmq_rx, from_zmq_tx.clone()));
    to_zmq_tx.send(FireWhalMessage::Status(StatusUpdate { component: "Firewall".to_string(), is_healthy: true, message: "Ready".to_string() })).await?;
    let bpf = Arc::new(Mutex::new(Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/firewhal-kernel")))?));
    if let Err(e) = EbpfLogger::init(&mut *bpf.lock().await) { warn!("[Kernel] Failed to initialize eBPF logger: {}", e); }

    // Attach eBPF programs...
    {
        let mut bpf_guard = bpf.lock().await;
        let prog: &mut Xdp = bpf_guard.program_mut("firewhal_xdp").unwrap().try_into()?;
        prog.load()?;
        //Test Changes
        //prog.attach(&opt.iface, XdpFlags::default()).context("failed to attach XDP program")?;
        prog.attach("wlp5s0", XdpFlags::SKB_MODE).context("failed to attach XDP program")?;
        prog.attach("eth0", XdpFlags::SKB_MODE).context("failed to attach XDP program")?;
    }
    {
        let cgroup_file = File::open(&opt.cgroup_path)?;
        let mut bpf_guard = bpf.lock().await;
        let prog: &mut CgroupSockAddr = bpf_guard.program_mut("firewhal_egress_connect4").unwrap().try_into()?;
        prog.load()?;
        prog.attach(&cgroup_file, CgroupAttachMode::Single)?;
    }
    
    let bpf_clone = Arc::clone(&bpf);
// --- Block Event Handling ---
    
        // --- Block Event Handling: Final Architecture ---

    // 1. Create an internal channel to pass parsed events.
    let (event_tx, mut event_rx) = mpsc::channel::<BlockEvent>(1024); // Increased buffer
    
    let shutting_down = Arc::new(AtomicBool::new(false));


    // 2. Spawn the SENDER task (remains async).
    // This task's only job is to receive events and send them over ZMQ.
    let zmq_tx_clone_sender = to_zmq_tx.clone();
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let reason = event.reason;
            let pid = event.pid;
            let dest_ip = event.dest_addr;
            let dest_port = u16::from_be(event.dest_port);
            let content = format!("Blocked {:?} -> PID: {}, Dest: {}:{}", reason, pid, dest_ip, dest_port);
            info!("[Events] {}", content);

            let ipc_msg = FireWhalMessage::Debug(DebugMessage { source: "FirewallEvent".to_string(), content });
            if zmq_tx_clone_sender.send(ipc_msg).await.is_err() {
                warn!("[Events] ZMQ channel to router is closed, exiting sender task.");
                break;
            }
        }
    });


// 3. Spawn the READER task in a dedicated blocking thread.
    let bpf_clone_reader = Arc::clone(&bpf);
    let reader_shutdown_flag = Arc::clone(&shutting_down);


    let reader_handle = task::spawn_blocking(move || {
        info!("[Reader] Started listening for block events from the kernel.");

        // --- THIS IS THE FIX ---
        // Acquire the lock and create the RingBuf handle ONCE, before the loop.
        let mut bpf_guard = bpf_clone_reader.blocking_lock();
        let map = aya::Ebpf::map_mut(&mut bpf_guard, "EVENTS").unwrap();
        let mut events = RingBuf::try_from(map).unwrap();

        // This loop now continuously uses the SAME `events` handle.
        while !reader_shutdown_flag.load(Ordering::SeqCst) {
            // Check for a single event. The `next()` call advances the internal
            // state of the `events` handle (moves the bookmark).
            if let Some(buf) = events.next() {
                if let Ok(event) = read_from_buffer::<BlockEvent>(&buf) {
                    if event_tx.blocking_send(event).is_err() {
                        warn!("[Reader] Event channel is closed, exiting reader task.");
                        break; // Exit the loop
                    }
                }
            } else {
                // If there are no events, sleep the THREAD briefly to prevent burning CPU.
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    });

    
    // --- Main Event Loop and Shutdown logic ---
    info!("[Kernel] ✅ Firewall is active. Waiting for shutdown signal...");
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            Some(message) = from_zmq_rx.recv() => {
                match message {
                    FireWhalMessage::LoadRules(config) => {
                        if let Err(e) = apply_ruleset(Arc::clone(&bpf), config).await {
                            warn!("[Kernel] Failed to apply ruleset: {}", e);
                        }
                    }
                    _ => {}
                }
            }
            _ = signal::ctrl_c() => { info!("[Kernel] Ctrl-C received. Shutting down."); break; },
            _ = sigterm.recv() => { info!("[Kernel] SIGTERM received. Shutting down."); break; },
        };
    }
    info!("[Kernel] Shutting down tasks...");
    shutting_down.store(true, Ordering::SeqCst);

    reader_handle.await?;


    info!("[Kernel] 🧹 Detaching eBPF programs and exiting...");
    drop(to_zmq_tx);
    let _ = time::timeout(time::Duration::from_secs(2), zmq_handle).await;

    Ok(())
}