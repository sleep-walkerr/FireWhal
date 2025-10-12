use anyhow::Context;
use aya::{
    include_bytes_aligned, maps::{perf::AsyncPerfEventArrayBuffer, AsyncPerfEventArray, HashMap as AyaHashMap}, programs::{CgroupAttachMode, CgroupSockAddr, Xdp, XdpFlags}, util::online_cpus, Ebpf
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, LevelFilter};
use core::borrow;
use std::{
    fs::File,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr},
    sync::{atomic::{AtomicBool, Ordering}, Arc}, thread::yield_now, time::Duration,
};
use bytes::BytesMut;
use tokio::{
    signal,
    sync::{broadcast, mpsc, Mutex},
    task::{self}, time::{self, timeout},
};
use futures::{stream, StreamExt};
use async_stream::stream;
use std::boxed::Box;

use firewhal_core::{
    zmq_client_connection, BlockAddressRule, DebugMessage, FireWhalMessage, FirewallConfig, Rule,
    StatusUpdate, NetInterfaceRequest, NetInterfaceResponse,
};
use firewhal_kernel_common::{BlockEvent, RuleAction, RuleKey};

use pnet::datalink;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: String,
    #[clap(short, long, default_value = "wlp5s0")]
    iface: String,
}

enum BpfCommand {
    ApplyRuleset(FirewallConfig),
    AttachPrograms {
        interfaces: Vec<String>,
        cgroup_file: File,
    },
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

fn get_all_interfaces() -> Vec<String> {
    datalink::interfaces()
        .into_iter()
        .map(|iface| iface.name)
        .collect()
}

async fn attach_programs(bpf: Arc<tokio::sync::Mutex<Ebpf>>, interfaces: Vec<String>, cgroup_file: File) -> Result<(), anyhow::Error>{

    let mut bpf = bpf.lock().await;
    // XDP 
    info!("[Kernel] Applying XDP programs to interfaces {}...", interfaces.join(","));
    let xdp_program: &mut Xdp = bpf.program_mut("firewhal_xdp").unwrap().try_into().unwrap();
    xdp_program.load().unwrap();

    for interface in interfaces {
        xdp_program.attach(&interface, XdpFlags::SKB_MODE).unwrap();
    }
    info!("[Kernel] XDP programs applied.");


    // CGROUP
    info!("[Kernel] Applying CGROUP programs...");
    let egress_connect4_program: &mut CgroupSockAddr = bpf.program_mut("firewhal_egress_connect4").unwrap().try_into().unwrap();
    egress_connect4_program.load().unwrap();
    _ = egress_connect4_program.attach(&cgroup_file, CgroupAttachMode::Single);
    info!("[Kernel] CGROUP programs applied.");

    Ok(())
}

async fn apply_ruleset(bpf: Arc<tokio::sync::Mutex<Ebpf>>, config: FirewallConfig) -> Result<(), anyhow::Error> {
    let mut bpf = bpf.lock().await;
    info!("[Kernel] [Rule] Applying ruleset...");

    if let Ok(mut blocklist) = AyaHashMap::<_, RuleKey, RuleAction>::try_from(bpf.map_mut("RULES").unwrap()) {

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
    let (mut to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(128);
    let (from_zmq_tx, mut from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let zmq_handle = tokio::spawn(firewhal_core::zmq_client_connection(to_zmq_rx, from_zmq_tx.clone(), shutdown_rx));
    to_zmq_tx.send(FireWhalMessage::Status(StatusUpdate { component: "Firewall".to_string(), is_healthy: true, message: "Ready".to_string() })).await?;
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/firewhal-kernel")))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) { warn!("[Kernel] Failed to initialize eBPF logger: {}", e); }

    // 1. Load the bpf object. Make it mutable.
    if let Err(e) = EbpfLogger::init(&mut bpf) { warn!("[Kernel] Failed to initialize eBPF logger: {}", e); }

    // 2. Take ownership of the EVENTS map and move it to the event handler task.
    let events_map = bpf.take_map("EVENTS").ok_or_else(|| anyhow::anyhow!("Failed to find EVENTS map"))?;
    let zmq_tx_clone = to_zmq_tx.clone();
    tokio::spawn(async move {
        info!("[Events] Started listening for block events from the kernel.");
        let mut perf_array = AsyncPerfEventArray::try_from(events_map).unwrap();

        for cpu_id in online_cpus().unwrap() {
            let mut buf = perf_array.open(cpu_id, None).unwrap();
            let task_zmq_tx = zmq_tx_clone.clone();

            tokio::spawn(async move {
                let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();
                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for i in 0..events.read {
                        if let Ok(event) = read_from_buffer::<BlockEvent>(&buffers[i]) {
                            info!("[Kernel] Event found");
                        }
                    }
                }
            });
        }
    });

    // 3. Wrap the remaining bpf object in Arc<Mutex> to be shared for rule application.
    let bpf = Arc::new(Mutex::new(bpf));

    let cgroup_file = File::open(&opt.cgroup_path)?;
    // Fix to populate with list received from FireWhalConfig later
    let interfaces = get_all_interfaces();
    attach_programs(Arc::clone(&bpf), interfaces, cgroup_file).await;

    
    // --- Main Event Loop and Shutdown logic ---
    info!("[Kernel] ✅ Firewall is active. Waiting for shutdown signal...");
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            // Message processing
            Some(message) = from_zmq_rx.recv() => {
                match message {
                    FireWhalMessage::LoadRules(config) => {
                        apply_ruleset(Arc::clone(&bpf), config).await?;
                    },
                    FireWhalMessage::InterfaceRequest(request) => { // If the TUI requests a list of network interfaces
                        info!("[Kernel] Received interface request from TUI.");
                        let interface_list = match task::spawn_blocking(get_all_interfaces).await {
                            Ok(list) => list,
                            Err(e) => {
                                warn!("[Kernel] Failed to spawn blocking task for interfaces: {}", e);
                                vec![] // Send back an empty list on error
                            }
                        };
                        
                        let response = FireWhalMessage::InterfaceResponse(NetInterfaceResponse {
                            source: "Firewall".to_string(), // The firewall is the source of the list
                            interfaces: interface_list,
                        });
                        
                        if let Err(e) = to_zmq_tx.send(response).await {
                            warn!("[Kernel] Failed to send interface list: {}", e);
                        }
                    },
                    FireWhalMessage::UpdateInterfaces(update) => {
                        // if update.source == "TUI" {
                            info!("[Kernel] Received interface update from TUI {:?}.", update.interfaces);
                            let cgroup_file = File::open(&opt.cgroup_path)?;
                            attach_programs(Arc::clone(&bpf), update.interfaces, cgroup_file).await;
                        //}
                    },
                    _ => {}
                }
            }
            _ = signal::ctrl_c() => { info!("[Kernel] Ctrl-C received. Shutting down."); break; },
            _ = sigterm.recv() => { info!("[Kernel] SIGTERM received. Shutting down."); break; },
        };
    }
    info!("[Kernel] Shutting down tasks...");
    //shutting_down.store(true, Ordering::SeqCst);

    //reader_handle.await?;


    info!("[Kernel] 🧹 Detaching eBPF programs and exiting...");
    shutdown_tx.send(()).unwrap();
    let _ = time::timeout(time::Duration::from_secs(2), zmq_handle).await;

    Ok(())
}