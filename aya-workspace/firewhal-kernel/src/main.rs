use aya::{
    include_bytes_aligned, maps::{perf::AsyncPerfEventArrayBuffer, AsyncPerfEventArray, HashMap as AyaHashMap}, programs::{tc::SchedClassifierLinkId, xdp::{XdpLink, XdpLinkId}, CgroupAttachMode, CgroupSockAddr, SchedClassifier, TcAttachType, Xdp, XdpFlags}, util::online_cpus, Ebpf
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, LevelFilter};
use core::borrow;
use std::{
    collections::{HashMap, HashSet}, fmt::format, fs::File, hash::Hash, mem::{self, MaybeUninit}, net::{IpAddr, Ipv4Addr}, sync::{atomic::{AtomicBool, Ordering}, Arc}, thread::yield_now, time::Duration
};
use bytes::BytesMut;
use tokio::{
    signal,
    sync::{broadcast, mpsc, Mutex},
    task::{self}, time::{self, timeout},
};

use firewhal_core::{
    BlockAddressRule, DebugMessage, FireWhalMessage, FirewallConfig, NetInterfaceRequest, NetInterfaceResponse, Rule, StatusPong, StatusUpdate, DiscordBlockNotification
};
use firewhal_kernel_common::{BlockEvent, EventType, KernelEvent, RuleAction, RuleKey};

use pnet::{datalink, packet::ip::IpNextHeaderProtocols::Fire};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: String,
    #[clap(short, long, default_value = "wlp5s0")]
    iface: String,
}

pub struct ActiveXdpInterfaces {
    active_links: HashMap<String, XdpLinkId>
}

pub struct ActiveTcInterfaces {
    active_links: HashMap<String, (SchedClassifierLinkId, SchedClassifierLinkId)> // (Ingress, Egress)
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

async fn attach_tc_programs(
    bpf_arc: Arc<tokio::sync::Mutex<Ebpf>>,
    updated_interfaces: Vec<String>,
    active_tc_interfaces: Arc<Mutex<ActiveTcInterfaces>>,
) -> Result<(), anyhow::Error> {
    let mut bpf = bpf_arc.lock().await;
    let mut active_tc = active_tc_interfaces.lock().await;
    let new_interfaces_set: HashSet<String> = updated_interfaces.into_iter().collect();

    info!("[Kernel] Applying TC programs to interfaces: {}", new_interfaces_set.iter().cloned().collect::<Vec<_>>().join(", "));

    // Detach from interfaces that are no longer in the list
    let to_detach: Vec<String> = active_tc.active_links.keys()
        .filter(|&iface_name| !new_interfaces_set.contains(iface_name))
        .cloned()
        .collect();

    for iface in to_detach {
        if let Some((ingress_id, egress_id)) = active_tc.active_links.remove(&iface) {
            info!("[Kernel] Detaching TC programs from '{}'...", iface);
            {
                let prog_ingress: &mut SchedClassifier = bpf.program_mut("firewall_ingress_tc").unwrap().try_into()?;
                if let Err(e) = prog_ingress.detach(ingress_id) {
                    warn!("[Kernel] Failed to detach TC ingress from '{}': {}", iface, e);
                }
            }
            {
                let prog_egress: &mut SchedClassifier = bpf.program_mut("firewall_egress_tc").unwrap().try_into()?;
                if let Err(e) = prog_egress.detach(egress_id) {
                    warn!("[Kernel] Failed to detach TC egress from '{}': {}", iface, e);
                }
            }
        }
    }

    // Load programs once before the loop, scoping the mutable borrows.
    {
        let prog_ingress: &mut SchedClassifier = bpf.program_mut("firewall_ingress_tc").unwrap().try_into()?;
        prog_ingress.load();
    }
    {
        let prog_egress: &mut SchedClassifier = bpf.program_mut("firewall_egress_tc").unwrap().try_into()?;
        prog_egress.load();
    }

    // Attach to new interfaces
    for iface in new_interfaces_set.iter() {
        if active_tc.active_links.contains_key(iface) {
            continue; // Already attached, skip
        }
        let mut ingress_id: Option<SchedClassifierLinkId> = None;
        let mut egress_id: Option<SchedClassifierLinkId> = None;
        info!("[Kernel] Attaching TC programs to '{}'...", iface);
        {
            let ingress_prog: &mut SchedClassifier = bpf.program_mut("firewall_ingress_tc").unwrap().try_into().unwrap();
            if let Ok(ingress_identifier) = ingress_prog.attach(&iface, TcAttachType::Ingress) {
                ingress_id = Some(ingress_identifier);
            } else {
                warn!("[Kernel] Failed to attach TC ingress to '{}'", iface)
            }
        }

        {
            let egress_prog: &mut SchedClassifier = bpf.program_mut("firewall_egress_tc").unwrap().try_into().unwrap();
            if let Ok(egress_identifier) = egress_prog.attach(&iface, TcAttachType::Egress) {
                egress_id = Some(egress_identifier);
            } else {
                warn!("[Kernel] Failed to attach TC ingress to '{}'", iface)
            }
        }
        if let Some(ingress_id) = ingress_id{
            if let Some(egress_id) = egress_id {
                active_tc.active_links.insert(iface.clone(), (ingress_id, egress_id));
            } else {
                warn!("[Kernel] Failed to get attach ID for either ingress or egress '{}'", iface);
            }
        }
        
    }

    info!("[Kernel] TC programs applied.");
    Ok(())
}

async fn attach_xdp_programs(bpf: Arc<tokio::sync::Mutex<Ebpf>>, updated_interfaces: Vec<String>, active_xdp_programs: Arc<Mutex<ActiveXdpInterfaces>>) -> Result<(), anyhow::Error>{ // This should be renamed to represent TC program attachment
    let mut bpf = bpf.lock().await;
    let mut active_xdp_programs = active_xdp_programs.lock().await;

    // XDP 
    info!("[Kernel] Applying XDP programs to interfaces {}...", updated_interfaces.join(","));
    let xdp_program: &mut Xdp = bpf.program_mut("firewhal_xdp").unwrap().try_into().unwrap();
    let _ = xdp_program.load();

    //Iterate
    let new_set: HashSet<&String> = updated_interfaces.iter().collect();

    let interfaces_to_remove: Vec<String> = active_xdp_programs.active_links.keys().filter(|&iface_name| !updated_interfaces.contains(iface_name)).cloned().collect();
    
    // Now, iterate through that list, remove each from the map, and detach.
    info!("Interfaces to Remove: {:?}", interfaces_to_remove);
    for iface in interfaces_to_remove {
        // .remove() gives us ownership of the XdpLinkId.
        if let Some(link_id) = active_xdp_programs.active_links.remove(&iface) {
            info!("[Kernel] Detaching XDP from '{}'...", iface);
            if let Err(e) = xdp_program.detach(link_id) {
                warn!("[Kernel] Failed to detach from '{}': {}", iface, e);
            }
        }
    }

    // --- 2. Attach to new interfaces that were not previously active ---
    for iface in updated_interfaces {
        // If our map of active links DOES NOT already contain this interface, attach it.
        if !active_xdp_programs.active_links.contains_key(&iface) {
            info!("[Kernel] Attaching XDP to '{}'...", iface);
            match xdp_program.attach(&iface, XdpFlags::default()) {
                Ok(link_id) => {
                    // Success! Save the new link_id in our map.
                    active_xdp_programs.active_links.insert(iface.clone(), link_id);
                }
                Err(e) => {
                    warn!("[Kernel] Failed to attach to '{}': {}", iface, e);
                }
            }
        }
    }
    info!("[Kernel] XDP programs applied.");
    Ok(())
}

async fn attach_cgroup_programs(bpf: Arc<tokio::sync::Mutex<Ebpf>>, cgroup_file: File) -> Result<(), anyhow::Error>{
    let mut bpf = bpf.lock().await;
    // CGROUP
    info!("[Kernel] Applying CGROUP programs...");
    // INGRESS PROGRAMS
    //
    // let ingress_recvmsg4_program: &mut CgroupSockAddr = bpf.program_mut("firewhal_ingress_recvmsg4").unwrap().try_into().unwrap();
    // ingress_recvmsg4_program.load();
    // _ = ingress_recvmsg4_program.attach(&cgroup_file, CgroupAttachMode::Single);
    // EGRESS PROGRAMS
    //
    let egress_connect4_program: &mut CgroupSockAddr = bpf.program_mut("firewhal_egress_connect4").unwrap().try_into().unwrap();
    let _ = egress_connect4_program.load();
    _ = egress_connect4_program.attach(&cgroup_file, CgroupAttachMode::Single);
    //
    let firewhal_egress_sendmsg4_program: &mut CgroupSockAddr = bpf.program_mut("firewhal_egress_sendmsg4").unwrap().try_into().unwrap();
    let _ = firewhal_egress_sendmsg4_program.load();
    _ = firewhal_egress_sendmsg4_program.attach(&cgroup_file, CgroupAttachMode::Single);
    //
    let firewhal_egress_bind4_program: &mut CgroupSockAddr = bpf.program_mut("firewhal_egress_bind4").unwrap().try_into().unwrap();
    let _ = firewhal_egress_bind4_program.load();
    _ = firewhal_egress_bind4_program.attach(&cgroup_file, CgroupAttachMode::Single);
    
    info!("[Kernel] CGROUP programs applied.");

    Ok(())
}

async fn apply_ruleset(bpf: Arc<tokio::sync::Mutex<Ebpf>>, config: FirewallConfig) -> Result<(), anyhow::Error> {
    let mut bpf = bpf.lock().await;
    info!("[Kernel] [Rule] Applying ruleset...");

    if let Ok(mut rulelist) = AyaHashMap::<_, RuleKey, RuleAction>::try_from(bpf.map_mut("RULES").unwrap()) {

    for rule in config.rules {
            // Create Key from Rule
            let mut new_key = RuleKey {
                protocol: rule.protocol.unwrap_or(firewhal_core::Protocol::Wildcard) as u32,
                dest_ip: 0, // Set placeholder IPs for now
                dest_port: rule.dest_port.unwrap_or(0), // Wildcard port if not specified
                source_ip: 0, // Set placeholder IPs for now
                source_port: rule.source_port.unwrap_or(0), // Wildcard port if not specified,
            };

            
            // Allow/Block matching to build RuleAction
            let action: firewhal_kernel_common::RuleAction;
            match(rule.action) {
                firewhal_core::Action::Allow => {
                    action = firewhal_kernel_common::RuleAction {
                        action: firewhal_kernel_common::Action::Allow,
                        rule_id: 127 // Placeholder value for now
                    };
                }
                firewhal_core::Action::Deny => {
                    action = firewhal_kernel_common::RuleAction {
                        action: firewhal_kernel_common::Action::Deny,
                        rule_id: 127 // Placeholder value for now
                    };
                }
            }

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
            // Add them to the key
            new_key.source_ip = src_ip_u32;
            new_key.dest_ip = dst_ip_u32;
        } else {} // IPv6 Logic

        // Insertion of completed key
        if let Err(e) = rulelist.insert(&new_key, action, 0) {
            warn!("[Kernel] Failed to insert rule: {}", e);
        } else {
            info!("[Kernel] [Rule] Applied: {:?} traffic to Protocol: {}, Destination IP: {}, Destination Port: {}, Source IP: {}, Source Port: {}",
            if action.action as u32 == 0 { "Allow" } else { "Deny" }, new_key.protocol, Ipv4Addr::from(u32::from_be(new_key.dest_ip)), new_key.dest_port, Ipv4Addr::from(u32::from_be(new_key.source_ip)), new_key.source_port);
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
    let zmq_handle = tokio::spawn(firewhal_core::zmq_client_connection(to_zmq_rx, from_zmq_tx.clone(), shutdown_rx, "Firewall".to_string()));
    to_zmq_tx.send(FireWhalMessage::Status(StatusUpdate { component: "Firewall".to_string(), is_healthy: true, message: "Ready".to_string() })).await?;
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/firewhal-kernel")))?;
    let active_xdp_interfaces: Arc<Mutex<ActiveXdpInterfaces>> = Arc::new(Mutex::new(ActiveXdpInterfaces { active_links: HashMap::new() }));
    let active_tc_interfaces: Arc<Mutex<ActiveTcInterfaces>> = Arc::new(Mutex::new(ActiveTcInterfaces { active_links: HashMap::new() }));

    if let Err(e) = EbpfLogger::init(&mut bpf) { warn!("[Kernel] Failed to initialize eBPF logger: {}", e); }

    // 2. Take ownership of the EVENTS map and move it to the event handler task.
    let events_map = bpf.take_map("EVENTS").ok_or_else(|| anyhow::anyhow!("Failed to find EVENTS map"))?;
    let zmq_tx_clone = to_zmq_tx.clone();

    tokio::spawn(async move {
        info!("[Events] Started listening for block events from the kernel.");
        let mut perf_array = AsyncPerfEventArray::try_from(events_map)?;

        for cpu_id in online_cpus().unwrap() {
            let mut buf = perf_array.open(cpu_id, None).unwrap();
            let task_zmq_tx = zmq_tx_clone.clone();

            tokio::spawn(async move {
                let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();
                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for i in 0..events.read {
                        if let Ok(kernel_event) = read_from_buffer::<KernelEvent>(&buffers[i]) { // modify this to accept KernelEvents, which could be a connection attempt or a block event for notifications
                            
                            let (comm_slice, comm_str) = {
                                let null_pos = kernel_event.comm.iter().position(|&c| c == 0).unwrap_or(kernel_event.comm.len());
                                let slice = &kernel_event.comm[0..null_pos];
                                (slice, String::from_utf8_lossy(slice))
                            };
                            match kernel_event.event_type {
                                EventType::ConnectionAttempt => {
                                    info!(
                                        "[Events] CONN_ATTEMPT: PID={}, TGID={}, Comm={}, Src={}:{}, Dest={}:{}, Proto={:?}",
                                        kernel_event.pid,
                                        kernel_event.tgid,
                                        comm_str,
                                        Ipv4Addr::from(kernel_event.saddr),
                                        kernel_event.sport,
                                        Ipv4Addr::from(kernel_event.daddr),
                                        kernel_event.dport,
                                        kernel_event.protocol
                                    );
                                }
                                EventType::BlockEvent => {
                                //     pub struct KernelEvent {
                                //     pub event_type: EventType, // Discriminant for userspace to know how to interpret
                                //     pub pid: u32,               // Thread ID from bpf_get_current_pid_tgid() low 32 bits
                                //     pub tgid: u32,               // Process ID from bpf_get_current_pid_tgid() high 32 bits
                                //     pub comm: [u8; 16],          // Command name from ctx.command()

                                //     // Network Tuple Info (relevant for BlockEvent and ConnectionAttempt)
                                //     // Always store in Network Byte Order (Big Endian) for consistency with maps
                                //     pub saddr: u32,              // Source IP (NBO)
                                //     pub daddr: u32,              // Destination IP (NBO)
                                //     pub sport: u16,              // Source Port (NBO)
                                //     pub dport: u16,              // Destination Port (NBO)
                                //     pub protocol: u8,            // IP Protocol number

                                //     pub reason: BlockReason,     // Specific reason for BlockEvent type
                                //     pub _padding: [u8; 19],
                                // }
                                    let formatted_event = format!(
                                        "BLOCKED: Reason={:?}, PID={}, TGID={}, Comm={}, Dest={}:{}, Proto={:?}",
                                        kernel_event.reason,
                                        kernel_event.pid,
                                        kernel_event.tgid,
                                        comm_str,
                                        Ipv4Addr::from(u32::from_be(kernel_event.daddr)),
                                        kernel_event.dport,
                                        kernel_event.protocol,
                                    );
                                    info!("[Events] {}", formatted_event);
                                    
                                    // Send event to ZMQ
                                    let debug_message = DebugMessage {
                                        source: "Firewall".to_string(),
                                        content: formatted_event.clone(),
                                    };
                                    if let Err(e) = task_zmq_tx.send(FireWhalMessage::Debug(debug_message)).await {
                                        warn!("[Events] Failed to send block event: {}", e);
                                    }

                                    let discord_block_message = DiscordBlockNotification {
                                        component: "Firewall".to_string(),
                                        content: formatted_event.clone(),
                                    };
                                    if let Err(e) = task_zmq_tx.send(FireWhalMessage::DiscordBlockNotify(discord_block_message)).await {
                                        warn!("[Events] Failed to send block event to Discord: {}", e);
                                    }
                                }
                                EventType::DebugMessage => {
                                    let debug_content_bytes = &kernel_event.comm;
                                    let debug_content_str = String::from_utf8_lossy(debug_content_bytes);
                                    info!("[Events] EBPF_DEBUG: PID={}, TGID={}, Msg={}", kernel_event.pid, kernel_event.tgid, debug_content_str);
                                }
                            }
                            // //Format event
                            // let formatted_event = format!(
                            //     "Blocked {:?} -> PID: {}, Dest: {}:{}",
                            //     event.reason,
                            //     event.pid,
                            //     event.dest_addr,
                            //     event.dest_port

                            // );
                            // Send event
                            // let debug_message = DebugMessage {
                            //     source: "Firewall".to_string(),
                            //     content: formatted_event.clone(),
                            // };
                            // if let Err(e) = task_zmq_tx.send(FireWhalMessage::Debug(debug_message)).await {
                            //     warn!("[Events] Failed to send block event: {}", e);
                            // }
                            // // Test sending event to discord bot
                            // let discord_block_message = DiscordBlockNotification {
                            //     component: "Firewall".to_string(),
                            //     content: formatted_event.clone(),
                            // };
                            // if let Err(e) = task_zmq_tx.send(FireWhalMessage::DiscordBlockNotify(discord_block_message)).await {
                            //     warn!("[Events] Failed to send block event to Discord: {}", e);
                            // }
                        }
                    }
                }
            });
        }
        Ok::<(), anyhow::Error>(())
    });

    // 3. Wrap the remaining bpf object in Arc<Mutex> to be shared for rule application.
    let bpf = Arc::new(Mutex::new(bpf));

    let cgroup_file = File::open(&opt.cgroup_path)?;
    let initial_interfaces = get_all_interfaces();
    attach_xdp_programs(Arc::clone(&bpf), initial_interfaces.clone(), active_xdp_interfaces.clone()).await?;
    attach_cgroup_programs(Arc::clone(&bpf), cgroup_file).await?;
    attach_tc_programs(Arc::clone(&bpf), initial_interfaces.clone(), active_tc_interfaces.clone()).await?;
    
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
                        let interfaces = update.interfaces;
                        attach_xdp_programs(Arc::clone(&bpf), interfaces.clone(), active_xdp_interfaces.clone()).await?;
                        attach_tc_programs(Arc::clone(&bpf), interfaces, active_tc_interfaces.clone()).await?;
                        //}
                    },
                    FireWhalMessage::Ping(ping) => {
                        if ping.source == "TUI" {
                            info!("[Kernel] Received status ping from TUI.");
                            let response = FireWhalMessage::Pong(StatusPong {
                                source: "Firewall".to_string()
                            } );
                            if let Err(e) = to_zmq_tx.send(response).await {
                                warn!("[Kernel] Failed to send status update: {}", e);
                            }
                        }
                    },
                    _ => {}
                }
            }
            _ = signal::ctrl_c() => { info!("[Kernel] Ctrl-C received. Shutting down."); break; },
            _ = sigterm.recv() => { info!("[Kernel] SIGTERM received. Shutting down."); break; },
        };
    }
    info!("[Kernel] Shutting down tasks...");
    // Send message to TUI indicating inactive status
    let pong_message = FireWhalMessage::Pong( StatusPong {
        source: "Firewall".to_string()
    });
    if let Err(e) = to_zmq_tx.send(pong_message).await {
        
    }
    //shutting_down.store(true, Ordering::SeqCst);

    //reader_handle.await?;


    info!("[Kernel] 🧹 Detaching eBPF programs and exiting...");
    shutdown_tx.send(()).unwrap();
    let _ = time::timeout(time::Duration::from_secs(2), zmq_handle).await;

    Ok(())
}