use aya::{
    Ebpf, include_bytes_aligned, maps::{Array as AyaArray, AsyncPerfEventArray, HashMap as AyaHashMap, MapData, perf::AsyncPerfEventArrayBuffer
    }, programs::{
            CgroupAttachMode, CgroupSockAddr, SchedClassifier, TcAttachType, Xdp, XdpFlags, tc::SchedClassifierLinkId, xdp::{XdpLink, XdpLinkId}, SockOps}, util::online_cpus
};
use anyhow::{bail, Context, Result};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, LevelFilter};
use core::borrow;
use std::{
    collections::{HashMap, HashSet}, 
    fmt::format, 
    fs::{self, File}, 
    hash::Hash, 
    io::{self, BufRead, BufReader, Read}, 
    mem::{self, MaybeUninit}, 
    net::{IpAddr, Ipv4Addr}, 
    path::{Path, PathBuf}, 
    process::Command as StdCommand, 
    sync::{atomic::{AtomicBool, Ordering}, Arc}, 
    thread::yield_now, 
    time::Duration,
    ffi::CString,
};

use bytes::BytesMut;
use tokio::{
    signal,
    sync::{broadcast, mpsc, Mutex},
    task::{self}, time::{self, timeout},
};

use nix;
use std::os::unix::process::CommandExt;

use firewhal_core::{
    ApplicationAllowlistConfig, 
    BlockAddressRule, 
    DebugMessage, 
    DiscordBlockNotification, 
    FireWhalConfig, 
    FireWhalMessage, 
    NetInterfaceRequest, 
    NetInterfaceResponse, 
    Rule, 
    StatusPong, 
    StatusUpdate,
    PermissiveModeEnable,
    PermissiveModeDisable,
    ProcessLineageTuple,
    ProcessInfo
};
use firewhal_kernel_common::{Action, BlockEvent, EventType, KernelEvent, PidTrustInfo, RuleAction, RuleKey, ConnectionKey};

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

// fn get_all_interfaces() -> Vec<String> {
//     datalink::interfaces()
//         .into_iter()
//         .map(|iface| iface.name)
//         .collect()
// }

// Helper function to get PPID and process name
fn get_process_info(pid: u32) -> Option<(u32, String, String)> {
    let status_path = format!("/proc/{}/status", pid);
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    let exe_path = format!("/proc/{}/exe", pid);

    let mut ppid: Option<u32> = None;
    let mut name: Option<String> = None; // Process name from /proc/<pid>/status 'Name:' field
    let mut exe_full_path: Option<String> = None; // Full executable path from /proc/<pid>/exe

    // Read /proc/<pid>/status for Name and PPid
    if let Ok(file) = fs::File::open(&status_path) {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            if line.starts_with("Name:") {
                name = line.split_whitespace().nth(1).map(String::from);
            } else if line.starts_with("PPid:") {
                ppid = line.split_whitespace().nth(1).and_then(|s| s.parse().ok());
            }
            if name.is_some() && ppid.is_some() { break; } // Found both, optimize
        }
    }

    // Read /proc/<pid>/exe for the full executable path
    if let Ok(path_buf) = fs::read_link(&exe_path) {
        exe_full_path = Some(path_buf.to_string_lossy().into_owned());
    }

    // Prioritize full executable path, otherwise use 'Name:' from status.
    // If neither, fallback to a placeholder.
    let final_name = exe_full_path.clone().unwrap_or_else(|| name.unwrap_or_else(|| format!("Unknown ({})", pid)));

    ppid.map(|p| (p, final_name, exe_full_path.unwrap_or_default().to_string())) // Return PPID, preferred_name, and full path
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
                let prog_ingress: &mut SchedClassifier = bpf.program_mut("firewhal_ingress_tc").unwrap().try_into()?;
                if let Err(e) = prog_ingress.detach(ingress_id) {
                    warn!("[Kernel] Failed to detach TC ingress from '{}': {}", iface, e);
                }
            }
            {
                let prog_egress: &mut SchedClassifier = bpf.program_mut("firewhal_egress_tc").unwrap().try_into()?;
                if let Err(e) = prog_egress.detach(egress_id) {
                    warn!("[Kernel] Failed to detach TC egress from '{}': {}", iface, e);
                }
            }
        }
    }

    // Load programs once before the loop, scoping the mutable borrows.
    {
        let prog_ingress: &mut SchedClassifier = bpf.program_mut("firewhal_ingress_tc").unwrap().try_into()?;
        prog_ingress.load();
    }
    {
        let prog_egress: &mut SchedClassifier = bpf.program_mut("firewhal_egress_tc").unwrap().try_into()?;
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
            let ingress_prog: &mut SchedClassifier = bpf.program_mut("firewhal_ingress_tc").unwrap().try_into().unwrap();
            if let Ok(ingress_identifier) = ingress_prog.attach(&iface, TcAttachType::Ingress) {
                ingress_id = Some(ingress_identifier);
            } else {
                warn!("[Kernel] Failed to attach TC ingress to '{}'", iface)
            }
        }

        {
            let egress_prog: &mut SchedClassifier = bpf.program_mut("firewhal_egress_tc").unwrap().try_into().unwrap();
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

async fn attach_cgroup_programs(bpf: Arc<tokio::sync::Mutex<Ebpf>>, cgroup_file: File) -> Result<(), anyhow::Error>{
    let mut bpf = bpf.lock().await;
    // CGROUP
    info!("[Kernel] Applying CGROUP programs...");
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

    let firewhal_sock_ops: &mut SockOps = bpf.program_mut("firewhal_sock_ops").unwrap().try_into()?;
    let _ = firewhal_sock_ops.load();
    _ = firewhal_sock_ops.attach(&cgroup_file, CgroupAttachMode::default())?;
    
    info!("[Kernel] CGROUP programs applied.");

    Ok(())
}
async fn apply_ruleset(bpf: Arc<tokio::sync::Mutex<Ebpf>>, config: FireWhalConfig) -> Result<(), anyhow::Error> {
    let mut bpf = bpf.lock().await;
    info!("[Kernel] [Rule] Applying ruleset...");

    // Process outgoing rules in a separate scope to manage borrows.
    {
        let mut rulelist = AyaHashMap::<_, RuleKey, RuleAction>::try_from(bpf.map_mut("RULES").unwrap())?;
        let mut new_rule_keys = HashSet::<RuleKey>::new();

        info!("[Kernel] [Rule] Upserting new/updated outgoing rules...");
        for rule in config.outgoing_rules {
            let mut new_key = RuleKey {
                protocol: rule.protocol.unwrap_or(firewhal_core::Protocol::Wildcard) as u32,
                dest_ip: 0,
                dest_port: rule.dest_port.unwrap_or(0),
                source_ip: 0,
                source_port: rule.source_port.unwrap_or(0),
            };

            let action = match rule.action {
                firewhal_core::Action::Allow => firewhal_kernel_common::RuleAction {
                    action: firewhal_kernel_common::Action::Allow,
                    rule_id: 127,
                },
                firewhal_core::Action::Deny => firewhal_kernel_common::RuleAction {
                    action: firewhal_kernel_common::Action::Deny,
                    rule_id: 127,
                },
            };

            if let Some(IpAddr::V4(source_ip)) = rule.source_ip {
                new_key.source_ip = u32::from_be_bytes(source_ip.octets());
            }
            if let Some(IpAddr::V4(destination_ip)) = rule.dest_ip {
                new_key.dest_ip = u32::from_be_bytes(destination_ip.octets());
            }

            new_rule_keys.insert(new_key);

            if let Err(e) = rulelist.insert(&new_key, action, 0) {
                warn!("[Kernel] Failed to insert outgoing rule: {}", e);
            } else {
                info!("[Kernel] [Rule] Applied Outgoing: {:?} traffic to Protocol: {}, Destination IP: {}, Destination Port: {}, Source IP: {}, Source Port: {}",
                action.action, new_key.protocol, Ipv4Addr::from(u32::from_be(new_key.dest_ip)), new_key.dest_port, Ipv4Addr::from(u32::from_be(new_key.source_ip)), new_key.source_port);
            }
        }

        info!("[Kernel] [Rule] Pruning stale outgoing rules...");
        let mut stale_keys = Vec::new();
        for previous_rule_result in rulelist.iter() {
            if let Ok((key, _)) = previous_rule_result {
                if !new_rule_keys.contains(&key) {
                    stale_keys.push(key);
                }
            }
        }

        info!("[Kernel] [Rule] Found {} stale outgoing rules to remove.", stale_keys.len());
        for key in stale_keys {
            if let Err(e) = rulelist.remove(&key) {
                warn!("[Kernel] Failed to remove stale outgoing rule: {}", e);
            }
        }
    } // `rulelist` and its mutable borrow of `bpf` are dropped here.

    // Process incoming rules in a new scope.
    {
        let mut incoming_rulelist = AyaHashMap::<_, RuleKey, RuleAction>::try_from(bpf.map_mut("INCOMING_RULES").unwrap())?;
        let mut new_incoming_rule_keys = HashSet::<RuleKey>::new();

        info!("[Kernel] [Rule] Upserting new/updated incoming rules...");
        for rule in config.incoming_rules {
            let mut new_key = RuleKey {
                protocol: rule.protocol.unwrap_or(firewhal_core::Protocol::Wildcard) as u32,
                dest_ip: 0,
                dest_port: rule.dest_port.unwrap_or(0),
                source_ip: 0,
                source_port: rule.source_port.unwrap_or(0),
            };

            let action = match rule.action {
                firewhal_core::Action::Allow => firewhal_kernel_common::RuleAction {
                    action: firewhal_kernel_common::Action::Allow,
                    rule_id: 127,
                },
                firewhal_core::Action::Deny => firewhal_kernel_common::RuleAction {
                    action: firewhal_kernel_common::Action::Deny,
                    rule_id: 127,
                },
            };

            if let Some(IpAddr::V4(source_ip)) = rule.source_ip {
                new_key.source_ip = u32::from_be_bytes(source_ip.octets());
            }
            if let Some(IpAddr::V4(destination_ip)) = rule.dest_ip {
                new_key.dest_ip = u32::from_be_bytes(destination_ip.octets());
            }

            new_incoming_rule_keys.insert(new_key);

            if let Err(e) = incoming_rulelist.insert(&new_key, action, 0) {
                warn!("[Kernel] Failed to insert incoming rule: {}", e);
            } else {
                info!("[Kernel] [Rule] Applied Incoming: {:?} traffic to Protocol: {}, Destination IP: {}, Destination Port: {}, Source IP: {}, Source Port: {}",
                action.action, new_key.protocol, Ipv4Addr::from(u32::from_be(new_key.dest_ip)), new_key.dest_port, Ipv4Addr::from(u32::from_be(new_key.source_ip)), new_key.source_port);
            }
        }

        info!("[Kernel] [Rule] Pruning stale incoming rules..."); 
        let mut stale_incoming_keys = Vec::new();
        for previous_rule_result in incoming_rulelist.iter() {
            if let Ok((key, _)) = previous_rule_result {
                if !new_incoming_rule_keys.contains(&key) {
                    stale_incoming_keys.push(key);
                }
            }
        }

        info!("[Kernel] [Rule] Found {} stale incoming rules to remove.", stale_incoming_keys.len());
        for key in stale_incoming_keys {
            if let Err(e) = incoming_rulelist.remove(&key) {
                warn!("[Kernel] Failed to remove stale incoming rule: {}", e);
            }
        }
    }

    info!("[Kernel] [Rule] Ruleset successfully applied.");
    Ok(())
}

// Function to load app identities
async fn load_app_ids(
    app_ids_arc: Arc<Mutex<HashMap<PathBuf, String>>>,
    cache_arc: Arc<Mutex<HashMap<u32, ProcessInfo>>>, // The userspace cache
    trusted_pids_arc: Arc<Mutex<AyaHashMap<MapData, u32, PidTrustInfo>>>, // The kernel map
    config: ApplicationAllowlistConfig,
) -> Result<(), anyhow::Error> {
    
    // --- 1. Build the new allowlist in memory ---
    let mut new_app_ids = HashMap::<PathBuf, String>::new();
    for (app_id_key, app_identity) in config.apps {
        info!("[Kernel] Loading new app identity for app_id: '{}', path: {:?}", app_id_key, app_identity.path);
        new_app_ids.insert(app_identity.path, app_identity.hash);
    }

    // --- 2. Lock all the maps we need to modify ---
    let mut app_ids_guard = app_ids_arc.lock().await;
    let mut cache_guard = cache_arc.lock().await;
    let mut trusted_pids_guard = trusted_pids_arc.lock().await;

    // --- 3. Find Stale TGIDs ---
    // Iterate over our userspace cache of *active* processes
    let mut stale_tgids = Vec::new();
    for (tgid, process_info) in cache_guard.iter() {
        
        // Check if the path for this active TGID is in the *new* allowlist
        match new_app_ids.get(&process_info.path) {
            Some(new_hash) => {
                // Path is still in the list. Now check if the hash has changed.
                if *new_hash != process_info.hash {
                    // The hash has changed! This process is now stale/untrusted.
                    info!("[Kernel] Stale PID (Hash Mismatch): {}. Marking for removal.", tgid);
                    stale_tgids.push(*tgid);
                }
                // If hash matches, do nothing. The process is still trusted.
            }
            None => {
                // Path is no longer in the allowlist at all.
                info!("[Kernel] Stale PID (Path Removed): {}. Marking for removal.", tgid);
                stale_tgids.push(*tgid);
            }
        }
    }

    // --- 4. Prune Stale TGIDs from both caches ---
    for tgid in stale_tgids {
        // Remove from userspace cache
        cache_guard.remove(&tgid);
        
        // Remove from eBPF kernel map
        if let Err(e) = trusted_pids_guard.remove(&tgid) {
            warn!("[Kernel] Failed to remove stale TGID {} from TRUSTED_PIDS map: {}", tgid, e);
        }
    }

    // --- 5. Finally, update the main allowlist with the new one ---
    *app_ids_guard = new_app_ids;

    info!("[Kernel] App allowlist reloaded and stale PIDs pruned.");
    Ok(())
}

/// Calculates a file's hash by spawning a sandboxed, external process.
///
/// This function executes the `firewhal-hashing` utility, passing it a file path.
/// For security, the child process drops its privileges to the 'nobody' user
/// before it begins execution. The function captures and returns the hash from stdout.
async fn calculate_file_hash(path: PathBuf) -> Result<String> {
    // 1. Build the command using `std::process::Command` to access `pre_exec`.
    let mut hash_command = StdCommand::new("/opt/firewhal/bin/firewhal-hashing");
    hash_command.arg(path);

    // 2. Get user info for 'nobody' to drop privileges.
    let target_user = nix::unistd::User::from_name("root")
        .context("Failed to get user info for 'nobody'")?
        .context("User 'nobody' not found")?;

    // 3. Set up the privilege drop to run in the child process before `exec`.
    // This is `unsafe` because it runs after `fork` but before `exec`, a context
    // where many standard library functions are not safe to call. The `nix` calls
    // used here are designed for this purpose.
    unsafe {
        hash_command.pre_exec(move || {
            let username = CString::new("root")
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            nix::unistd::initgroups(&username, target_user.gid)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            nix::unistd::setgid(target_user.gid)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            nix::unistd::setuid(target_user.uid)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            Ok(())
        });
    }

    // 4. Convert to a Tokio command to execute asynchronously and capture output.
    let output = tokio::process::Command::from(hash_command).output()
        .await
        .context("Failed to spawn 'firewhal-hashing' command")?;

    // 5. Check the result and return the hash or an error.
    if output.status.success() {
        let line = String::from_utf8_lossy(&output.stdout);
        Ok(line.trim().to_string())
    } else {
        let error_message = String::from_utf8_lossy(&output.stderr);
        bail!("firewhal-hashing failed with status {}: {}", output.status, error_message.trim());
    }
}

async fn update_permissive_mode_flag(
    flag_array: Arc<Mutex<AyaArray<MapData, u32>>>,
    is_enabled: bool,
) -> Result<(), anyhow::Error> {
    let mut permissive_map_guard = flag_array.lock().await; // Lock the Bpf object

    let index: u32 = 0;
    let value: u32 = if is_enabled { 1 } else { 0 };

    // Set the value in the map
    permissive_map_guard.set(index, value, 0)?;

    info!("Updated eBPF execution flag to: {}", is_enabled);
    Ok(())
}

async fn get_permissive_mode_value(
    flag_array: Arc<Mutex<AyaArray<MapData, u32>>> // Have to use array here since bool maps don't exist
) -> Result<u32, anyhow::Error> {
    let mut permissive_map_guard = flag_array.lock().await; // Lock the Bpf object
    let permissive_flag = permissive_map_guard.get(&0, 0)?;

    Ok(permissive_flag)
}

async fn prune_denied_pids(
    trusted_pids_map_arc: Arc<Mutex<AyaHashMap<MapData, u32, PidTrustInfo>>>,
    active_process_cache_arc: Arc<Mutex<HashMap<u32, ProcessInfo>>>
) -> Result<(), anyhow::Error> {
    
    info!("[Kernel] Pruning all 'Deny' entries from caches...");
    
    let mut stale_tgids_kernel = Vec::new();
    let mut stale_tgids_userspace = Vec::new();

    // 1. Find stale PIDs in the kernel map
    {
        let mut trusted_pids_guard = trusted_pids_map_arc.lock().await;
        for entry in trusted_pids_guard.iter() {
            if let Ok((tgid, info)) = entry {
                if info.action == Action::Deny {
                    stale_tgids_kernel.push(tgid);
                }
            }
        }
        
        for tgid in stale_tgids_kernel {
            let _ = trusted_pids_guard.remove(&tgid);
        }
    } // Kernel map lock released

    // 2. Find stale PIDs in the userspace cache
    {
        let mut cache_guard = active_process_cache_arc.lock().await;
        for (tgid, info) in cache_guard.iter() {
            if info.action == firewhal_core::Action::Deny {
                stale_tgids_userspace.push(*tgid);
            }
        }

        for tgid in stale_tgids_userspace {
            cache_guard.remove(&tgid);
        }
    } // Userspace cache lock released
    
    info!("[Kernel] Pruning complete.");
    Ok(())
}

/// Wipes all kernel and userspace trust caches.
/// Called when permissive mode is disabled to force re-verification of all processes.
async fn on_disable_permissive_mode(
    trusted_pids_map_arc: Arc<Mutex<AyaHashMap<MapData, u32, PidTrustInfo>>>,
    trusted_connections_map_arc: Arc<Mutex<AyaHashMap<MapData, ConnectionKey, u32>>>,
    pending_connections_map_arc: Arc<Mutex<AyaHashMap<MapData, ConnectionKey, u32>>>,
    active_process_cache_arc: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
) -> Result<(), anyhow::Error> {
    
    info!("[Kernel] Permissive mode disabled. Clearing all trust caches...");

    // 1. Clear the kernel's TRUSTED_PIDS map
    // We must iterate and remove, as eBPF maps don't have a `.clear()`
    {
        let mut trusted_pids_guard = trusted_pids_map_arc.lock().await;
        
        let keys: Vec<u32> = trusted_pids_guard.iter()
            .filter_map(|result| result.ok())
            .map(|(key, _value)| key)
            .collect();

        for key in keys {
            if let Err(e) = trusted_pids_guard.remove(&key) {
                warn!("[Kernel] Failed to remove PID {} from TRUSTED_PIDS map: {}", key, e);
            }
        }
        info!("[Kernel] TRUSTED_PIDS map cleared.");
    }

    // 2. Clear the kernel's TRUSTED_CONNECTIONS_MAP
    {
        let mut trusted_connections_guard = trusted_connections_map_arc.lock().await;
        
        let keys: Vec<ConnectionKey> = trusted_connections_guard.iter()
            .filter_map(|r| r.ok())
            .map(|(k, _)| k)
            .collect();
            
        for key in keys {
            let _ = trusted_connections_guard.remove(&key); // Ignore errors
        }
        info!("[Kernel] TRUSTED_CONNECTIONS_MAP cleared.");
    }

    // 3. Clear the kernel's PENDING_CONNECTIONS_MAP
    {
        let mut pending_connections_guard = pending_connections_map_arc.lock().await;
        
        let keys: Vec<ConnectionKey> = pending_connections_guard.iter()
            .filter_map(|r| r.ok())
            .map(|(k, _)| k)
            .collect();

        for key in keys {
            let _ = pending_connections_guard.remove(&key); // Ignore errors
        }
        info!("[Kernel] PENDING_CONNECTIONS_MAP cleared.");
    }

    // 4. Clear your userspace cache (this one *does* have .clear())
    {
        let mut active_cache_guard = active_process_cache_arc.lock().await;
        active_cache_guard.clear();
        info!("[Kernel] Userspace ActiveProcessCache cleared.");
    }

    info!("[Kernel] All caches cleared. Re-verification will occur on next connection.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse(); // Remove later
    env_logger::Builder::new().filter_level(LevelFilter::Info).init();
    // ZMQ IPC channel senders and receivers
    let (mut to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(128);
    let (from_zmq_tx, mut from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
    // ZMQ shutdown signal channels, for shutting down IPC async task
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

    let zmq_handle = tokio::spawn(firewhal_core::zmq_client_connection(to_zmq_rx, from_zmq_tx.clone(), shutdown_rx, "Firewall".to_string()));
    

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/firewhal-kernel")))?;

    let active_xdp_interfaces: Arc<Mutex<ActiveXdpInterfaces>> = Arc::new(Mutex::new(ActiveXdpInterfaces { active_links: HashMap::new() }));
    let active_tc_interfaces: Arc<Mutex<ActiveTcInterfaces>> = Arc::new(Mutex::new(ActiveTcInterfaces { active_links: HashMap::new() }));

    // Hashmap that contains application paths and hashes
    let app_ids: Arc<Mutex<HashMap<PathBuf, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let app_ids_for_event_processing = Arc::clone(&app_ids);
    let app_ids_for_id_update = Arc::clone(&app_ids);

    // Create active process cache, for removal of trusted PIDs and connections when the app list changes or when permissive mode is used
    let active_process_cache: Arc<Mutex<HashMap<u32, ProcessInfo>>> = 
        Arc::new(Mutex::new(HashMap::new()));
    let active_process_cache_for_event_processing = Arc::clone(&active_process_cache);
    let active_process_cache_for_id_update = Arc::clone(&active_process_cache);
    
    

    // Initialize event logger
    if let Err(e) = EbpfLogger::init(&mut bpf) { warn!("[Kernel] Failed to initialize eBPF logger: {}", e); }

    // 2. Take ownership of the EVENTS map and move it to the event handler task.
    let events_map = bpf.take_map("EVENTS").ok_or_else(|| anyhow::anyhow!("Failed to find EVENTS map"))?;

    // Take ownership of PID map for use within async KernelEvent handling
    let trusted_pids_map_raw = bpf.take_map("TRUSTED_PIDS").ok_or_else(|| anyhow::anyhow!("Failed to find TRUSTED_PIDS map"))?;
    // Get actual map
    let trusted_pids_aya_map = AyaHashMap::<_, u32, PidTrustInfo>::try_from(trusted_pids_map_raw)?;
    // Create a sharable reference to the map
    let trusted_pids_shared = Arc::new(tokio::sync::Mutex::new(trusted_pids_aya_map));
    let trusted_pids_for_id_update = Arc::clone(&trusted_pids_shared);



    // Take ownership of PENDING AND TRUSTED CONNECTIONS MAPS
    let pending_connections_map_raw = bpf.take_map("PENDING_CONNECTIONS_MAP").ok_or_else(|| anyhow::anyhow!("Failed to find PENDING_CONNECTIONS_MAP map"))?;
    let trusted_connections_map_raw = bpf.take_map("TRUSTED_CONNECTIONS_MAP").ok_or_else(|| anyhow::anyhow!("Failed to find TRUSTED_CONNECTIONS_MAP map"))?;
    // Get actual maps
    let pending_connections_map = AyaHashMap::<_, ConnectionKey, u32>::try_from(pending_connections_map_raw)?;
    let trusted_connections_map = AyaHashMap::<_, ConnectionKey, u32>::try_from(trusted_connections_map_raw)?;
    // Create a sharable reference to the maps
    let pending_connections_shared = Arc::new(tokio::sync::Mutex::new(pending_connections_map));
    let trusted_connections_shared = Arc::new(tokio::sync::Mutex::new(trusted_connections_map));
    let trusted_connections_for_id_update = Arc::clone(&trusted_connections_shared);

    // Create a reference of pending connections for permissive and app id update
    let pending_connections_for_id_update = Arc::clone(&pending_connections_shared);



    // Get map for permissive mode
    let permissive_mode_map_raw = bpf.take_map("PERMISSIVE_MODE_ENABLED").ok_or_else(|| anyhow::anyhow!("Failed to find PERMISSIVE_MODE_ENABLED map"))?;
    // Get actual permissive mode map
    let permissive_mode_map = AyaArray::<_, u32>::try_from(permissive_mode_map_raw)?;
    // Create sharable reference
    let permissive_mode_shared: Arc<Mutex<AyaArray<MapData, u32>>> = Arc::new(tokio::sync::Mutex::new(permissive_mode_map));
    let permissive_mode_for_cpu: Arc<Mutex<AyaArray<MapData, u32>>> = Arc::clone(&permissive_mode_shared);
    let permissive_mode_for_main_loop: Arc<Mutex<AyaArray<MapData, u32>>> = Arc::clone(&permissive_mode_shared);

    let zmq_tx_clone = to_zmq_tx.clone();

    tokio::spawn(async move {
        info!("[Events] Started listening for block events from the kernel.");
        let mut perf_array = AsyncPerfEventArray::try_from(events_map)?;
        
        

        for cpu_id in online_cpus().unwrap() {
            let mut buf = perf_array.open(cpu_id, None).unwrap();
            let task_zmq_tx = zmq_tx_clone.clone();
            // Clone the Arc for each inner task
            let trusted_pids_for_task = Arc::clone(&trusted_pids_shared);
            let app_ids_for_task = Arc::clone(&app_ids);
            let pending_connections_for_task = Arc::clone(&pending_connections_shared);
            let trusted_connections_for_task = Arc::clone(&trusted_connections_shared);
            let permissive_mode_for_task = Arc::clone(&permissive_mode_for_cpu);
            let cache_for_task = Arc::clone(&active_process_cache_for_event_processing);
            

            tokio::spawn(async move {
                let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();
                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for i in 0..events.read {
                        if let Ok(kernel_event) = read_from_buffer::<KernelEvent>(&buffers[i]) {
                            
                            let pid = kernel_event.tgid;

                            // --- 1. Top-Level Cache Check (This is the only one we need) ---
                            { // Scoped lock
                                let cache_guard = cache_for_task.lock().await;
                                if cache_guard.contains_key(&pid) {
                                    // info!("[Events] CACHE_HIT: TGID {} already processed.", pid);
                                    continue; // Skip to the next event
                                }
                            } // Lock released
                            info!("[Events] CACHE_MISS: New TGID {} detected. Verifying...", pid);

                            // --- 2. Gather Process Info (This is now only run on a cache miss) ---
                            let (comm_slice, comm_str) = {
                                let null_pos = kernel_event.comm.iter().position(|&c| c == 0).unwrap_or(kernel_event.comm.len());
                                let slice = &kernel_event.comm[0..null_pos];
                                (slice, String::from_utf8_lossy(slice))
                            };

                            let mut lineage_info = Vec::new();
                            let mut lineage_paths = Vec::<PathBuf>::new();
                            let mut current_pid = pid;
                            let mut visited_pids = HashSet::new();

                            for _ in 0..10 { 
                                if current_pid == 0 || current_pid == 1 || visited_pids.contains(&current_pid) {
                                    break;
                                }
                                visited_pids.insert(current_pid);

                                if let Some((ppid, proc_name, full_exe_path)) = get_process_info(current_pid) {
                                    let display_name = if !full_exe_path.is_empty() {
                                        full_exe_path
                                    } else {
                                        proc_name
                                    };
                                    lineage_paths.push(display_name.clone().into());
                                    lineage_info.push(format!("{} (PID: {})", display_name, current_pid));
                                    current_pid = ppid;
                                } else {
                                    lineage_info.push(format!("Unknown Process (PID: {})", current_pid));
                                    break;
                                }
                            }

                            lineage_info.reverse();
                            let lineage_string = if lineage_info.is_empty() {
                                format!("No lineage info for PID {}", pid)
                            } else {
                                lineage_info.join(" -> ")
                            };

                            // --- 3. Match on Event Type (Now that we have all info) ---
                            match kernel_event.event_type {
                                EventType::ConnectionAttempt => {
                                    let connection_key: ConnectionKey = unsafe { kernel_event.payload.connection_attempt.key };
                                    
                                    info!(
                                        "[Events] CONN_ATTEMPT: PID={}, TGID={}, Comm={}, Src={}:{}, Dest={}:{}, Proto={:?} \n  Process Lineage: {}",
                                        kernel_event.pid,
                                        kernel_event.tgid,
                                        comm_str,
                                        Ipv4Addr::from(u32::from_le(connection_key.saddr)), // Use from_le for logging
                                        u16::from_le(connection_key.sport),             // Use from_le for logging
                                        Ipv4Addr::from(u32::from_le(connection_key.daddr)), // Use from_le for logging
                                        u16::from_le(connection_key.dport),             // Use from_le for logging
                                        connection_key.protocol,
                                        lineage_string
                                    );
                                    
                                    // --- THE REDUNDANT CACHE CHECK HAS BEEN REMOVED FROM HERE ---

                                    // --- Check Permissive Mode Flag ---
                                    let permissive_flag = match get_permissive_mode_value(Arc::clone(&permissive_mode_for_task)).await {
                                        Ok(flag) => flag,
                                        Err(e) => {
                                            warn!("[Events] Failed to get permissive mode flag: {}. Defaulting to OFF.", e);
                                            0
                                        }
                                    };

                                    // --- 4. Make Decision (Permissive or Strict) ---
                                    let (decision, proc_info) = if permissive_flag == 1 {
                                        // --- 4a. PERMISSIVE MODE IS ON ---
                                        info!("[Events] PERMISSIVE_MODE: Allowing new TGID {}", pid);
                                        lineage_paths.reverse();
                                        let mut permissive_app_ids_defined = Vec::<(String, String)>::new();
                                        let mut final_path = PathBuf::new();

                                        for app_path in &lineage_paths {
                                            if let Ok(current_hash) = calculate_file_hash(app_path.clone()).await {
                                                permissive_app_ids_defined.push((
                                                    app_path.to_string_lossy().into_owned(),
                                                    current_hash.clone()
                                                ));
                                                if final_path.as_os_str().is_empty() {
                                                    final_path = app_path.clone();
                                                }
                                            }
                                        }
                                        
                                        let path_tuple_to_send = ProcessLineageTuple {
                                            component: "Firewall".to_string(),
                                            lineage_tuple: permissive_app_ids_defined,
                                        };
                                        if let Err(e) = task_zmq_tx.send(FireWhalMessage::PermissiveModeTuple(path_tuple_to_send)).await {
                                            warn!("[Events] Failed to send permissive mode tuple: {}", e);
                                        }

                                        (Action::Allow, ProcessInfo {
                                            path: final_path,
                                            hash: "PERMISSIVE_ALLOW".to_string(),
                                            action: firewhal_core::Action::Allow,
                                        })
                                    } else {
                                        // --- 4b. PERMISSIVE MODE IS OFF ---
                                        info!("[Events] Verifying TGID {} against allowlist...", pid);
                                        lineage_paths.reverse(); 
                                        
                                        let mut decision = Action::Deny;
                                        let mut matched_path = PathBuf::new();
                                        let mut matched_hash = String::new();

                                        
                                        for app_path in &lineage_paths {
                                            let expected_hash = {
                                                let app_ids_guard = app_ids_for_task.lock().await;
                                                app_ids_guard.get(app_path).cloned() // Clone the hash string
                                            }; // 2. Lock is immediately released here

                                            // 3. Now we check the hash
                                            if let Some(expected_hash) = expected_hash {
                                                // Path is in the allowlist. Now check the hash.
                                                info!("[Verify] Path match for TGID {}: {}. Checking hash.", pid, app_path.display());
                                                
                                                match calculate_file_hash(app_path.clone()).await {
                                                    Ok(actual_hash) => {
                                                        if expected_hash == actual_hash {
                                                            info!("[Verify] Hash MATCH for {}. Allowing.", app_path.display());
                                                            decision = Action::Allow;
                                                            matched_path = app_path.clone();
                                                            matched_hash = actual_hash;
                                                        } else {
                                                            info!("[Verify] HASH MISMATCH for {}. Blocking.", app_path.display());
                                                            decision = Action::Deny;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        info!("[Verify] Failed to hash {}: {}. Blocking.", app_path.display(), e);
                                                        decision = Action::Deny;
                                                    }
                                                }
                                                break; 
                                            }
                                        }
                                        
                                        let core_action = match decision {
                                            Action::Allow => firewhal_core::Action::Allow,
                                            Action::Deny => firewhal_core::Action::Deny,
                                        };

                                        (decision, ProcessInfo {
                                            path: matched_path,
                                            hash: matched_hash,
                                            action: core_action
                                        })
                                    };

                                    // --- 5. Update Caches and Kernel Maps ---
                                    let trust_info = PidTrustInfo {
                                        action: decision,
                                        last_seen_ns: 0,
                                    };
                                    
                                    { // Scoped block for locks
                                        let mut cache_guard = cache_for_task.lock().await;
                                        let mut trusted_pids_guard = trusted_pids_for_task.lock().await;

                                        cache_guard.insert(pid, proc_info);
                                        
                                        if let Err(e) = trusted_pids_guard.insert(&pid, trust_info, 0) {
                                            warn!("[Kernel] Failed to insert trust for PID {}: {}", pid, e);
                                        } else {
                                            info!("[Kernel] Inserted trust for PID {}: {:?}", pid, trust_info.action);
                                        }
                                    }

                                    // if decision == Action::Allow {
                                    //     let mut trusted_connections = trusted_connections_for_task.lock().await;
                                    //     let mut pending_connections = pending_connections_for_task.lock().await;
                                    //     let _ = trusted_connections.insert(&connection_key, pid, 0);
                                    //     let _ = pending_connections.remove(&connection_key);
                                    // }
                                }
                                EventType::BlockEvent => {
                                    let payload = unsafe { kernel_event.payload.block_event };
                                    let connection_key = payload.key;
                                    let formatted_event = format!(
                                        "BLOCKED: Reason={:?}, PID={}, TGID={}, Comm={}, Dest={}:{}, Proto={:?} \n  Process Lineage: {}",
                                        payload.reason,
                                        kernel_event.pid,
                                        kernel_event.tgid,
                                        comm_str,
                                        Ipv4Addr::from(u32::from_be(connection_key.daddr)),
                                        connection_key.dport,
                                        connection_key.protocol,
                                        lineage_string
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
    // let initial_interfaces = get_all_interfaces();
    // attach_xdp_programs(Arc::clone(&bpf), initial_interfaces.clone(), active_xdp_interfaces.clone()).await?;
    attach_cgroup_programs(Arc::clone(&bpf), cgroup_file).await?;
    // attach_tc_programs(Arc::clone(&bpf), initial_interfaces.clone(), active_tc_interfaces.clone()).await?;
    
    // Set Permissive Mode To False just to be safe
    update_permissive_mode_flag(Arc::clone(&permissive_mode_shared), false).await?;


    // --- Main Event Loop and Shutdown logic ---
    // Send Ready Status to IPC
    to_zmq_tx.send(FireWhalMessage::Status(StatusUpdate { component: "Firewall".to_string(), is_healthy: true, message: "Ready".to_string() })).await?;
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
                    FireWhalMessage::LoadAppIds(incoming_app_ids_config) => {
                        info!("[Kernel] Received app IDs from TUI");
                        load_app_ids( Arc::clone(&app_ids_for_id_update), Arc::clone(&active_process_cache_for_id_update), Arc::clone(&trusted_pids_for_id_update), incoming_app_ids_config).await?;
                    },
                    FireWhalMessage::LoadInterfaceState(interface_state_message) => {
                        // if update.source == "TUI" {
                        info!("[Kernel] Received interface update from TUI {:?}.", interface_state_message.enforced_interfaces);
                        let interfaces: Vec<String> = interface_state_message.enforced_interfaces.iter().cloned().collect();
                        // attach_xdp_programs(Arc::clone(&bpf), interfaces.clone(), active_xdp_interfaces.clone()).await?; 
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
                    FireWhalMessage::EnablePermissiveMode(_) => { 
                        update_permissive_mode_flag(Arc::clone(&permissive_mode_for_main_loop), true).await?;
                        prune_denied_pids(
                            Arc::clone(&trusted_pids_for_id_update),
                            Arc::clone(&active_process_cache_for_id_update) // Make sure you have a clone for this
                        ).await?;
                    },
                    FireWhalMessage::DisablePermissiveMode(_) => {
                        update_permissive_mode_flag(Arc::clone(&permissive_mode_for_main_loop), false).await?;
                        on_disable_permissive_mode(
                            Arc::clone(&trusted_pids_for_id_update),
                            Arc::clone(&trusted_connections_for_id_update),
                            Arc::clone(&pending_connections_for_id_update),
                            Arc::clone(&active_process_cache)
                        ).await?;
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

    info!("[Kernel] 🧹 Detaching eBPF programs and exiting...");
    shutdown_tx.send(()).unwrap();
    // Wait for the ZMQ task to shut down, but with a timeout to prevent hangs.
    // if let Err(_) = time::timeout(Duration::from_secs(2), zmq_handle).await {
    //     warn!("[Kernel] Timeout waiting for ZMQ task to shut down. It may be forcefully terminated.");
    // } else {
    //     info!("[Kernel] ZMQ task shut down gracefully.");
    // }

    Ok(())
}