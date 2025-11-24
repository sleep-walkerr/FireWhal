/*
Define IPv4 address via u32::from_be_bytes([192, 168, 1, 2])
*/

#![no_std]
#![no_main]

use core::{fmt::DebugTuple, hash::Hash, mem, net::{IpAddr,Ipv4Addr}};

use aya_ebpf::{
    EbpfContext, bindings::{TC_ACT_OK, TC_ACT_SHOT, sockaddr, xdp_action, bpf_sock_tuple, bpf_sock, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB}, helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_get_socket_cookie, bpf_skc_lookup_tcp, bpf_sk_release}, macros::{cgroup_sock_addr, classifier, map, xdp, sock_ops}, maps::{Array, HashMap, LpmTrie, LruHashMap, PerfEventArray, RingBuf}, programs::{SockAddrContext, TcContext, SockOpsContext} 
};
use aya_log_ebpf::{info, error, warn};

use firewhal_kernel_common::{Action, BlockEvent, BlockEventPayload, BlockReason, ConnectionAttemptPayload, ConnectionInfo, ConnectionKey, ConnectionTuple, EventType, KernelEvent, LpmIpKey, PidTrustInfo, RuleAction, RuleKey, parse_packet_tuple, parse_tcp_header};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

#[map]
static mut EVENTS: PerfEventArray<KernelEvent> = PerfEventArray::new(0); // Change to accept KernelEvents instead

#[map]
static mut RULES: HashMap<RuleKey, RuleAction> = HashMap::with_max_entries(1024, 0);

#[map]
static mut INCOMING_RULES: HashMap<RuleKey, RuleAction> = HashMap::with_max_entries(1024, 0);

#[map] // Connection Tracking Map for Stateful
static mut CONNECTION_MAP: LruHashMap<ConnectionTuple, ConnectionInfo> =
    LruHashMap::with_max_entries(4096, 0);

#[map]
static mut TRUSTED_PIDS: HashMap<u32, PidTrustInfo> = HashMap::with_max_entries(4096, 0);

#[map]
static mut PENDING_CONNECTIONS_MAP: HashMap<ConnectionKey, u32> = HashMap::with_max_entries(4096, 0);

#[map]
static mut TRUSTED_CONNECTIONS_MAP: HashMap<ConnectionKey, u32> = HashMap::with_max_entries(4096, 0);

#[map]
static mut SOCKET_COOKIE_TRUST: HashMap<u64, u32> = HashMap::with_max_entries(4096, 0);

#[map]
static mut PERMISSIVE_MODE_ENABLED: Array<u32> = Array::with_max_entries(1, 0);

#[map] 
static PENDING_LISTENING_PORTS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map] 
static TRUSTED_LISTENING_PORTS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

// Set by sock_ops, Read by TC
#[map]
static TRUSTED_COOKIES: HashMap<u64, u8> = HashMap::with_max_entries(10000, 0);

#[map]
static HANDSHAKE_ALLOWED: HashMap<ConnectionTuple, u64> = HashMap::with_max_entries(4096, 0);


// The following maps were for the map-in-map implementation and are no longer needed.
//
// #[map]
// static mut PROTOCOL_RULES: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);
// #[map(pinned)]
// static mut PORT_RULES_TEMPLATE: HashMap<u16, u32> = HashMap::with_max_entries(256, 0);
// #[map(pinned)]
// static mut IP_RULES_TEMPLATE: LpmTrie<LpmIpKey, RuleAction> = LpmTrie::with_max_entries(1024, 0);

// Handler for syscall programs, inserts connection keys for already approved PIDs and sends events for those not in the map
fn app_tracking(prog_name: &str, ctx: &SockAddrContext) {
    //Consider changing these back to safe "ctx.user_ipv" and the like if you can
    let sockaddr_pointer = ctx.sock_addr;
    let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
    // let msg_src_ip4 = unsafe { (*sockaddr_pointer).msg_src_ip4 }; // This is the source IP address, just like the port, it always returns 0 here
    let user_port = unsafe { (*sockaddr_pointer).user_port }; 
    let protocol = unsafe { (*sockaddr_pointer).protocol };
    let command_fetch = ctx.command();
    let command: [u8; 16]; 
    if command_fetch.is_ok() {
        command = command_fetch.unwrap();
    } else { 
        command = [0; 16];
        info!(ctx, "Command fetching failed");
    }

    //Ports are u32 instead of u16 because src and dst are stored into one value for efficiency
    // They need to be converted to be used first
    let source_port =  u32::from_be(user_port) as u16;
    let destination_port = (u32::from_be(user_port) >> 16) as u16;


    // Check if TGID already exists in map
    if let Some(pid_info) = unsafe { TRUSTED_PIDS.get(&ctx.tgid()) } {
        info!(ctx, "[Kernel] [{}] Trusted PID {} found for {}", prog_name, (ctx.tgid()) as u32, Ipv4Addr::from(u32::from_be(user_ip4)));
        if pid_info.action == Action::Allow {
            // Build connection key for payload
            let key_to_use = ConnectionKey { saddr: 0, daddr: user_ip4, sport: 0, dport: destination_port, protocol: protocol as u8, _padding: [0; 3]};
            // Insert into again, in case of a trusted process connecting to a new ip address
            if let Err(e) = unsafe { PENDING_CONNECTIONS_MAP.insert(&key_to_use, &ctx.tgid(), 0) } { // Switched this from trusted to pending to fit new model
                warn!(ctx, "[Kernel] [{}] Failed to insert connection key: PID:{}, Key: [{}, src[{}:{}], dst[{}:{}]]", 
                prog_name, 
                ctx.tgid(), 
                key_to_use.protocol as u8,
                Ipv4Addr::from(u32::from_be(key_to_use.saddr)), 
                key_to_use.sport, 
                Ipv4Addr::from(u32::from_be(key_to_use.daddr)),  
                key_to_use.dport,                
                );
            } else {
                info!(ctx, "[Kernel] [{}] Successfully inserted connection key: PID:{}, Key: [{}, src[{}:{}], dst[{}:{}]]", 
                prog_name, 
                ctx.tgid(), 
                key_to_use.protocol as u8,
                Ipv4Addr::from(u32::from_be(key_to_use.saddr)), 
                key_to_use.sport, 
                Ipv4Addr::from(u32::from_be(key_to_use.daddr)),  
                key_to_use.dport, 
                );
            }
            return 
        }
    } else { // If it doesn't send event to check application
        // Build connection key for payload
        let key_to_use = ConnectionKey { saddr: 0, daddr: user_ip4, sport: 0, dport: destination_port, protocol: protocol as u8, _padding: [0; 3]};
        let conn_attempt_payload = ConnectionAttemptPayload {
            key: key_to_use
        };
        let connection_attempt_event = KernelEvent {
            event_type: EventType::ConnectionAttempt, // Specific event type
            pid: ctx.pid(),
            tgid: ctx.tgid(),
            comm: command,
            payload: firewhal_kernel_common::KernelEventPayload { connection_attempt: (conn_attempt_payload) }
        };
        // Insert into pending connections map
        if let Err(e) = unsafe { PENDING_CONNECTIONS_MAP.insert(&key_to_use, &ctx.tgid(), 0) } {
            warn!(ctx, "[Kernel] [{}] Failed to insert connection key: PID:{}, Key: [{}, src[{}:{}], dst[{}:{}]]", 
            prog_name, 
            ctx.tgid(), 
            key_to_use.protocol as u8,
            Ipv4Addr::from(u32::from_be(key_to_use.saddr)), 
            key_to_use.sport, 
            Ipv4Addr::from(u32::from_be(key_to_use.daddr)),  
            key_to_use.dport,                
        );
        } else {
            info!(ctx, "[Kernel] [{}] Successfully inserted connection key: PID:{}, Key: [{}, src[{}:{}], dst[{}:{}]]", 
            prog_name, 
            ctx.tgid(), 
            key_to_use.protocol as u8,
            Ipv4Addr::from(u32::from_be(key_to_use.saddr)), 
            key_to_use.sport, 
            Ipv4Addr::from(u32::from_be(key_to_use.daddr)),  
            key_to_use.dport, 
            );
        }
        // Send event for processing
        unsafe { EVENTS.output(ctx, &connection_attempt_event, 0) };
    }
}

#[inline(always)]
fn rule_matching(ctx: &TcContext, tuple: ConnectionTuple, info: ConnectionInfo) -> Result<i32, ()> {
    // --- 1. Prepare Block Event (in case we need it) ---
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    let block_event_payload = BlockEventPayload {
        key: ConnectionKey {
            sport: tuple.sport,
            dport: tuple.dport,
            protocol: tuple.protocol,
            saddr: tuple.saddr,
            daddr: tuple.daddr,
            _padding: [0; 3],
        },
        // Set a more accurate block reason based on protocol
        reason: match tuple.protocol as u32 {
            6 => BlockReason::IpBlockedEgressTcp,
            17 => BlockReason::IpBlockedEgressUdp,
            _ => BlockReason::IpBlockedEgressTcp, // Default
        },
    };
    let block_event = KernelEvent {
        event_type: EventType::BlockEvent,
        pid: pid_tgid as u32,
        tgid: tgid,
        comm: [0; 16],
        payload: firewhal_kernel_common::KernelEventPayload {
            block_event: (block_event_payload),
        },
    };

    // --- 2. Define Rule Keys to Check, from most to least specific ---
    let keys_to_check = [
        // Most specific: Proto + IP + Port
        RuleKey { protocol: tuple.protocol as u32, dest_ip: tuple.daddr, dest_port: tuple.dport, source_ip: 0, source_port: 0 },
        // Wildcard Port: Proto + IP
        RuleKey { protocol: tuple.protocol as u32, dest_ip: tuple.daddr, dest_port: 0, source_ip: 0, source_port: 0 },
        // Wildcard IP: Proto + Port
        RuleKey { protocol: tuple.protocol as u32, dest_ip: 0, dest_port: tuple.dport, source_ip: 0, source_port: 0 },
        // Wildcard Protocol: IP + Port
        RuleKey { protocol: 0, dest_ip: tuple.daddr, dest_port: tuple.dport, source_ip: 0, source_port: 0 },
        // Wildcard Protocol & Port: IP only
        RuleKey { protocol: 0, dest_ip: tuple.daddr, dest_port: 0, source_ip: 0, source_port: 0 },
        // Wildcard Protocol & IP: Port only
        RuleKey { protocol: 0, dest_ip: 0, dest_port: tuple.dport, source_ip: 0, source_port: 0 },
    ];

    // --- 3. Check for a matching rule ---
    let mut matched_action: Option<&RuleAction> = None;

    // The verifier can unroll this sequence of checks.
    if let Some(action) = unsafe { RULES.get(&keys_to_check[0]) } { matched_action = Some(action); }
    else if let Some(action) = unsafe { RULES.get(&keys_to_check[1]) } { matched_action = Some(action); }
    else if let Some(action) = unsafe { RULES.get(&keys_to_check[2]) } { matched_action = Some(action); }
    else if let Some(action) = unsafe { RULES.get(&keys_to_check[3]) } { matched_action = Some(action); }
    else if let Some(action) = unsafe { RULES.get(&keys_to_check[4]) } { matched_action = Some(action); }
    else if let Some(action) = unsafe { RULES.get(&keys_to_check[5]) } { matched_action = Some(action); }

    // --- 4. Process the matched rule ---
    if let Some(action) = matched_action {
        return match action.action {
            Action::Allow => {
                info!(ctx, "[Kernel] [egress_tc] Rule {} ALLOWED connection to {}:{}", action.rule_id, Ipv4Addr::from(u32::from_be(tuple.daddr)), tuple.dport);
                // Add to stateful map for return traffic
                if unsafe { CONNECTION_MAP.insert(&tuple, &info, 0) }.is_err() {
                    info!(ctx, "[Egress] FAILED to insert tuple into map!");
                    return Ok(TC_ACT_SHOT);
                }
                Ok(TC_ACT_OK)
            }
            Action::Deny => {
                info!(ctx, "[Kernel] [egress_tc] Rule {} BLOCKED connection to {}:{}", action.rule_id, Ipv4Addr::from(u32::from_be(tuple.daddr)), tuple.dport);
                unsafe { EVENTS.output(ctx, &block_event, 0) };
                Ok(TC_ACT_SHOT)
            }
        };
    }

    // --- 5. Default Action: No rule matched ---
    // If we reach here, no rule matched. Your previous logic defaulted to block.
    info!(ctx, "[Kernel] [egress_tc] No rule matched. Blocking connection to {}:{}", Ipv4Addr::from(u32::from_be(tuple.daddr)), tuple.dport);
    Ok(TC_ACT_SHOT)
}

#[inline(always)]
fn ingress_rule_matching(ctx: &TcContext, tuple: ConnectionTuple) -> Result<i32, ()> {
    // --- 1. Prepare Block Event (in case we need it) ---
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    let block_event_payload = BlockEventPayload {
        key: ConnectionKey {
            sport: tuple.sport,
            dport: tuple.dport,
            protocol: tuple.protocol,
            saddr: tuple.saddr,
            daddr: tuple.daddr,
            _padding: [0; 3],
        },
        reason: BlockReason::IpBlockedIngress, // A more specific reason
    };
    let block_event = KernelEvent {
        event_type: EventType::BlockEvent,
        pid: pid_tgid as u32,
        tgid: tgid,
        comm: [0; 16],
        payload: firewhal_kernel_common::KernelEventPayload {
            block_event: (block_event_payload),
        },
    };

    // --- 2. Define Rule Keys for INGRESS traffic ---
    // For ingress, we match against the SOURCE IP and PORT.
    let keys_to_check = [
        // Most specific: Proto + Source IP + Source Port
        RuleKey { protocol: tuple.protocol as u32, source_ip: tuple.saddr, source_port: tuple.sport, dest_ip: 0, dest_port: 0 },
        // Wildcard Port: Proto + Source IP
        RuleKey { protocol: tuple.protocol as u32, source_ip: tuple.saddr, source_port: 0, dest_ip: 0, dest_port: 0 },
        // Wildcard Protocol: Source IP only
        RuleKey { protocol: 0, source_ip: tuple.saddr, source_port: 0, dest_ip: 0, dest_port: 0 },
        // Wildcard All: Source Port Only
        RuleKey { protocol: 0, source_ip: 0, source_port: tuple.sport, dest_ip: 0, dest_port: 0 },
        // Wildcard All: Destination Port Only
        RuleKey { protocol: 0, source_ip: 0, source_port: 0, dest_ip: 0, dest_port: tuple.dport },
    ];

    // --- 3. Check for a matching rule ---
    let mut matched_action: Option<&RuleAction> = None;

    if let Some(action) = unsafe { INCOMING_RULES.get(&keys_to_check[0]) } { matched_action = Some(action); }
    else if let Some(action) = unsafe { INCOMING_RULES.get(&keys_to_check[1]) } { matched_action = Some(action); }
    else if let Some(action) = unsafe { INCOMING_RULES.get(&keys_to_check[2]) } { matched_action = Some(action); }
    else if let Some(action) = unsafe { INCOMING_RULES.get(&keys_to_check[3]) } { matched_action = Some(action); }
    else if let Some(action) = unsafe { INCOMING_RULES.get(&keys_to_check[4]) } { matched_action = Some(action); }


    // --- 4. Process the matched rule ---
    if let Some(action) = matched_action {
        return match action.action {
            Action::Allow => {
                info!(ctx, "[Kernel] [ingress_tc] Rule {} ALLOWED incoming connection from {}:{}", action.rule_id, Ipv4Addr::from(u32::from_be(tuple.saddr)), tuple.sport);
                // Check if TCP traffic
                if tuple.protocol == 6 {
                    let tcp_header_result = parse_tcp_header(ctx);

                    if let Ok(tcp_header) =  tcp_header_result{
                        info!(ctx, "[Kernel] [ingress_tc] TCP connection SYN Check: {}", tcp_header.syn());
                        if tcp_header.syn() == 1 {
                            // let ts = unsafe { bpf_ktime_get_ns() };
                            info!(ctx, "[Kernel] [ingress_tc] Inserting Handshake Allow: {} {} {} {} {}", tuple.saddr, tuple.daddr, tuple.sport, tuple.dport, tuple.protocol);
                            unsafe { HANDSHAKE_ALLOWED.insert(&tuple, &0, 0) };
                        }
                    }
                }

                Ok(TC_ACT_OK)
            }
            Action::Deny => {
                info!(ctx, "[Kernel] [ingress_tc] Rule {} BLOCKED incoming connection from {}:{}", action.rule_id, Ipv4Addr::from(u32::from_be(tuple.saddr)), tuple.sport);
                unsafe { EVENTS.output(ctx, &block_event, 0) };
                Ok(TC_ACT_SHOT)
            }
        };
    }

    // --- 5. Default Action: No rule matched ---
    info!(ctx, "[Kernel] [ingress_tc] No ingress rule matched. Blocking connection from {}:{}", Ipv4Addr::from(u32::from_be(tuple.saddr)), tuple.sport);
    Ok(TC_ACT_SHOT)
}

// INGRESS PROGRAMS
#[classifier] // Checks incoming traffic, allowed traffic should include either explicit allows via rules, or connection map matches for the stateful firewall
pub fn firewhal_ingress_tc(ctx: TcContext) -> i32 {
    match try_firewhal_ingress_tc(ctx) {
        Ok(ret) => ret,
        Err(_) => {
            TC_ACT_OK // If parsing fails, allow. It means there is no handling for that type of traffic
        }, 
    }
}

fn try_firewhal_ingress_tc(ctx: TcContext) -> Result<i32, ()> {

        let result = || -> Result<i32, i32> {
            if let Ok(tuple) = parse_packet_tuple(&ctx) {
                // For ingress, we need to check for the REVERSE tuple, since we are
                // looking for the return path of an outgoing connection.
                let reversed_tuple = ConnectionTuple {
                    saddr: tuple.daddr, // Swapped
                    daddr: tuple.saddr, // Swapped
                    sport: tuple.dport, // Swapped
                    dport: tuple.sport, // Swapped
                    protocol: tuple.protocol,
                    ..tuple
                };

                // Also check for a portless version for protocols like ICMP
                let portless_tuple = ConnectionTuple {
                    sport: 0,
                    dport: 0,
                    ..reversed_tuple
                };

                let dhcp_response = ConnectionTuple {
                    saddr: 0,
                    daddr: 0,
                    sport: 68,
                    dport: 67,
                    protocol: 17,
                    ..reversed_tuple
                };


                // For logging, convert network-order (big-endian) values to host-order.
                // Ipv4Addr::from() expects a big-endian u32, so we don't convert IPs.
                // The info! macro handles the u16 endianness for printing.
                let source_address = Ipv4Addr::from(reversed_tuple.saddr);
                let destination_address = Ipv4Addr::from(reversed_tuple.daddr);
                let source_port = reversed_tuple.sport;
                let destination_port = reversed_tuple.dport;
                let protocol = reversed_tuple.protocol;

                // Check if this connection is in our tracking map.
                if unsafe { CONNECTION_MAP.get(&reversed_tuple).is_some() } {
                    // info!(&ctx, "[Kernel] [firewall_ingress_tc]: Allowed tuple found: [{} {} {} {} {}]\n\n", source_address, destination_address, source_port, destination_port, protocol);
                    //
                    return Ok(TC_ACT_OK)
                } else if unsafe { CONNECTION_MAP.get(&dhcp_response).is_some() } {
                    // info!(&ctx, "[Kernel] [firewall_ingress_tc]: Allowed tuple found: [{} {} {} {} {}]\n\n", source_address, destination_address, source_port, destination_port, protocol);
                    //
                    return Ok(TC_ACT_OK)
                } else if unsafe { CONNECTION_MAP.get(&portless_tuple).is_some() } {
                    // info!(&ctx, "[Kernel] [firewall_ingress_tc]: Allowed portless tuple found: [{} {} {} {} {}]", source_address, destination_address, source_port, destination_port, protocol);
                    return Ok(TC_ACT_OK);
                } else {
                    info!(&ctx, "[Kernel] [firewall_ingress_tc]: Tuple not found for: [{} {} {} {} {}]", source_address, destination_address, source_port, destination_port, protocol);
                    // If no stateful match, fall back to stateless ingress rule matching.
                    return ingress_rule_matching(&ctx, tuple).map_err(|_| 0);
                }
            } else {
                info!(&ctx, "[Kernel] [firewall_ingress_tc]: Parsing error");
                return Err(TC_ACT_OK)
            }
        }();

    match result {
        Ok(ret) => Ok(ret),
        Err(ret) => {
            Err(())
        },
    }
}


// EGRESS PROGRAMS
#[cgroup_sock_addr(connect4)]
pub fn firewhal_egress_connect4(ctx: SockAddrContext) -> i32 {
    match try_firewhal_egress_connect4(ctx) {
        Ok(ret) => ret,
        Err(_) => {
            // let traffic pass on failure for now
            1
        }
    }
}
pub fn try_firewhal_egress_connect4(ctx: SockAddrContext) -> Result<i32, ()> {
    // Here we will now send the command information along with other relevant information to the userspace, which will then either add the PID to the list of approved PIDs or drop
    // We then check if it was added, if not, we block the connection attempt
    

    let result = || -> Result<i32, i32> {
        app_tracking("connect4",&ctx);
        Ok(1) // Allow the connection, blocking delegated to tc egress program
    }();

    match result {
        Ok(ret) => Ok(ret),
        Err(ret) => {
            info!(&ctx,"[Kernel] [connect4] Program logic failed.");
            Err(())
        },
    }
}



#[cgroup_sock_addr(sendmsg4)]
pub fn firewhal_egress_sendmsg4(ctx: SockAddrContext) -> i32 {
    let result = || -> Result<i32, i32> {
        app_tracking("sendmsg4", &ctx);
        Ok(1) // Allow the connection for now, blocking delegated to tc egress program
    }();
        

    match result {
        Ok(ret) => ret,
        Err(ret) => {
            info!(&ctx, "[Kernel] [sendmsg4] Failed to process packet.");
            ret
        },
    }
}


#[cgroup_sock_addr(bind4)]
pub fn firewhal_egress_bind4(ctx: SockAddrContext) -> i32 {
    let result = || -> Result<i32, i32> {
        let user_port = unsafe { (*ctx.sock_addr).user_port }; 
        let destination_port = (u32::from_be(user_port) >> 16) as u16;
        
        info!(&ctx, "[Kernel] [bind4] Destination Port: {}", destination_port);
        
        let insertion_result = unsafe {PENDING_LISTENING_PORTS.insert(&u32::from(destination_port), &ctx.tgid(), 0) };
        if insertion_result.is_err() {
                    info!(&ctx, "[Egress] FAILED to insert tuple into map!");
                    return Ok(TC_ACT_SHOT)
                }
        app_tracking("bind4", &ctx);
        Ok(1) // Allow the connection for now, blocking delegated to tc egress program
    }();

    match result {
        Ok(ret) => ret,
        Err(ret) => {
            info!(&ctx, "[Kernel] [bind4] Failed to process packet.");
            ret
        },
    }
}

#[classifier] // Used for connection tracking when an outgoing connection is allowed
pub fn firewhal_egress_tc(ctx: TcContext) -> i32 { // Change return type to include tuple, and then insert it here
    match try_firewhal_egress_tc(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK, // If there is a parsing error, allow the traffic. It means we haven't implemented a way to handle it yet.
    }
}

fn try_firewhal_egress_tc(ctx: TcContext) -> Result<i32, ()> {
    let mut tuple = parse_packet_tuple(&ctx)?;
    // Create debug printing fields
    let debug_saddr = Ipv4Addr::from(u32::from_be(tuple.saddr));
    let debug_daddr = Ipv4Addr::from(u32::from_be(tuple.daddr));
    let debug_sport = tuple.sport;
    let debug_dport = tuple.dport;
    // Placeholder Info, Move Inside ConnectionKey Matching Later for REAL TGID
    let mut info = ConnectionInfo {
        pid: 0, // In TC we don't know the PID, this would be set by the cgroup program
        last_seen: unsafe { bpf_ktime_get_ns() },
    };
    // Check to see if broadcast for DHCP
    if tuple.saddr == Ipv4Addr::from([0,0,0,0]).into() && tuple.daddr == Ipv4Addr::from([255,255,255,255]).into() { // Add port 68 and 67 here as well
        
        let broadcast_rule = ConnectionTuple {
        saddr: 0,
        daddr: 0,
        sport: tuple.sport,
        dport: tuple.dport,
        protocol: tuple.protocol,
        _pad: [0; 3],
        };
        tuple = broadcast_rule;
        info!(&ctx, "[Kernel] [egress_tc] DHCP ALLOWED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                info!(&ctx, "[Kernel] [egress_tc]: Adding tuple for DHCP: [{} {} {} {} {}]", debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                let result = unsafe { CONNECTION_MAP.insert(&tuple, &info, 0) };
                if result.is_err() {
                    info!(&ctx, "[Egress] FAILED to insert tuple into map!");
                    return Ok(TC_ACT_SHOT)
                }
                return Ok(TC_ACT_OK);
    }


    // Extract Connection Key for Pending Match
    let incoming_connection_key = ConnectionKey {
        saddr: tuple.saddr,
        daddr: tuple.daddr,
        sport: tuple.sport,
        dport: tuple.dport,
        protocol: tuple.protocol,
        _padding: [0; 3],
     };

     // Two potential pending keys for matching
     // Likely Pending Connection Key (with port)
     let pending_connection_key = ConnectionKey {
        saddr: 0,
        daddr: tuple.daddr,
        sport: 0,
        dport: tuple.dport,
        protocol: tuple.protocol,
        _padding: [0; 3],
     };

     // Portless Pending Connection Key: *** This is for instances when QUIC or other contexts cause the port to be 0 in the syscall programs
     let portless_pending_connection_key = ConnectionKey {
        saddr: 0,
        daddr: tuple.daddr,
        sport: 0,
        dport: tuple.dport,
        protocol: tuple.protocol,
        _padding: [0; 3],
     };

     // Print for Debug
     info!(&ctx, "[Kernel] [egress_tc] ConnectionKey: {} {} {} {} {}", debug_saddr, debug_daddr, debug_sport, debug_dport, incoming_connection_key.protocol as u8);

    // THIS NEEDS TO BE MOVED: Server Functionality
    //
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };
    if cookie == 0 {
        // Packet is not associated with a socket.
        info!(&ctx, "[Kernel] [egress_tc] Packet has no socket cookie.");
    } else if unsafe { TRUSTED_COOKIES.get(&cookie).is_some() } {
        info!(&ctx, "[Kernel] [egress_tc] Trusted Cookie Found: {}", cookie);
        return Ok(TC_ACT_OK)
    } else {
        info!(&ctx, "[Kernel] [egress_tc] No Trusted Cookie Found: {}", cookie);
        if tuple.protocol == 6 {
            let tcp_header_result = parse_tcp_header(&ctx);

            if let Ok(tcp_header) =  tcp_header_result{
                info!(&ctx, "HANDSHAKE CHECK");
                // Check if packet is a SYN-ACK packet, this means its a local server responding to a SYN packet
                if tcp_header.syn() != 0 && tcp_header.ack() != 0 {
                    info!(&ctx, "HANDSHAKE CHECK TRUE");

                    // Reverse tuple to match insertion
                    let reversed_tuple = ConnectionTuple {
                        saddr: tuple.daddr, // Swapped
                        daddr: tuple.saddr, // Swapped
                        sport: tuple.dport, // Swapped
                        dport: tuple.sport, // Swapped
                        protocol: tuple.protocol,
                        ..tuple
                    };
                    info!(&ctx, "CHECKING KEY: {} {} {} {} {}", reversed_tuple.saddr, reversed_tuple.daddr, reversed_tuple.sport, reversed_tuple.dport, reversed_tuple.protocol);
                    // Check for temporary allow entry made for allowed incoming traffic
                    if unsafe { HANDSHAKE_ALLOWED.get(&reversed_tuple).is_some() } {
                        // Check whether application is allowed or not
                        // Get pid of the application associated with bind
                        if let Some(tgid) = unsafe { PENDING_LISTENING_PORTS.get(&u32::from(reversed_tuple.dport)) } {
                            // Check if that pid (tgid) is in the trusted map
                            if let Some(pid_info) = unsafe { TRUSTED_PIDS.get(tgid) } {
                                // Check if the action for that PID is allow
                                if pid_info.action == Action::Allow {
                                    // Delete entry from PENDING_LISTENING_PORTS
                                    unsafe { PENDING_LISTENING_PORTS.remove(&u32::from(reversed_tuple.dport)) }.map_err(|_| ())?;
                                    // Add entry to TRUSTED_LISTENING_PORTS
                                    unsafe { TRUSTED_LISTENING_PORTS.insert(&u32::from(reversed_tuple.dport), &tgid, 0) }.map_err(|_| ())?;
                                    return Ok(TC_ACT_OK); // Explicitly allow the SYN-ACK
                                } else if pid_info.action == Action::Deny {
                                    // Delete entry from PENDING_LISTENING_PORTS
                                    unsafe { PENDING_LISTENING_PORTS.remove(&u32::from(reversed_tuple.dport)) }.map_err(|_| ())?;
                                    return Ok(TC_ACT_SHOT); // Explicitly deny the SYN-ACK
                                }
                            }
                        }
                        
                    }
                }
            }

        }
    }


    // THIS NEEDS TO GO IN A FUNCTION
    // Lookup in TRUSTED_CONNECTIONS_MAP
    if let Some(tgid_match) = unsafe { TRUSTED_CONNECTIONS_MAP.get(&incoming_connection_key) } {
    info.pid = *tgid_match;

    // --- YOUR NEW LOGIC GOES HERE ---
    // Check if the associated PID is *still* trusted
    if let Some(pid_info) = unsafe { TRUSTED_PIDS.get(tgid_match) } {
        if pid_info.action == Action::Allow {
            // PID is still trusted, refresh the connection's timestamp in the LRU map
            unsafe { TRUSTED_CONNECTIONS_MAP.insert(&incoming_connection_key, tgid_match, 0) }.map_err(|_| ())?;
            info!(&ctx, "[Kernel] [egress_tc] Trusted Connection for TGID {} refreshed.", *tgid_match);
            // Fall through to the final Ok(1) to allow the packet
        } else {
            // PID is in the map, but is explicitly DENIED. Block the packet.
            info!(&ctx, "[Kernel] [egress_tc] Connection for TGID {} is explicitly DENIED. Blocking.", *tgid_match);
            return Ok(TC_ACT_SHOT);
        }
    } else {
        // RACE CONDITION HANDLED:
        // The connection is known, but the PID (TGID) is no longer in the trusted map.
        // This is a stale connection. Block it and remove it.
        info!(&ctx, "[Kernel] [egress_tc] Stale connection for untrusted TGID {}. Blocking and removing.", *tgid_match);
        unsafe { TRUSTED_CONNECTIONS_MAP.remove(&incoming_connection_key) }.map_err(|_| ())?;
        return Ok(TC_ACT_SHOT);
    }
    
    // 2. Check if the connection is new and pending verification
    } else if let Some(tgid_match) = unsafe { PENDING_CONNECTIONS_MAP.get(&pending_connection_key) } {
        info.pid = *tgid_match;
        info!(&ctx, "[Kernel] [egress_tc] Pending Connection for {}, checking.", *tgid_match);
        
        if let Some(pid_info) = unsafe { TRUSTED_PIDS.get(tgid_match) } {
            if pid_info.action == Action::Allow {
                info!(&ctx, "[Kernel] [egress_tc] Pending Connection Allowed {}", *tgid_match);
                // Move from PENDING to TRUSTED
                unsafe {
                    TRUSTED_CONNECTIONS_MAP.insert(&incoming_connection_key, tgid_match, 0).map_err(|_| ())?;
                    PENDING_CONNECTIONS_MAP.remove(&pending_connection_key).map_err(|_| ())?;
                }
                // Fall through to the final Ok(1) to allow the packet
            } else { 
                info!(&ctx, "[Kernel] [egress_tc] Pending Connection Blocked (PID Denied) {}", *tgid_match);
                return Ok(TC_ACT_SHOT); // Block the connection
             }
        } else {
            info!(&ctx, "[Kernel] [egress_tc] Pending Connection Blocked (PID Not Found).");
            return Ok(TC_ACT_SHOT);
        }
    } else if let Some(tgid_match) = unsafe { PENDING_CONNECTIONS_MAP.get(&portless_pending_connection_key) } {
        info.pid = *tgid_match;
        info!(&ctx, "[Kernel] [egress_tc] Pending Connection for {}, checking.", *tgid_match);
        
        if let Some(pid_info) = unsafe { TRUSTED_PIDS.get(tgid_match) } {
            if pid_info.action == Action::Allow {
                info!(&ctx, "[Kernel] [egress_tc] Pending Connection Allowed {}", *tgid_match);
                // Move from PENDING to TRUSTED
                unsafe {
                    TRUSTED_CONNECTIONS_MAP.insert(&incoming_connection_key, tgid_match, 0).map_err(|_| ())?;
                    PENDING_CONNECTIONS_MAP.remove(&pending_connection_key).map_err(|_| ())?;
                }
                // Fall through to the final Ok(1) to allow the packet
            } else { 
                info!(&ctx, "[Kernel] [egress_tc] Pending Connection Blocked (PID Denied) {}", *tgid_match);
                return Ok(TC_ACT_SHOT); // Block the connection
             }
        } else {
            info!(&ctx, "[Kernel] [egress_tc] Pending Connection Blocked (PID Not Found).");
            return Ok(TC_ACT_SHOT);
        }
    
    // 3. Not found in either map
    } else {
        info!(&ctx, "[Kernel] [egress_tc] Connection Not Found in Either Map. Blocking.");
        return Ok(TC_ACT_SHOT);
    }

    
    //let mut comm = unsafe { bpf_get_current_comm().unwrap() };


    

    // ADD TEMP DEBUG PRINT OF FIELDS
    info!(&ctx, "[Kernel] [egress_tc] CHECKING TRAFFIC: [{}:{}, {}:{}]", debug_saddr, debug_sport, debug_daddr, debug_dport);

    // Insert fxn call here
    let rule_matching_result = rule_matching(&ctx, tuple, info)?;

    Ok(rule_matching_result) // Default: Block All 
}


// NEW PROGRAM TESTING
#[sock_ops]
pub fn firewhal_sock_ops(ctx: SockOpsContext) -> u32 {
    match try_firewhal_sock_ops(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_firewhal_sock_ops(ctx: SockOpsContext) -> Result<u32, u32> {
    match ctx.op() {
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            // 1. Get Local Port
            // Note: local_port in sock_ops is usually host byte order, 
            // but verify against your architecture.
            let local_port = ctx.local_port(); 
            info!(&ctx, "[Kernel] Checking Local Port: {}", local_port);
            
            // 2. Check if the port is trusted (set by your bind program)
            if unsafe { TRUSTED_LISTENING_PORTS.get(&local_port).is_some() } {
                
                // 3. Get the cookie of THIS new child socket
                let cookie = unsafe { bpf_get_socket_cookie(ctx.ops as *mut _) };
                info!(&ctx, "[Kernel] Trusted Port Found, Inserting Cookie: {},{}", local_port, cookie);
                
                // 4. Whitelist this specific connection for TC
                let val: u8 = 1;
                unsafe { TRUSTED_COOKIES.insert(&cookie, &val, 0) };

                // 2. Cleanup the Handshake Map
                let key = ConnectionTuple {
                    saddr: ctx.remote_ip4(), 
                    sport: ctx.remote_port() as u16, // Ensure byte order is correct here!
                    daddr: ctx.local_ip4(),
                    dport: ctx.local_port() as u16,
                    protocol: 6,
                    _pad: [0; 3],
                };
                
                unsafe { HANDSHAKE_ALLOWED.remove(&key) };
            }
        }
        _ => {}
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}