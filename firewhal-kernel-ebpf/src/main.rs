/*
Define IPv4 address via u32::from_be_bytes([192, 168, 1, 2])
*/

#![no_std]
#![no_main]

use core::{hash::Hash, mem, net::{IpAddr,Ipv4Addr}};

use aya_ebpf::{
    bindings::{sockaddr, xdp_action, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_get_current_comm},
    macros::{cgroup_sock_addr, classifier, map, xdp},
    maps::{HashMap, LpmTrie, PerfEventArray, RingBuf, LruHashMap, Array}, 
    programs::{tc, SockAddrContext, TcContext, XdpContext}, EbpfContext, 
};
use aya_log_ebpf::{info, error, warn};

use firewhal_kernel_common::{Action, BlockEvent, BlockEventPayload, BlockReason, ConnectionAttemptPayload, ConnectionInfo, ConnectionKey, ConnectionTuple, EventType, KernelEvent, LpmIpKey, PidTrustInfo, RuleAction, RuleKey, parse_packet_tuple};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};



#[map]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static mut PORT_BLOCKLIST: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static mut ICMP_BLOCK_ENABLED: HashMap<u8, u8> = HashMap::with_max_entries(1, 0);

#[map]
static mut EVENTS: PerfEventArray<KernelEvent> = PerfEventArray::new(0); // Change to accept KernelEvents instead

#[map]
static mut RULES: HashMap<RuleKey, RuleAction> = HashMap::with_max_entries(1024, 0);

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
static mut PERMISSIVE_MODE_ENABLED: Array<u32> = Array::with_max_entries(1, 0);


// The following maps were for the map-in-map implementation and are no longer needed.
//
// #[map]
// static mut PROTOCOL_RULES: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);
// #[map(pinned)]
// static mut PORT_RULES_TEMPLATE: HashMap<u16, u32> = HashMap::with_max_entries(256, 0);
// #[map(pinned)]
// static mut IP_RULES_TEMPLATE: LpmTrie<LpmIpKey, RuleAction> = LpmTrie::with_max_entries(1024, 0);

// INGRESS PROGRAMS
// #[xdp]
// pub fn firewhal_xdp(ctx: XdpContext) -> u32 {
//     let result = || -> Result<u32, ()> {
//         let data_end = ctx.data_end();
//         let data_start = ctx.data();

//         // We manually track the offset as we parse headers.
//         let mut offset = 0;

//         // Load Ethernet header. All pointer operations are unsafe and must be
//         // enclosed in an unsafe block. The bounds check is what makes this
//         // operation safe.
//         let eth_hdr: EthHdr = unsafe {
//             let ptr = (data_start as *const u8).add(offset) as *const EthHdr;
//             if (ptr as *const u8).add(mem::size_of::<EthHdr>()) > (data_end as *const u8) {
//                 return Err(());
//             }
//             *ptr
//         };
//         offset += mem::size_of::<EthHdr>();

//         if !matches!(eth_hdr.ether_type, EtherType::Ipv4) {
//             return Ok(xdp_action::XDP_PASS);
//         }

//         // Load IPv4 header.
//         let ipv4_hdr: Ipv4Hdr = unsafe {
//             let ptr = (data_start as *const u8).add(offset) as *const Ipv4Hdr;
//             if (ptr as *const u8).add(mem::size_of::<Ipv4Hdr>()) > (data_end as *const u8) {
//                 return Err(());
//             }
//             *ptr
//         };
//         let icmp_block_ptr = core::ptr::addr_of_mut!(ICMP_BLOCK_ENABLED);
        
//         if ipv4_hdr.proto == IpProto::Icmp {
//             if unsafe { (*icmp_block_ptr).get(&1).is_some() } {
//                 // <-- NEW: Send a BlockEvent
//                 let event = BlockEvent {
//                     reason: BlockReason::IcmpBlocked,
//                     pid: 0, // PID is not available in the XDP context
//                     dest_addr: IpAddr::V4(ipv4_hdr.dst_addr()),
//                     dest_port: 0,
//                 };
//                 //unsafe { EVENTS.output(&ctx,&event, 0) };
//                 return Ok(xdp_action::XDP_DROP);
//             }
//         }

//         Ok(xdp_action::XDP_PASS)
//     }();

//     match result {
//         Ok(ret) => ret,
//         Err(_) => xdp_action::XDP_PASS, // On parsing error, better to pass than to drop unexpectedly
//     }
// }

#[classifier] // Replaces primary use of XDP for all incoming packets, uses a map of current connections to implement stateful filtering
pub fn firewall_ingress_tc(ctx: TcContext) -> i32 {
    match try_firewall_ingress_tc(ctx) {
        Ok(ret) => ret,
        Err(_) => {
            TC_ACT_OK // If parsing fails, allow. It means there is no handling for that type of traffic
        }, 
    }
}

fn try_firewall_ingress_tc(ctx: TcContext) -> Result<i32, ()> {

        let result = || -> Result<i32, i32> {
            if let Ok(incoming_tuple) = parse_packet_tuple(&ctx) {
                // For ingress, we need to check for the REVERSE tuple, since we are
                // looking for the return path of an outgoing connection.
                let reversed_tuple = ConnectionTuple {
                    saddr: incoming_tuple.daddr, // Swapped
                    daddr: incoming_tuple.saddr, // Swapped
                    sport: incoming_tuple.dport, // Swapped
                    dport: incoming_tuple.sport, // Swapped
                    protocol: incoming_tuple.protocol,
                    ..incoming_tuple
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
                    // info!(&ctx, "[Kernel] [firewall_ingress_tc]: Tuple not found for: [{} {} {} {} {}]", source_address, destination_address, source_port, destination_port, protocol);
                    return Ok(TC_ACT_SHOT)
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
/*
Down the line, what the plan is is to use cgroup outgoing to check if the application's traffic is allowed
Then use the outgoing TC programs to check for subsequent rules, either for all applications or 
for a specific application.
Why do this? Because at the point of a connect() call, for instance, its so early that port numbers may have
not been assigned. This is an issue that will never occurr at the stage a TC program is triggered
*/


// TEST FUNCTION 
fn app_tracking(prog_name: &str, ctx: &SockAddrContext) {
    //Consider changing these back to safe "ctx.user_ipv" and the like if you can
    let sockaddr_pointer = ctx.sock_addr;
    let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
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

    // Check to see if permissive mode is not enabled
    if let Some(flag_val) = unsafe { PERMISSIVE_MODE_ENABLED.get(0) } {
        if *flag_val == 0 {
            // Check if TGID already exists in map
            if let Some(pid_info) = unsafe { TRUSTED_PIDS.get(&ctx.tgid()) } {
                info!(ctx, "[Kernel] [{}] Trusted PID {} found for {}", prog_name, (ctx.tgid()) as u32, Ipv4Addr::from(u32::from_be(user_ip4)));
                // Build connection key for payload
                let key_to_use = ConnectionKey { saddr: 0, daddr: user_ip4, sport: 0, dport: destination_port, protocol: protocol as u8, _padding: [0; 3]};
                // Insert into again, in case of a trusted process connecting to a new ip address
                if let Err(e) = unsafe { TRUSTED_CONNECTIONS_MAP.insert(&key_to_use, &ctx.tgid(), 0) } {
                    warn!(ctx, "[Kernel] [{}] Failed to insert connection key {}", prog_name, ctx.tgid());
                } else {
                    info!(ctx, "[Kernel] [{}] Successfully inserted connection key {}", prog_name, ctx.tgid());
                }
                return 
            } else { // If it doesn't send event to check application
                // Build connection key for payload
                let key_to_use = ConnectionKey { saddr: 0, daddr: user_ip4, sport: 0, dport: destination_port, protocol: protocol as u8, _padding: [0; 3]};
                // Print key string for debug purposes
                info!(ctx, "[Kernel] [{}] ConnectionKey: {} {} {} {} {}", prog_name, key_to_use.saddr, key_to_use.daddr, key_to_use.sport, key_to_use.dport, key_to_use.protocol as u8);
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
                // Insert into map
                if let Err(e) = unsafe { PENDING_CONNECTIONS_MAP.insert(&key_to_use, &ctx.tgid(), 0) } {
                    warn!(ctx, "[Kernel] [{}] Failed to insert connection key {}", prog_name, ctx.tgid());
                } else {
                    info!(ctx, "[Kernel] [{}] Successfully inserted connection key {}", prog_name, ctx.tgid());
                }
                // Send event for processing
                unsafe { EVENTS.output(ctx, &connection_attempt_event, 0) };
            }
        } else { // Permissive Mode is enabled
            //info!(&ctx, "[Kernel] [firewall_egress_tc] PERMISSIVE MODE ENABLED");
            // Build connection key for payload
            let key_to_use = ConnectionKey { saddr: 0, daddr: user_ip4, sport: 0, dport: destination_port, protocol: protocol as u8, _padding: [0; 3]};
            // Print key string for debug purposes
            info!(ctx, "[Kernel] [{}] ConnectionKey: {} {} {} {} {}", prog_name, key_to_use.saddr, key_to_use.daddr, key_to_use.sport, key_to_use.dport, key_to_use.protocol as u8);
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
            // Send event to userspace to send conn attempt to TUI
            unsafe { EVENTS.output(ctx, &connection_attempt_event, 0) };
        }
    }
}

//END TEST FUNCTION MOVE LATER
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
pub fn firewall_egress_tc(ctx: TcContext) -> i32 { // Change return type to include tuple, and then insert it here
    match try_firewall_egress_tc(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK, // If there is a parsing error, allow the traffic. It means we haven't implemented a way to handle it yet.
    }
}

fn try_firewall_egress_tc(ctx: TcContext) -> Result<i32, ()> {
    // TESTING FOR FLAG SET
    if let Some(flag_val) = unsafe { PERMISSIVE_MODE_ENABLED.get(0) } {
        if *flag_val == 1 {
            //info!(&ctx, "[Kernel] [firewall_egress_tc] PERMISSIVE MODE ENABLED");
            return Ok(TC_ACT_SHOT);
        }
    }
    //END TESTING
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
        info!(&ctx, "[Kernel] [firewall_egress_tc] DHCP ALLOWED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                info!(&ctx, "[Kernel] [firewall_egress_tc]: Adding tuple for DHCP: [{} {} {} {} {}]", debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                let result = unsafe { CONNECTION_MAP.insert(&tuple, &info, 0) };
                if result.is_err() {
                    info!(&ctx, "[Egress] FAILED to insert tuple into map!");
                    return Ok(TC_ACT_SHOT)
                }
                return Ok(TC_ACT_OK);
    }


    // Extract Connection Key for Pending Match
    let incoming_connection_key = ConnectionKey {
        saddr: 0,
        daddr: tuple.daddr,
        sport: 0,
        dport: tuple.dport,
        protocol: tuple.protocol,
        _padding: [0; 3],
     };
     // Print for Debug
     info!(&ctx, "[Kernel] [egress_tc] ConnectionKey: {} {} {} {} {}", debug_saddr, debug_daddr, debug_sport, debug_dport, incoming_connection_key.protocol as u8);
     // Lookup in TRUSTED_CONNECTIONS_MAP
     if let Some(tgid_match) = unsafe { TRUSTED_CONNECTIONS_MAP.get(&incoming_connection_key) } {
        info!(&ctx, "[Kernel] [egress_tc] Trusted Connection for {}, continuing.", *tgid_match);
        // Already approved connection, do nothing
     } else if let Some(tgid_match) = unsafe { PENDING_CONNECTIONS_MAP.get(&incoming_connection_key) } {
        info!(&ctx, "[Kernel] [egress_tc] Pending Connection for {}, checking.", *tgid_match);
        if let Some(pid_info) = unsafe { TRUSTED_PIDS.get(&tgid_match) } {
            if pid_info.action == Action::Allow {
                info!(&ctx, "[Kernel] [egress_tc] Pending Connection Allowed {}", *tgid_match);
            //Let the connection pass
            } else { 
                info!(&ctx, "[Kernel] [egress_tc] Pending Connection Blocked {}", *tgid_match);
                return Ok(TC_ACT_SHOT)
             } // Block the connection
        } else {
            info!(&ctx, "[Kernel] [egress_tc] Pending Connection Blocked, No PID Found.");
            return Ok(TC_ACT_SHOT)
        }
     } else {
        info!(&ctx, "[Kernel] [egress_tc] Connection Not Found in Either Map");
        // Not found in either map, default to block
        return Ok(TC_ACT_SHOT)
     }

    
    
    // This is where you would track the new outgoing connection.
    // TODO: A real implementation would check if this egress is from an approved PID.
    // For now, we'll add any outgoing connection to the map to allow its return traffic.
    

    

    // Get a reference to the RULES hashmap
    let rules_ptr =  core::ptr::addr_of_mut!(RULES);

    // Create keys to check for Rule Match
    // Specific Match
    let full_key = RuleKey {
        protocol: tuple.protocol as u32, // Don't forget about wild card for protocol
        source_port: 0, // Source port is irrelevant in this filter
        dest_port: tuple.dport,
        source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        dest_ip: tuple.daddr,
    };
    // Wildcard port match
    let wildcard_port_key = RuleKey {
        protocol: tuple.protocol as u32, // Don't forget about wild card for protocol
        source_port: 0, // Source port is irrelevant in this filter
        dest_port: 0,
        source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        dest_ip: tuple.daddr,
    };
    // Wildcard IP match
    let wildcard_ip_key = RuleKey {
        protocol: tuple.protocol as u32, // Don't forget about wild card for protocol
        source_port: 0, // Source port is irrelevant in this filter
        dest_port: tuple.dport,
        source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        dest_ip: 0,
    };
    // Wildcard Protocol Match on Dest IP
    let ip_wildcard_proto_key = RuleKey {
        protocol: 0,
        source_port: 0,
        dest_port: 0,
        source_ip: 0,
        dest_ip: tuple.daddr,
    };
    // Wildcard Protocol Match on Dest Port
    let port_wildcard_proto_key = RuleKey {
        protocol: 0,
        source_port: 0,
        dest_port: tuple.dport,
        source_ip: 0,
        dest_ip: 0,
    };
    // Wildcard Protocol Match on Dest IP and Port
    let full_wildcard_proto_key = RuleKey {
        protocol: 0,
        source_port: 0,
        dest_port: tuple.dport,
        source_ip: 0,
        dest_ip: tuple.daddr,
    };
    
    // Create block event to report block
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    //let mut comm = unsafe { bpf_get_current_comm().unwrap() };
    // Create payload to send in KernelEvent
    let block_event_payload = BlockEventPayload {
        key: ConnectionKey {
            sport: tuple.sport,
            dport: tuple.dport,
            protocol: tuple.protocol,
            saddr: tuple.saddr,
            daddr: tuple.daddr,
            _padding: [0; 3],
        },
        reason: BlockReason::IpBlockedEgressTcp,
    };
    let block_event = KernelEvent {
        event_type: EventType::BlockEvent, // Specific event type
        pid: pid_tgid as u32,
        tgid: tgid,
        comm: [0; 16],
        payload: firewhal_kernel_common::KernelEventPayload { block_event: (block_event_payload) }
    };

    

    // ADD TEMP DEBUG PRINT OF FIELDS
    info!(&ctx, "[Kernel] [egress_tc] CHECKING TRAFFIC: [{}:{}, {}:{}]", debug_saddr, debug_sport, debug_daddr, debug_dport);

    // Check all keys
    if let Some(action) = unsafe { (*rules_ptr).get(&full_key) } {
        // New matching 
        match action.action {
            Action::Deny => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} BLOCKED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                unsafe { EVENTS.output(&ctx, &block_event, 0) };
                return Ok(TC_ACT_SHOT); // Block
            }
            Action::Allow => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} ALLOWED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                info!(&ctx, "[Kernel] [firewall_egress_tc]: Adding tuple for related incoming traffic: [{} {} {} {} {}]", debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                let result = unsafe { CONNECTION_MAP.insert(&tuple, &info, 0) };
                if result.is_err() {
                    info!(&ctx, "[Egress] FAILED to insert tuple into map!");
                    return Ok(TC_ACT_SHOT)
                }
                return Ok(TC_ACT_OK);
            }
        }
    } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_port_key) } {
        match action.action {
            Action::Deny => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} BLOCKED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                unsafe { EVENTS.output(&ctx, &block_event, 0) };
                return Ok(TC_ACT_SHOT); // Block
            }
            Action::Allow => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} ALLOWED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                info!(&ctx, "[Kernel] [firewall_egress_tc]: Adding tuple for related incoming traffic: [{} {} {} {} {}]", debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                let result = unsafe { CONNECTION_MAP.insert(&tuple, &info, 0) };
                if result.is_err() {
                    info!(&ctx, "[Egress] FAILED to insert tuple into map!");
                    return Ok(TC_ACT_SHOT)
                }
                return Ok(TC_ACT_OK);
            }
        }
    } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_ip_key) } {
        match action.action {
            Action::Deny => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} BLOCKED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                unsafe { EVENTS.output(&ctx, &block_event, 0) };
                return Ok(TC_ACT_SHOT); // Block
            }
            Action::Allow => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} ALLOWED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                info!(&ctx, "[Kernel] [firewall_egress_tc]: Adding tuple for related incoming traffic: [{} {} {} {} {}]", debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                let result = unsafe { CONNECTION_MAP.insert(&tuple, &info, 0) };
                if result.is_err() {
                    info!(&ctx, "[Egress] FAILED to insert tuple into map!");
                    return Ok(TC_ACT_SHOT)
                }
                return Ok(TC_ACT_OK);
            }
        }
    } else if let Some(action) = unsafe { (*rules_ptr).get(&ip_wildcard_proto_key) } {
        match action.action {
            Action::Deny => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} BLOCKED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                unsafe { EVENTS.output(&ctx, &block_event, 0) };
                return Ok(TC_ACT_SHOT); // Block
            }
            Action::Allow => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} ALLOWED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                info!(&ctx, "[Kernel] [firewall_egress_tc]: Adding tuple for related incoming traffic: [{} {} {} {} {}]", debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                let result = unsafe { CONNECTION_MAP.insert(&tuple, &info, 0) };
                if result.is_err() {
                    info!(&ctx, "[Egress] FAILED to insert tuple into map!");
                    return Ok(TC_ACT_SHOT)
                }
                return Ok(TC_ACT_OK);
            }
        }
    } else if let Some(action) = unsafe { (*rules_ptr).get(&port_wildcard_proto_key) } {
        match action.action {
            Action::Deny => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} BLOCKED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                unsafe { EVENTS.output(&ctx, &block_event, 0) };
                return Ok(TC_ACT_SHOT); // Block
            }
            Action::Allow => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} ALLOWED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                info!(&ctx, "[Kernel] [firewall_egress_tc]: Adding tuple for related incoming traffic: [{} {} {} {} {}]", debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                let result = unsafe { CONNECTION_MAP.insert(&tuple, &info, 0) };
                if result.is_err() {
                    info!(&ctx, "[Egress] FAILED to insert tuple into map!");
                    return Ok(TC_ACT_SHOT)
                }
                return Ok(TC_ACT_OK);
            }
        }
    } else if let Some(action) = unsafe { (*rules_ptr).get(&full_wildcard_proto_key) } {
        match action.action {
            Action::Deny => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} BLOCKED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                unsafe { EVENTS.output(&ctx, &block_event, 0) };
                return Ok(TC_ACT_SHOT); // Block
            }
            Action::Allow => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} ALLOWED connection Source: {}:{}, Destination: {}:{}, Protocol: {}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                info!(&ctx, "[Kernel] [firewall_egress_tc]: Adding tuple for related incoming traffic: [{} {} {} {} {}]", debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                let result = unsafe { CONNECTION_MAP.insert(&tuple, &info, 0) };
                if result.is_err() {
                    info!(&ctx, "[Egress] FAILED to insert tuple into map!");
                    return Ok(TC_ACT_SHOT)
                }
                return Ok(TC_ACT_OK);
            }
        }
    }

    Ok(TC_ACT_SHOT) // Default: Block All 
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}