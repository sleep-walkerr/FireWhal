/*
Define IPv4 address via u32::from_be_bytes([192, 168, 1, 2])
*/

#![no_std]
#![no_main]

use core::{hash::Hash, mem, net::{IpAddr,Ipv4Addr}};

use aya_ebpf::{
    bindings::{sockaddr, xdp_action, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{cgroup_sock_addr, classifier, map, xdp},
    maps::{HashMap, LpmTrie, PerfEventArray, RingBuf, LruHashMap}, // <-- NEW: Import RingBuf
    programs::{tc, SockAddrContext, TcContext, XdpContext}, EbpfContext, 
};
use aya_log_ebpf::{info, error, warn};

use firewhal_kernel_common::{BlockEvent, BlockReason, RuleKey, RuleAction, Action, LpmIpKey, ConnectionTuple, ConnectionInfo, parse_packet_tuple};

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


// NEW MAPS
#[map]
static mut EVENTS: PerfEventArray<BlockEvent> = PerfEventArray::new(0);

#[map]
static mut RULES: HashMap<RuleKey, RuleAction> = HashMap::with_max_entries(1024, 0);

#[map] // Connection Tracking Map for Stateful
static mut CONNECTION_MAP: LruHashMap<ConnectionTuple, ConnectionInfo> =
    LruHashMap::with_max_entries(4096, 0);

// The following maps were for the map-in-map implementation and are no longer needed.
//
// #[map]
// static mut PROTOCOL_RULES: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);
// #[map(pinned)]
// static mut PORT_RULES_TEMPLATE: HashMap<u16, u32> = HashMap::with_max_entries(256, 0);
// #[map(pinned)]
// static mut IP_RULES_TEMPLATE: LpmTrie<LpmIpKey, RuleAction> = LpmTrie::with_max_entries(1024, 0);

// INGRESS PROGRAMS
#[xdp]
pub fn firewhal_xdp(ctx: XdpContext) -> u32 {
    let result = || -> Result<u32, ()> {
        let data_end = ctx.data_end();
        let data_start = ctx.data();

        // We manually track the offset as we parse headers.
        let mut offset = 0;

        // Load Ethernet header. All pointer operations are unsafe and must be
        // enclosed in an unsafe block. The bounds check is what makes this
        // operation safe.
        let eth_hdr: EthHdr = unsafe {
            let ptr = (data_start as *const u8).add(offset) as *const EthHdr;
            if (ptr as *const u8).add(mem::size_of::<EthHdr>()) > (data_end as *const u8) {
                return Err(());
            }
            *ptr
        };
        offset += mem::size_of::<EthHdr>();

        if !matches!(eth_hdr.ether_type, EtherType::Ipv4) {
            return Ok(xdp_action::XDP_PASS);
        }

        // Load IPv4 header.
        let ipv4_hdr: Ipv4Hdr = unsafe {
            let ptr = (data_start as *const u8).add(offset) as *const Ipv4Hdr;
            if (ptr as *const u8).add(mem::size_of::<Ipv4Hdr>()) > (data_end as *const u8) {
                return Err(());
            }
            *ptr
        };
        let icmp_block_ptr = core::ptr::addr_of_mut!(ICMP_BLOCK_ENABLED);
        
        if ipv4_hdr.proto == IpProto::Icmp {
            if unsafe { (*icmp_block_ptr).get(&1).is_some() } {
                // <-- NEW: Send a BlockEvent
                let event = BlockEvent {
                    reason: BlockReason::IcmpBlocked,
                    pid: 0, // PID is not available in the XDP context
                    dest_addr: IpAddr::V4(ipv4_hdr.dst_addr()),
                    dest_port: 0,
                };
                unsafe { EVENTS.output(&ctx,&event, 0) };
                return Ok(xdp_action::XDP_DROP);
            }
        }

        Ok(xdp_action::XDP_PASS)
    }();

    match result {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS, // On parsing error, better to pass than to drop unexpectedly
    }
}

#[classifier] // Replaces primary use of XDP for all incoming packets, uses a map of current connections to implement stateful filtering
pub fn firewall_ingress_tc(ctx: TcContext) -> i32 {
    match try_firewall_ingress_tc(ctx) {
        Ok(ret) => ret,
        Err(_) => {
            TC_ACT_SHOT
        }, // Default to drop if parsing fails
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
                    info!(&ctx, "[Kernel] [firewall_ingress_tc]: Tuple not found for: [{} {} {} {} {}]", source_address, destination_address, source_port, destination_port, protocol);
                    return Ok(TC_ACT_SHOT)
                }
            } else {
                info!(&ctx, "[Kernel] [firewall_ingress_tc]: Parsing error");
                return Err(TC_ACT_SHOT)
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
#[cgroup_sock_addr(connect4)]
pub fn firewhal_egress_connect4(ctx: SockAddrContext) -> i32 {
    let result = || -> Result<i32, i32> {
        // //Consider changing these back to safe "ctx.user_ipv" and the like if you can
        // let pid = ctx.pid();
        // let sockaddr_pointer = ctx.sock_addr;
        // let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
        // let user_port = unsafe { (*sockaddr_pointer).user_port }; 
        // let protocol = unsafe { (*sockaddr_pointer).protocol };

        // //Ports are u32 instead of u16 because src and dst are stored into one value for efficiency
        // // They need to be converted to be used first
        // let source_port = unsafe { ((*sockaddr_pointer).user_port) as u16};
        // let destination_port = (u32::from_be(user_port) >> 16) as u16;


        // //Convert to readable format for error logging
        // let user_ip_converted = Ipv4Addr::from(u32::from_be(user_ip4));
        // let user_port_converted = (u32::from_be(user_port) >> 16) as u16;
        
        // // Get a reference to the RULES hashmap
        // let rules_ptr =  core::ptr::addr_of_mut!(RULES);

        // // Create keys to check for Rule Match
        // // Specific Match
        // let full_key = RuleKey {
        //     protocol: protocol, // Don't forget about wild card for protocol
        //     source_port: 0, // Source port is irrelevant in this filter
        //     dest_port: destination_port,
        //     source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        //     dest_ip: user_ip4,
        // };
        // // Wildcard port match
        // let wildcard_port_key = RuleKey {
        //     protocol: protocol, // Don't forget about wild card for protocol
        //     source_port: 0, // Source port is irrelevant in this filter
        //     dest_port: 0,
        //     source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        //     dest_ip: user_ip4,
        // };
        // // Wildcard IP match
        // let wildcard_ip_key = RuleKey {
        //     protocol: protocol, // Don't forget about wild card for protocol
        //     source_port: 0, // Source port is irrelevant in this filter
        //     dest_port: destination_port,
        //     source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        //     dest_ip: 0,
        // };
        // // Create block event to report block
        // let block_report_event = BlockEvent {
        //     reason: BlockReason::IpBlockedEgressUdp,
        //     pid: ctx.pid(),
        //     dest_addr:IpAddr::V4(Ipv4Addr::from(user_ip4.to_be())),
        //     dest_port: user_port_converted,
        // };
        // // Check all keys
        // if let Some(action) = unsafe { (*rules_ptr).get(&full_key) } {
        //     // New matching 
        //     match action.action {
        //         Action::Deny => {
        //             info!(&ctx, "[Kernel] [connect4] Rule {} blocked connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
        //             return Ok(0); // Block
        //         }
        //         Action::Allow => {
        //             // info!(&ctx, "[Kernel] [connect4] Rule {} allowed connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             return Ok(1);
        //         }
        //     }
        // } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_port_key) } {
        //     match action.action {
        //         Action::Deny => {
        //             info!(&ctx, "[Kernel] [connect4] Rule {} blocked connection to IP {}, port {}", action.rule_id, user_ip_converted, user_port_converted);
        //             unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
        //             return Ok(0); // Block
        //         }
        //         Action::Allow => {
        //             // info!(&ctx, "[Kernel] [connect4] Rule {} allowed connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             return Ok(1);
        //         }
        //     }
        // } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_ip_key) } {
        //     match action.action {
        //         Action::Deny => {
        //             info!(&ctx, "[Kernel] [connect4] Rule {} blocked connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
        //             return Ok(0); // Block
        //         }
        //         Action::Allow => {
        //             // info!(&ctx, "[Kernel] [connect4] Rule {} allowed connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             return Ok(1);
        //         }
        //     }
        // }
        // // Print all allowed traffic
        // info!(&ctx, "[Kernel] [connect4] BLOCKED connection to IP {}, Destination Port {}, Protocol {}, Source Port {}", user_ip_converted, destination_port, protocol, source_port);
        
        Ok(1) // Allow the connection for now, blocking delegated to tc egress program
    }();

    match result {
        Ok(ret) => ret,
        Err(ret) => {
            info!(&ctx, "[Kernel] [connect4] Failed to process packet.");
            ret
        },
    }
}



#[cgroup_sock_addr(sendmsg4)]
pub fn firewhal_egress_sendmsg4(ctx: SockAddrContext) -> i32 {
    let result = || -> Result<i32, i32> {
        // //Consider changing these back to safe "ctx.user_ipv" and the like if you can
        // let pid = ctx.pid();
        // let sockaddr_pointer = ctx.sock_addr;
        // let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
        // let user_port = unsafe { (*sockaddr_pointer).user_port }; 
        // let protocol = unsafe { (*sockaddr_pointer).protocol };

        // //Ports are u32 instead of u16 because src and dst are stored into one value for efficiency
        // // They need to be converted to be used first
        // let source_port = unsafe { ((*sockaddr_pointer).user_port) as u16};
        // let destination_port = (u32::from_be(user_port) >> 16) as u16;


        // //Convert to readable format for error logging
        // let user_ip_converted = Ipv4Addr::from(u32::from_be(user_ip4));
        // let user_port_converted = (u32::from_be(user_port) >> 16) as u16;
        
        // // Get a reference to the RULES hashmap
        // let rules_ptr =  core::ptr::addr_of_mut!(RULES);

        // // Create keys to check for Rule Match
        // // Specific Match
        // let full_key = RuleKey {
        //     protocol: protocol, // Don't forget about wild card for protocol
        //     source_port: 0, // Source port is irrelevant in this filter
        //     dest_port: destination_port,
        //     source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        //     dest_ip: user_ip4,
        // };
        // // Wildcard port match
        // let wildcard_port_key = RuleKey {
        //     protocol: protocol, // Don't forget about wild card for protocol
        //     source_port: 0, // Source port is irrelevant in this filter
        //     dest_port: 0,
        //     source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        //     dest_ip: user_ip4,
        // };
        // // Wildcard IP match
        // let wildcard_ip_key = RuleKey {
        //     protocol: protocol, // Don't forget about wild card for protocol
        //     source_port: 0, // Source port is irrelevant in this filter
        //     dest_port: destination_port,
        //     source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        //     dest_ip: 0,
        // };
        // // Create block event to report block
        // let block_report_event = BlockEvent {
        //     reason: BlockReason::IpBlockedEgressUdp,
        //     pid: ctx.pid(),
        //     dest_addr:IpAddr::V4(Ipv4Addr::from(user_ip4.to_be())),
        //     dest_port: user_port_converted,
        // };
        // // Check all keys
        // if let Some(action) = unsafe { (*rules_ptr).get(&full_key) } {
        //     // New matching 
        //     match action.action {
        //         Action::Deny => {
        //             info!(&ctx, "[Kernel] [sendmsg4] Rule {} blocked connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
        //             return Ok(0); // Block
        //         }
        //         Action::Allow => {
        //             // info!(&ctx, "[Kernel] [sendmsg4] Rule {} allowed connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             return Ok(1);
        //         }
        //     }
        // } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_port_key) } {
        //     match action.action {
        //         Action::Deny => {
        //             info!(&ctx, "[Kernel] [sendmsg4] Rule {} blocked connection to IP {}, port {}", action.rule_id, user_ip_converted, user_port_converted);
        //             unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
        //             return Ok(0); // Block
        //         }
        //         Action::Allow => {
        //             // info!(&ctx, "[Kernel] [sendmsg4] Rule {} allowed connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             return Ok(1);
        //         }
        //     }
        // } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_ip_key) } {
        //     match action.action {
        //         Action::Deny => {
        //             info!(&ctx, "[Kernel] [sendmsg4] Rule {} blocked connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
        //             return Ok(0); // Block
        //         }
        //         Action::Allow => {
        //             // info!(&ctx, "[Kernel] [sendmsg4] Rule {} allowed connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             return Ok(1);
        //         }
        //     }
        // }
        // // Print all blocked traffic
        // info!(&ctx, "[Kernel] [sendmsg4] BLOCKED connection to IP {}, Destination Port {}, Protocol {}, Source Port {}", user_ip_converted, destination_port, protocol, source_port);
        
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
        // //Consider changing these back to safe "ctx.user_ipv" and the like if you can
        // let pid = ctx.pid();
        // let sockaddr_pointer = ctx.sock_addr;
        // let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
        // let dest_ip4 = unsafe { (*sockaddr_pointer).msg_src_ip4 };
        // let user_port = unsafe { (*sockaddr_pointer).user_port }; 
        // let protocol = unsafe { (*sockaddr_pointer).protocol };

        // //Ports are u32 instead of u16 because src and dst are stored into one value for efficiency
        // // They need to be converted to be used first
        // let source_port = unsafe { ((*sockaddr_pointer).user_port) as u16};
        // let destination_port = (u32::from_be(user_port) >> 16) as u16;


        // //Convert to readable format for error logging
        // let user_ip_converted = Ipv4Addr::from(u32::from_be(user_ip4));
        // let dest_ip_converted = Ipv4Addr::from(u32::from_be(dest_ip4));
        // let user_port_converted = (u32::from_be(user_port) >> 16) as u16;
        
        // // Get a reference to the RULES hashmap
        // let rules_ptr =  core::ptr::addr_of_mut!(RULES);

        // // Create keys to check for Rule Match
        // // Specific Match
        // let full_key = RuleKey {
        //     protocol: protocol, // Don't forget about wild card for protocol
        //     source_port: 0, // Source port is irrelevant in this filter
        //     dest_port: destination_port,
        //     source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        //     dest_ip: user_ip4,
        // };
        // // Wildcard port match
        // let wildcard_port_key = RuleKey {
        //     protocol: protocol, // Don't forget about wild card for protocol
        //     source_port: 0, // Source port is irrelevant in this filter
        //     dest_port: 0,
        //     source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        //     dest_ip: user_ip4,
        // };
        // // Wildcard IP match
        // let wildcard_ip_key = RuleKey {
        //     protocol: protocol, // Don't forget about wild card for protocol
        //     source_port: 0, // Source port is irrelevant in this filter
        //     dest_port: destination_port,
        //     source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
        //     dest_ip: 0,
        // };
        // // Create block event to report block
        // let block_report_event = BlockEvent {
        //     reason: BlockReason::IpBlockedEgressUdp,
        //     pid: ctx.pid(),
        //     dest_addr:IpAddr::V4(Ipv4Addr::from(user_ip4.to_be())),
        //     dest_port: user_port_converted,
        // };
        // // Check all keys
        // if let Some(action) = unsafe { (*rules_ptr).get(&full_key) } {
        //     // New matching 
        //     match action.action {
        //         Action::Deny => {
        //             info!(&ctx, "[Kernel] [bind4] Rule {} blocked connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
        //             return Ok(0); // Block
        //         }
        //         Action::Allow => {
        //             // info!(&ctx, "[Kernel] [bind4] Rule {} allowed connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             return Ok(1);
        //         }
        //     }
        // } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_port_key) } {
        //     match action.action {
        //         Action::Deny => {
        //             info!(&ctx, "[Kernel] [bind4] Rule {} blocked connection to IP {}, port {}", action.rule_id, user_ip_converted, user_port_converted);
        //             unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
        //             return Ok(0); // Block
        //         }
        //         Action::Allow => {
        //             // info!(&ctx, "[Kernel] [bind4] Rule {} allowed connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             return Ok(1);
        //         }
        //     }
        // } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_ip_key) } {
        //     match action.action {
        //         Action::Deny => {
        //             info!(&ctx, "[Kernel] [bind4] Rule {} blocked connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
        //             return Ok(0); // Block
        //         }
        //         Action::Allow => {
        //             // info!(&ctx, "[Kernel] [bind4] Rule {} allowed connection to IP {}, port {}, protocol {}", action.rule_id, user_ip_converted, user_port_converted, protocol);
        //             return Ok(1);
        //         }
        //     }
        // }
        // // Print all blocked traffic
        // info!(&ctx, "[Kernel] [bind4] BLOCKED connection User IP {}, Destination IP {}, Destination Port {}, Protocol {}, Source Port {}", user_ip_converted, dest_ip_converted, destination_port, protocol, source_port);
        
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
pub fn firewall_egress_tc(ctx: TcContext) -> i32 {
    match try_firewall_egress_tc(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_firewall_egress_tc(ctx: TcContext) -> Result<i32, ()> {
    let mut tuple = parse_packet_tuple(&ctx)?;
    
    // This is where you would track the new outgoing connection.
    // TODO: A real implementation would check if this egress is from an approved PID.
    // For now, we'll add any outgoing connection to the map to allow its return traffic.
    let info = ConnectionInfo {
        pid: 0, // In TC we don't know the PID, this would be set by the cgroup program
        last_seen: unsafe { bpf_ktime_get_ns() },
    };
    // Check to see if broadcast for DHCP
    if tuple.saddr == Ipv4Addr::from([0,0,0,0]).into() && tuple.daddr == Ipv4Addr::from([255,255,255,255]).into() {
        let broadcast_rule = ConnectionTuple {
        saddr: 0,
        daddr: 0,
        sport: tuple.sport,
        dport: tuple.dport,
        protocol: tuple.protocol,
        _pad: [0; 3],
        };
        tuple = broadcast_rule;
    }
    
    let result = unsafe { CONNECTION_MAP.insert(&tuple, &info, 0) };
    if result.is_err() {
        info!(&ctx, "[Egress] FAILED to insert tuple into map!");
        return Ok(TC_ACT_SHOT)
    }

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
    // Create block event to report block
    let block_report_event = BlockEvent {
        reason: BlockReason::IpBlockedEgressUdp,
        pid: ctx.pid(),
        dest_addr:IpAddr::V4(Ipv4Addr::from(tuple.daddr.to_be())),
        dest_port: tuple.sport,
    };

    // Create debug printing fields
    let debug_saddr = Ipv4Addr::from(u32::from_be(tuple.saddr));
    let debug_daddr = Ipv4Addr::from(u32::from_be(tuple.daddr));
    let debug_sport = tuple.sport;
    let debug_dport = tuple.dport;
    let debug_protocol = tuple.protocol;
    // Check all keys
    if let Some(action) = unsafe { (*rules_ptr).get(&full_key) } {
        // New matching 
        match action.action {
            Action::Deny => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} BLOCKED connection Source: {}:{}, Destination: {}:{}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
                return Ok(TC_ACT_SHOT); // Block
            }
            Action::Allow => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} ALLOWED connection Source: {}:{}, Destination: {}:{}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                return Ok(TC_ACT_OK);
            }
        }
    } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_port_key) } {
        match action.action {
            Action::Deny => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} BLOCKED connection Source: {}:{}, Destination: {}:{}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
                return Ok(TC_ACT_SHOT); // Block
            }
            Action::Allow => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} ALLOWED connection Source: {}:{}, Destination: {}:{}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                return Ok(TC_ACT_OK);
            }
        }
    } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_ip_key) } {
        match action.action {
            Action::Deny => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} BLOCKED connection Source: {}:{}, Destination: {}:{}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
                return Ok(TC_ACT_SHOT); // Block
            }
            Action::Allow => {
                info!(&ctx, "[Kernel] [firewall_egress_tc] Rule {} ALLOWED connection Source: {}:{}, Destination: {}:{}", action.rule_id, debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);
                return Ok(TC_ACT_OK);
            }
        }
    }

    info!(&ctx, "[Kernel] [firewall_egress_tc]: Adding tuple for related incoming traffic: [{} {} {} {} {}]", debug_saddr, debug_sport, debug_daddr, debug_dport, tuple.protocol);

    Ok(TC_ACT_OK) // Allow all traffic for now
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}