/*
Define IPv4 address via u32::from_be_bytes([192, 168, 1, 2])
*/

#![no_std]
#![no_main]

use core::{mem, net::{IpAddr,Ipv4Addr}};

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_get_current_pid_tgid,
    macros::{cgroup_sock_addr, map, xdp},
    maps::{HashMap, PerfEventArray, RingBuf}, // <-- NEW: Import RingBuf
    programs::{SockAddrContext, XdpContext}, EbpfContext,
};
use aya_log_ebpf::info;

use firewhal_kernel_common::{BlockEvent, BlockReason, RuleKey, RuleAction, Action};

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
static mut EVENTS: PerfEventArray<BlockEvent> = PerfEventArray::new(0);


#[map]
static mut RULES: HashMap<RuleKey, RuleAction> = HashMap::with_max_entries(1024, 0);

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

#[cgroup_sock_addr(recvmsg4)]
pub fn firewhal_ingress_recvmsg4(ctx: SockAddrContext) -> i32 {
    let result = || -> Result<i32, i32> {
        let sockaddr_pointer = ctx.sock_addr;
        let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
        let user_port = unsafe { (*sockaddr_pointer).user_port };

        // Convert to readable format
        let user_ip_converted = u32::from_be(user_ip4);
        let user_port_converted = (u32::from_be(user_port) >> 16) as u16;

        Ok(1)
        }();

    match result {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// EGRESS PROGRAMS
#[cgroup_sock_addr(connect4)]
pub fn firewhal_egress_connect4(ctx: SockAddrContext) -> i32 {
    let result = || -> Result<i32, i32> {
        //Consider changing these back to safe "ctx.user_ipv" and the like if you can
        let sockaddr_pointer = ctx.sock_addr;
        let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
        let user_port = unsafe { (*sockaddr_pointer).user_port }; 
        let protocol = unsafe { (*sockaddr_pointer).protocol };

        //Ports are u32 instead of u16 because src and dst are stored into one value for efficiency
        // They need to be converted to be used first
        let source_port = unsafe { ((*sockaddr_pointer).user_port) as u16};
        let destination_port = unsafe { ((*sockaddr_pointer).user_port >> 16) as u16};


        //Convert to readable format for error logging
        let user_ip_converted = Ipv4Addr::from(u32::from_be(user_ip4));
        let user_port_converted = (u32::from_be(user_port) >> 16) as u16;
        
        // Get a reference to the RULES hashmap
        let rules_ptr =  core::ptr::addr_of_mut!(RULES);

        // Create keys to check for block
        // Specific Match
        let full_key = RuleKey {
            protocol: protocol, // Don't forget about wild card for protocol
            source_port: 0, // Source port is irrelevant in this filter
            dest_port: destination_port,
            source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
            dest_ip: user_ip4,
        };
        // Wildcard port match
        let wildcard_port_key = RuleKey {
            protocol: protocol, // Don't forget about wild card for protocol
            source_port: 0, // Source port is irrelevant in this filter
            dest_port: 0,
            source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
            dest_ip: user_ip4,
        };
        // Wildcard IP match
        let wildcard_ip_key = RuleKey {
            protocol: protocol, // Don't forget about wild card for protocol
            source_port: 0, // Source port is irrelevant in this filter
            dest_port: destination_port,
            source_ip: 0, // src is available in ingress programs, not egress since we already know its from us
            dest_ip: 0,
        };
        // Create block event to report block
        let block_report_event = BlockEvent {
            reason: BlockReason::IpBlockedEgressUdp,
            pid: ctx.pid(),
            dest_addr:IpAddr::V4(Ipv4Addr::from(user_ip4.to_be())),
            dest_port: user_port_converted,
        };
        // Check all keys
        if let Some(action) = unsafe { (*rules_ptr).get(&full_key) } {
            if matches!(action.action, Action::Block) {
                info!(&ctx, "Rule {} blocked connection to IP {}, port {}", action.rule_id, user_ip_converted, user_port_converted);
                unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
                return Ok(0); // Block
            }
        } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_port_key) } {
            if matches!(action.action, Action::Block) {
                info!(&ctx, "Rule {} blocked connection to IP {}, port {}", action.rule_id, user_ip_converted, user_port_converted);
                unsafe { EVENTS.output(&ctx, &block_report_event, 0) } {
                return Ok(0); // Block
            }
        } else if let Some(action) = unsafe { (*rules_ptr).get(&wildcard_ip_key) } {
            if matches!(action.action, Action::Block) {
                info!(&ctx, "Rule {} blocked connection to IP {}, port {}", action.rule_id, user_ip_converted, user_port_converted);
                unsafe { EVENTS.output(&ctx, &block_report_event, 0) } 

                return Ok(0); // Block
            }
        }
    }
        Ok(1) // Allow the connection
    }();

    match result {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}



#[cgroup_sock_addr(sendmsg4)]
pub fn firewhal_egress_sendmsg4(ctx: SockAddrContext) -> i32 {
    let result = || -> Result<i32, i32> {
        let sockaddr_pointer = ctx.sock_addr;
        let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
        let user_port = unsafe { (*sockaddr_pointer).user_port };
        let dest_ip_host = u32::from_be(user_ip4);
        let dest_port_host = (u32::from_be(user_port) >> 16) as u16;
        // info!(
        //     &ctx,
        //     "UDP EGRESS Connection Attempt to: {}, port: {}",
        //     dest_ip_host, dest_port_host,
        // );

        let dest_addr = user_ip4;
        let blocklist_ptr = core::ptr::addr_of_mut!(BLOCKLIST);
        if unsafe { (*blocklist_ptr).get(&dest_addr).is_some() } {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let block_report_event = BlockEvent {
                reason: BlockReason::IpBlockedEgressUdp,
                pid: ctx.pid(),
                dest_addr:IpAddr::V4(Ipv4Addr::from(dest_addr.to_be())),
                dest_port: dest_port_host,
            };
            unsafe { EVENTS.output(&ctx, &block_report_event, 0) };
            // info!(&ctx, "Cgroup Egress: BLOCKED PID {}, dest addr {}", pid, dest_addr);
            return Ok(0); // Block the connection
        }

        Ok(1) // Allow the connection
    }();

    match result {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}


#[cgroup_sock_addr(bind4)]
pub fn firewhal_egress_bind4(ctx: SockAddrContext) -> i32 {
let result = || -> Result<i32, i32> {
        let sockaddr_pointer = ctx.sock_addr;
        let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
        let user_port = unsafe { (*sockaddr_pointer).user_port };
        let dest_ip_host = u32::from_be(user_ip4);
        let dest_port_host = (u32::from_be(user_port) >> 16) as u16;
        // info!(
        //     &ctx,
        //     "UDP EGRESS Connection Attempt to: {}, port: {}",
        //     dest_ip_host, dest_port_host,
        // );

        let dest_addr = user_ip4;
        let blocklist_ptr = core::ptr::addr_of_mut!(BLOCKLIST);
        if unsafe { (*blocklist_ptr).get(&dest_addr).is_some() } {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

            let block_event_message = BlockEvent {
                reason : BlockReason::BindBlocked,
                pid: ctx.pid(),
                dest_addr:IpAddr::V4(Ipv4Addr::from(dest_addr.to_be())),
                dest_port: dest_port_host,
            };
            unsafe { EVENTS.output(&ctx, &block_event_message, 0) };

            info!(&ctx, "Cgroup Egress: BLOCKED PID {}, dest addr {}", pid, dest_addr);
            return Ok(0); // Block the connection
        }

        Ok(1) // Allow the connection
    }();

    match result {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}