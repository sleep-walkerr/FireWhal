/*
Define IPv4 address via u32::from_be_bytes([192, 168, 1, 2])
*/


#![no_std]
#![no_main]

use core::{iter::Cloned, mem};

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{cgroup_skb, cgroup_sock_addr, map, xdp},
    maps::HashMap,
    programs::{SkBuffContext, SockAddrContext, XdpContext},
    EbpfContext,
};
use aya_log_ebpf::info;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static mut PORT_BLOCKLIST: HashMap<u16, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static mut ICMP_BLOCK_ENABLED: HashMap<u8, u8> = HashMap::with_max_entries(1, 0);

// #[xdp]
// pub fn firewhal_xdp(ctx: XdpContext) -> u32 {
//     let result = || -> Result<u32, ()> {
//         // To parse packet data in XDP, we work with pointers to the start and
//         // end of the packet buffer. This is a robust way to handle packet data
//         // that works across aya-ebpf versions.
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
//         let icmp_block_ptr = unsafe { core::ptr::addr_of_mut!(ICMP_BLOCK_ENABLED) };
//         if ipv4_hdr.proto == IpProto::Icmp {
//             if unsafe { (*icmp_block_ptr).get(&1).is_some() } {
//                 info!(&ctx, "XDP: BLOCKED incoming ICMP packet");
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

#[cgroup_skb(ingress)]
pub fn firewhal_ingress(ctx: SkBuffContext) -> i32 {
    let result = || -> Result<i32, i64> {
        // NEW CODE ****
        // let skbuff_ptr = ctx.skb;
        // let user_ip4 = skbuff_ptr.local_ipv4();
        // let user_port = skbuff_ptr.local_port();
        
        if u32::from_be(ctx.skb.local_port()) != u32::from_be(22) {
            info!(
            &ctx,
            "Ingress Processing: remote ipv4 {:i}, remote port {}, local ipv4 {:i}, local port {}",
            u32::from_be(ctx.skb.remote_ipv4()), u32::from_be(ctx.skb.remote_port()), u32::from_be(ctx.skb.local_ipv4()), u32::from(ctx.skb.local_port()) // still not sure about whether I should be casting the port as a u16 but this seems to be working for now
            );
        }

        


        // // Parse Ethernet header
        // let eth_hdr: EthHdr = ctx.load(0)?;
        // if !matches!(eth_hdr.ether_type, EtherType::Ipv4) {
        //     return Ok(1); // Not an IPv4 packet, let it pass
        // }

        // // Parse IPv4 header
        // let ipv4_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN)?;
        // // Parse L4 headers for TCP and UDP to get the destination port
        // let dest_port = match ipv4_hdr.proto {
        //     IpProto::Tcp => {
        //         let tcp_hdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN)?;
        //         // Correctly parse the TCP port using from_be_bytes.
        //         u16::from_be(tcp_hdr.dest)
        //     }
        //     IpProto::Udp => {
        //         let udp_hdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN)?;
        //         u16::from_be_bytes(udp_hdr.dest)
        //     }
        //     _ => return Ok(1),
        // };

        

        // // Check if the destination port is in our blocklist
        // let port_blocklist_ptr = unsafe { core::ptr::addr_of_mut!(PORT_BLOCKLIST) };
        // if unsafe { (*port_blocklist_ptr).get(&dest_port).is_some() } {
        //     info!(
        //         &ctx,
        //         "Cgroup Ingress: BLOCKED incoming packet to port {}", dest_port
        //     );
        //     return Ok(0); // Drop the packet *** modified from TC_ACT_SHOT
        // }

        Ok(1) // Allow the packet
    }(); // Immediately execute the closure

    match result {
        Ok(ret) => ret,
        Err(_) => 0, // On any parsing error, pass the packet. It's safer.
    }
}

// #[cgroup_sock_addr(connect4)]
// pub fn firewhal_egress(ctx: SockAddrContext) -> i32 {
//     let result = || -> Result<i32, i32> {
//         let sockaddr_pointer = ctx.sock_addr;
//         let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
//         let user_port = unsafe { (*sockaddr_pointer).user_port };
//         let dest_ip_host = u32::from_be(user_ip4); // This conversion is correct for the IP.
//         let dest_port_host = (u32::from_be(user_port) >> 16) as u16;
//         info!(
//             &ctx,
//             "Attempting to connect to address: {:i}, port: {}",
//             dest_ip_host, dest_port_host,
//         );

//         // The BLOCKLIST map stores keys in network byte order, so we use the original value.
//         let dest_addr = user_ip4;
//         let blocklist_ptr = unsafe { core::ptr::addr_of_mut!(BLOCKLIST) };
//         if unsafe { (*blocklist_ptr).get(&dest_addr).is_some() } {
//             let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
//             info!(&ctx, "Cgroup Egress: BLOCKED PID {}, dest addr {}", pid, dest_addr);
//             return Ok(0); // Block the connection
//         }

//         Ok(1) // Allow the connection
//     }();

//     match result {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }



#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}