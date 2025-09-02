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
static mut PORT_BLOCKLIST: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static mut ICMP_BLOCK_ENABLED: HashMap<u8, u8> = HashMap::with_max_entries(1, 0);

// INGRESS PROGRAMS

/*
This programs job is to do basic filtering based on IP addresses and ports. Having the allow\block rules be modified from the cgroup_sock_addr egress programs for stateful packet filtering is ideal.
Ideally everything goes through XDP as it is the most performant, which is why I will try to follow the model of relying on XDP as much as possible, primarily using the cgroup_sock_addr programs to manage XDP rules. 

Next step: 
use this program to parse source and destination ip addresses and ports, and maybe mac addresses too
*/
#[xdp]
pub fn firewhal_xdp(ctx: XdpContext) -> u32 {
    let result = || -> Result<u32, ()> {
        // To parse packet data in XDP, we work with pointers to the start and
        // end of the packet buffer. This is a robust way to handle packet data
        // that works across aya-ebpf versions.



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
        let icmp_block_ptr = unsafe { core::ptr::addr_of_mut!(ICMP_BLOCK_ENABLED) };
        
        // Add basic print statement for all packets 
        info!(
            &ctx,
            "XDP: Source:[{}], Destination: [{}], Protocol: {}",
            ipv4_hdr.src_addr(),
            ipv4_hdr.dst_addr(),
            ipv4_hdr.proto as u8
        );


        if ipv4_hdr.proto == IpProto::Icmp {
            if unsafe { (*icmp_block_ptr).get(&1).is_some() } {
                info!(&ctx, "XDP: BLOCKED incoming ICMP packet");
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

/*
THIS PROGRAM IS BEING REPLACED BY A cgroup_sock_addr(recvmsg4) program due to its inability to process UDP packets
This program is included for the stateful aspect of the firewall. After applications have been approved via path and hash for outgoing traffic, their incoming traffic is monitored and allowed here and they are no longer handled by the egress program.
This program will only function properly with TCP connections
*/
#[cgroup_skb(ingress)] 
pub fn firewhal_ingress(ctx: SkBuffContext) -> i32 {
    let result = || -> Result<i32, i64> {
        
        if u32::from_be(ctx.skb.local_port()) != u32::from_be(22) {
            info!(
            &ctx,
            "Ingress Processing: remote ipv4 {:i}, remote port {}, local ipv4 {:i}, local port {}",
            u32::from_be(ctx.skb.remote_ipv4()), u32::from_be(ctx.skb.remote_port()), u32::from_be(ctx.skb.local_ipv4()), u32::from(ctx.skb.local_port()) // still not sure about whether I should be casting the port as a u16 but this seems to be working for now
            );
        }

        // FIX ME Ports are u32 with skbuff, need to modify blocklist hashmap
        // Check if the destination port is in our blocklist
        // let port_blocklist_ptr = unsafe { core::ptr::addr_of_mut!(PORT_BLOCKLIST) };
        // if unsafe { (*port_blocklist_ptr).get(&ctx.skb.local_port()).is_some() } {
        //     info!(
        //         &ctx,
        //         "Cgroup Ingress: BLOCKED incoming packet to port {}", u32::from(ctx.skb.local_port())
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

/*
This program is for filtering traffic to specific applications, may be completely unnecessary as a whole. 
*/
#[cgroup_sock_addr(recvmsg4)]
pub fn firewhal_ingress_recvmsg4(ctx: SockAddrContext) -> i32 {
    let result = || -> Result<i32, i32> {
        info!(
            &ctx,
            "Cgroup Ingress Processing, Packet Recieved"
            );
        Ok(1)
        }();

    match result {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// EGRESS PROGRAMS

/*  Monitors connect syscalls for IPv4 traffic, has awareness of the process making the call and will filter based on application hash and trust later. Only works for TCP
Include the ability to only allow outgoing traffic for specific ports on an application basis. For example, Firefox is only able to send traffic with a destination port of 443
Basic example:
sock_addr_program sees that firefox is in the list of trusted applications, its hash hasnt changed and neither has its path. We allow a connect syscall to a remote IP address with a destination address of 443.
Now, the sock_addr_program adds an allow rule to the rule list used by the XDP program from that remote IP address and from port 443 for incoming traffic either until the connection is closed or until a certain amount of time has passed. 
This method forgoes interacting with the systems conntrack functionality at all and requires the use of a map in the eBPF program that is potentially more performant to begin with. 
*/
#[cgroup_sock_addr(connect4)]
pub fn firewhal_egress_connect4(ctx: SockAddrContext) -> i32 {
    let result = || -> Result<i32, i32> {
        let sockaddr_pointer = ctx.sock_addr;
        let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
        let user_port = unsafe { (*sockaddr_pointer).user_port };
        // let remote_ip4 = unsafe { (*sockaddr_pointer).msg_src_ip4 };

        //Convert to readable format
        let user_ip_converted = u32::from_be(user_ip4); // This conversion is correct for the IP.
        let user_port_converted = (u32::from_be(user_port) >> 16) as u16;
        //let remote_ip_converted = u32::from_be(remote_ip4);
        
        info!(
            &ctx,
            "TCP EGRESS Connection Attempt TO: [{:i}, port: {}]",
            user_ip_converted, user_port_converted//, remote_ip_converted,
        );

        // The BLOCKLIST map stores keys in network byte order, so we use the original value.
        let dest_addr = user_ip4;
        let blocklist_ptr = unsafe { core::ptr::addr_of_mut!(BLOCKLIST) };
        if unsafe { (*blocklist_ptr).get(&dest_addr).is_some() } {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
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


// Monitors for sendmsg syscalls for IPv4 traffic, same as connect4 program except monitors UDP traffic instead
#[cgroup_sock_addr(sendmsg4)]
pub fn firewhal_egress_sendmsg4(ctx: SockAddrContext) -> i32 {
    let result = || -> Result<i32, i32> {
        let sockaddr_pointer = ctx.sock_addr;
        let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
        let user_port = unsafe { (*sockaddr_pointer).user_port };
        let dest_ip_host = u32::from_be(user_ip4); // This conversion is correct for the IP.
        let dest_port_host = (u32::from_be(user_port) >> 16) as u16;
        info!(
            &ctx,
            "UDP EGRESS Connection Attempt to: {:i}, port: {}",
            dest_ip_host, dest_port_host,
        );

        // The BLOCKLIST map stores keys in network byte order, so we use the original value.
        let dest_addr = user_ip4;
        let blocklist_ptr = unsafe { core::ptr::addr_of_mut!(BLOCKLIST) };
        if unsafe { (*blocklist_ptr).get(&dest_addr).is_some() } {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
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


// Monitors bind syscalls for IPv4 traffic, this is used in hosting contexts and will be useful in the context of servers
#[cgroup_sock_addr(bind4)]
pub fn firewhal_egress_bind4(ctx: SockAddrContext) -> i32 {
let result = || -> Result<i32, i32> {
        let sockaddr_pointer = ctx.sock_addr;
        let user_ip4 = unsafe { (*sockaddr_pointer).user_ip4 };
        let user_port = unsafe { (*sockaddr_pointer).user_port };
        let dest_ip_host = u32::from_be(user_ip4); // This conversion is correct for the IP.
        let dest_port_host = (u32::from_be(user_port) >> 16) as u16;
        info!(
            &ctx,
            "UDP EGRESS Connection Attempt to: {:i}, port: {}",
            dest_ip_host, dest_port_host,
        );

        // The BLOCKLIST map stores keys in network byte order, so we use the original value.
        let dest_addr = user_ip4;
        let blocklist_ptr = unsafe { core::ptr::addr_of_mut!(BLOCKLIST) };
        if unsafe { (*blocklist_ptr).get(&dest_addr).is_some() } {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
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