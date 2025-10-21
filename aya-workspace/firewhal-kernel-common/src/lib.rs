#![no_std]

use aya_ebpf::{bindings::TC_ACT_OK, programs::TcContext};
use aya_log_ebpf::{error, info, warn};
use network_types::icmp::Icmp;
use core::mem;
use network_types::eth::{self, EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use network_types::icmp::IcmpHdr;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LogRecord {
    pub pid: u32,
    pub message: [u8; 128],
}
use core::net::{IpAddr, Ipv4Addr};
use plain::Plain;

#[cfg(feature = "user")]
unsafe impl aya::Pod for LogRecord {}



use core::fmt::{self, Debug};

// TC Program Connection Handling and Tracking 

// Connection info
#[derive(Copy, Clone)]
pub struct ConnectionInfo {
    pub pid: u32,
    pub last_seen: u64,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionInfo {}

// Connection Map Key for Statful
#[repr(C)]
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct ConnectionTuple {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub _pad: [u8; 3], // Explicit padding
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionTuple {}

// TC Program Packet Parser
#[inline(always)]
pub fn parse_packet_tuple(ctx: &TcContext) -> Result<ConnectionTuple, ()> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    // The ether_type from the packet is big-endian. The EtherType::Ipv4 enum
    // has the value 0x0800. We must ensure the comparison is correct.
    // The simplest way is to use the `into()` conversion provided by network-types.
    // LOOK HERE
    if eth_hdr.ether_type == EtherType::Ipv4.into() {
        //info!(ctx, "IPv4 packet found. Continuing");
    } else if eth_hdr.ether_type == EtherType::Ipv6.into() {
        info!(ctx, "IPv6 {} Packet found. Breaking", u16::from_be(eth_hdr.ether_type));
        return Err(());
    } else {
        info!(ctx, "Unsupported Type {} found. Breaking", u16::from_be(eth_hdr.ether_type));
        return Err(())
    }

    let ipv4_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let l4_hdr_offset = EthHdr::LEN + Ipv4Hdr::LEN;
    //info!(ctx, "Successfully loaded Ipv4 header");
    // --- Convert IP addresses from [u8; 4] to u32 in Network Byte Order ---
    // The [u8; 4] is already big-endian, so u32::from_be_bytes() is the correct way
    // to get a u32 that represents this big-endian value, regardless of host endianness.
    let saddr_net = u32::from_le_bytes(ipv4_hdr.src_addr);
    let daddr_net = u32::from_le_bytes(ipv4_hdr.dst_addr);

    let (sport, dport) = match ipv4_hdr.proto {
        IpProto::Tcp => {
            let tcp_hdr: TcpHdr = ctx.load(l4_hdr_offset).map_err(|_| ())?; // Use dynamic offset
            (u16::from_be_bytes(tcp_hdr.source), u16::from_be_bytes(tcp_hdr.dest))
        }
        IpProto::Udp => {
            let udp_hdr: UdpHdr = ctx.load(l4_hdr_offset).map_err(|_| ())?; // Use dynamic offset
            (u16::from_be_bytes(udp_hdr.src), u16::from_be_bytes(udp_hdr.dst))
        }
        IpProto::Icmp => {
            let icmp_hdr: IcmpHdr = ctx.load(l4_hdr_offset).map_err(|_| ())?;
            // For ICMP, we can use type and code as pseudo-ports for more specific tracking.
            (icmp_hdr.type_.into(), icmp_hdr.code.into())
        }
        _ => {
            //info!(ctx, "Ports not supported for protocol: {}", ipv4_hdr.proto as u8);
            (0,0)
        }
    };

    Ok(ConnectionTuple {
        saddr: saddr_net,     // u32 in network byte order
        daddr: daddr_net,     // u32 in network byte order
        sport: sport,     // u16 in network byte order
        dport: dport,     // u16 in network byte order
        protocol: ipv4_hdr.proto as u8,
        _pad: [0; 3],
    })
    // Ok(ConnectionTuple {
    //     saddr: saddr_net,     // u32 in network byte order
    //     daddr: daddr_net,     // u32 in network byte order
    //     sport: sport_net,     // u16 in network byte order
    //     dport: dport_net,     // u16 in network byte order
    //     protocol: ipv4_hdr.proto as u8,
    // })
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Action {
    Allow,
    Deny
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Action {}

#[repr(C)]
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub struct RuleKey {
    pub protocol: u32,
    pub source_port: u16,
    pub dest_port: u16,
    pub source_ip: u32,
    pub dest_ip: u32,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleKey {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RuleAction {
    pub action: Action,
    pub rule_id: u32,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleAction {}





#[repr(u8)]
#[derive(Clone, Copy)]
pub enum BlockReason {
    IcmpBlocked = 1,
    IpBlockedEgressTcp = 2,
    IpBlockedEgressUdp = 3,
    BindBlocked = 4,
}

// Implement Debug manually because `aya-ebpf` doesn't support derive macros easily.
impl Debug for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockReason::IcmpBlocked => write!(f, "IcmpBlocked"),
            BlockReason::IpBlockedEgressTcp => write!(f, "IpBlockedEgressTcp"),
            BlockReason::IpBlockedEgressUdp => write!(f, "IpBlockedEgressUdp"),
            BlockReason::BindBlocked => write!(f, "BindBlocked"),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BlockEvent {
    // Reordered from largest to smallest
    pub pid: u32,                  // 4 bytes
    pub dest_addr: IpAddr,       // 4 bytes
    pub dest_port: u16,            // 2 bytes
    pub reason: BlockReason,       // 1 byte (now guaranteed by repr(u8))
} // Total size should now be 11 bytes + 1 padding byte = 12 bytes

// This part stays the same
unsafe impl Plain for BlockEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockEvent {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LpmIpKey {
    pub prefix_len: u32,
    pub ip_data: u32, // The IP address in big-endian
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for LpmIpKey {}