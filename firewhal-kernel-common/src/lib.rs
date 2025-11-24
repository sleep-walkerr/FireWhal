#![no_std]

use aya_ebpf::{bindings::TC_ACT_OK, programs::TcContext};
use aya_log_ebpf::{error, info, warn};
use network_types::icmp::Icmp;
use core::mem;
use core::fmt::{self, Debug, Formatter};
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





// TC Program Connection Handling and Tracking 

// Connection info
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectionInfo {
    pub pid: u32,
    pub last_seen: u64,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionInfo {}
unsafe impl Plain for ConnectionInfo {}

// Connection Map Key for Statful
#[repr(C)]
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct ConnectionTuple {
    pub saddr: u32,    // Network Byte Order (Big Endian)
    pub daddr: u32,    // Network Byte Order (Big Endian)
    pub sport: u16,    // Network Byte Order (Big Endian)
    pub dport: u16,    // Network Byte Order (Big Endian)
    pub protocol: u8,
    pub _pad: [u8; 3], // Padding to make total size 16 bytes (4+4+2+2+1+3) for alignment
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionTuple {}
unsafe impl Plain for ConnectionTuple {}




// TC Program Packet Parser for tuples
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
}

// TC TCP Header Parser for SYN ACK allows in TC Ingress
// Server functionalities require this
// This is a bandaid, if there's time refactor to have parsing function only return Ipv4Hdr, 
// Then have a separate function to return transport headers like tcp and udp
// Then do parsing inside of function
#[inline(always)]
pub fn parse_tcp_header(ctx: &TcContext) -> Result<TcpHdr, ()> {
    
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if eth_hdr.ether_type == EtherType::Ipv4.into() {
    } else if eth_hdr.ether_type == EtherType::Ipv6.into() {
        info!(ctx, "IPv6 {} Packet found. Breaking", u16::from_be(eth_hdr.ether_type));
        return Err(());
    } else {
        info!(ctx, "Unsupported Type {} found. Breaking", u16::from_be(eth_hdr.ether_type));
        return Err(())
    }

    let ipv4_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let l4_hdr_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    if ipv4_hdr.proto != IpProto::Tcp {
        let tcp_hdr: TcpHdr = ctx.load(l4_hdr_offset).map_err(|_| ())?; // Use dynamic offset

        // Get Ports this way: (u16::from_be_bytes(tcp_hdr.source), u16::from_be_bytes(tcp_hdr.dest))
        let tcp_header = tcp_hdr.clone();
        
        Ok(tcp_header)
    } else {
        Err(())
    }
}



// Structs for keeping track of trusted PIDs
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidTrustInfo {
    pub action: Action, // Allow or Deny
    pub last_seen_ns: u64, // Nanoseconds since boot (from bpf_ktime_get_ns())
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PidTrustInfo {}
unsafe impl Plain for PidTrustInfo {}

#[repr(C)]
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub struct RuleKey { // Change this later to have protocol as u8 and use plain along with padding 
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

















// CHANGED STRUCTS
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Allow = 0,
    Deny = 1,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Action {}
unsafe impl Plain for Action {}

// Connection Tuple for Tracking Process for Outgoing Connections (Ex: connect() -> tc_egress)#[repr(C)]
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub _padding: [u8; 3], // Pad to 16 bytes
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionKey {}
unsafe impl Plain for ConnectionKey {}

// Kernel Event Data Structures
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventType {
    ConnectionAttempt = 0,
    BlockEvent = 1,
    DebugMessage = 2,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EventType {}
unsafe impl Plain for EventType {}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlockReason {
    IcmpBlocked = 1,
    IpBlockedEgressTcp = 2,
    IpBlockedEgressUdp = 3,
    IpBlockedIngress = 5,
    BindBlocked = 4,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockReason {}
unsafe impl Plain for BlockReason {}

// Data specific to a ConnectionAttempt event
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConnectionAttemptPayload {
    pub key: ConnectionKey, // Embed the ConnectionKey directly
    // Add any other connection-specific info here
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionAttemptPayload {}
unsafe impl Plain for ConnectionAttemptPayload {}

// Data specific to a BlockEvent
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockEventPayload {
    pub key: ConnectionKey, // Embed the ConnectionKey here too
    pub reason: BlockReason,
    // Add any other block-specific info here
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockEventPayload {}
unsafe impl Plain for BlockEventPayload {}

// Data specific to a DebugMessage
// This can be variable length, so usually it's a fixed-size array
// or handled differently. For now, a fixed-size array is simple.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DebugMessagePayload {
    pub message: [u8; 64], // Fixed-size buffer for a short debug message
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DebugMessagePayload {}
unsafe impl Plain for DebugMessagePayload {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct KernelEvent {
    pub event_type: EventType,
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16], // Command name

    // Flexible payload: this struct will be large enough to hold the largest
    // of your individual payload types. You'll read this based on event_type.
    // For padding, ensure this combined_payload makes the whole struct 8-byte aligned.
    pub payload: KernelEventPayload,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for KernelEvent {}
unsafe impl Plain for KernelEvent {} // Always derive Plain if it's available and needed


// This is the "manual union" part.
// Its size should be the max size of any of your individual payloads.
// Ensure it's large enough and correctly aligned.
#[repr(C)]
#[derive(Copy, Clone)]
pub union KernelEventPayload {
    pub connection_attempt: ConnectionAttemptPayload,
    pub block_event: BlockEventPayload,
    pub debug_message: DebugMessagePayload,
    // Add more as needed.
    // Ensure padding here if necessary to make this union 8-byte aligned
    // and a multiple of 8 bytes for efficient perf buffer usage.
    // Example: [u8; MAX_PAYLOAD_SIZE] if you just want raw bytes.
    pub _padding: [u8; 64], // Example: make it big enough for DebugMessagePayload (64 bytes)
                            // and BlockEventPayload (16 bytes + X)
                            // Max size is currently DebugMessagePayload (64 bytes).
                            // ConnectionAttemptPayload is 16 bytes. BlockEventPayload is 16 + X.
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for KernelEventPayload {}
unsafe impl Plain for KernelEventPayload {}