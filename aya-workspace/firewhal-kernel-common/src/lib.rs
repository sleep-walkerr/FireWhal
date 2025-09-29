#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LogRecord {
    pub pid: u32,
    pub message: [u8; 128],
}
use core::net::Ipv4Addr;

#[cfg(feature = "user")]
unsafe impl aya::Pod for LogRecord {}

// Add these to your existing common file. You'll likely have `LogRecord` here already.

use core::fmt::{self, Debug};

#[repr(u32)]
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
#[derive(Clone, Copy)]
pub struct BlockEvent {
    pub reason: BlockReason,
    pub pid: u32,       // Process ID that initiated the connection
    pub dest_addr: Ipv4Addr, // The blocked destination address (in big-endian format)
    pub dest_port: u16, // Destination port (in big-endian format)
}