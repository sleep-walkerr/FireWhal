#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LogRecord {
    pub pid: u32,
    pub message: [u8; 128],
}
use core::net::Ipv4Addr;
use plain::Plain;

#[cfg(feature = "user")]
unsafe impl aya::Pod for LogRecord {}

// Add these to your existing common file. You'll likely have `LogRecord` here already.

use core::fmt::{self, Debug};

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
    pub dest_addr: Ipv4Addr,       // 4 bytes
    pub dest_port: u16,            // 2 bytes
    pub reason: BlockReason,       // 1 byte (now guaranteed by repr(u8))
} // Total size should now be 11 bytes + 1 padding byte = 12 bytes

// This part stays the same
unsafe impl Plain for BlockEvent {}


// #[repr(C, packed)]
// #[derive(Copy, Clone)]
// pub struct BlockEvent {
//     // Reordered from largest to smallest
//     pub pid: u32,                  // 4 bytes
//     pub dest_addr: Ipv4Addr,       // 4 bytes
//     pub dest_port: u16,            // 2 bytes
//     pub reason: BlockReason,       // 1 byte (now guaranteed by repr(u8))
// } // Total size should now be 11 bytes + 1 padding byte = 12 bytes

// // This part stays the same
// unsafe impl Plain for BlockEvent {}