#![no_std]

/// A simple log record sent from the eBPF program to the userspace loader.
/// This struct must be `#[repr(C)]` to ensure a predictable memory layout.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LogRecord {
    pub pid: u32,
    pub message: [u8; 128],
}
