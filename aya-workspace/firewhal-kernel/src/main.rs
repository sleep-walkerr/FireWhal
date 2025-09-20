use anyhow::Context;
use aya::{
    maps::HashMap,
    include_bytes_aligned,
    programs::{CgroupAttachMode, CgroupSockAddr, Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, LevelFilter, Record, SetLoggerError};
use simple_logging;
use std::{
    net::Ipv4Addr,
    str,
    thread,
    time::Duration,
    fs::{File, OpenOptions},
};
use tokio::{signal, sync::{mpsc, watch}};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: String,
    #[clap(short, long, default_value = "wlp5s0")]
    iface: String,
}

/// A custom logger that forwards log messages over a Tokio MPSC channel.
struct ZmqLogger {
    tx: mpsc::Sender<String>,
}

impl log::Log for ZmqLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let msg = format!("[Kernel] [{}] {}", record.level(), record.args());
            if self.tx.try_send(msg).is_err() {
                // Log is dropped if channel is full to prevent deadlock.
            }
        }
    }
    fn flush(&self) {}
}

/// Sets the global logger to our ZMQ logger.
fn set_zmq_logger(log_tx: mpsc::Sender<String>) -> Result<(), SetLoggerError> {
    let logger = ZmqLogger { tx: log_tx };
    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(LevelFilter::Info))
}


/// Runs in a separate thread. It forwards logs and listens for the shutdown command.
fn zmq_comms_thread(mut log_rx: mpsc::Receiver<String>, shutdown_tx: watch::Sender<()>) {
    let context = zmq::Context::new();
    let dealer = context.socket(zmq::DEALER).unwrap();
    
    thread::sleep(Duration::from_millis(500));
    
    if let Err(e) = dealer.connect("ipc:///tmp/firewhal_ipc.sock") {
        warn!("[ZMQ-Thread] Failed to connect to IPC router: {}. Shutting down.", e);
        return;
    }
    if let Err(e) = dealer.send("KERNEL_READY", 0) {
        warn!("[ZMQ-Thread] Failed to send KERNEL_READY: {}. Shutting down.", e);
        return;
    }
    info!("[ZMQ-Thread] Registered with IPC router.");

    let mut poll_items = [dealer.as_poll_item(zmq::POLLIN)];
    loop {
        while let Ok(msg) = log_rx.try_recv() {
            if dealer.send(&msg, zmq::DONTWAIT).is_err() {
                // Drop log if buffer full.
            }
        }

        match zmq::poll(&mut poll_items, 100) {
            Ok(count) if count > 0 && poll_items[0].is_readable() => {
                if let Ok(multipart) = dealer.recv_multipart(0) {
                    if multipart.len() >= 2 {
                        if let Ok(msg) = str::from_utf8(&multipart[1]) {
                            if msg == "CMD:SHUTDOWN:firewall" {
                                info!("[ZMQ-Thread] Shutdown command received.");
                                let _ = shutdown_tx.send(());
                                break;
                            }
                        }
                    }
                } else { break; }
            }
            Ok(_) => {} // Poll timed out.
            Err(_) => break, // Poll error.
        }

        if shutdown_tx.is_closed() { break; }
        thread::sleep(Duration::from_millis(10));
    }
    info!("[ZMQ-Thread] Listener thread is shutting down.");
}


// firewhal-kernel.rs

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // --- SETUP DEDICATED LOG FILE ---
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/firewhal-kernel.log")?;
    simple_logging::log_to(log_file, LevelFilter::Info);

    info!("--- Firewhal Kernel Starting Up ---");
    info!("Loading and attaching eBPF programs...");
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewhal-kernel"
    )))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }
    
    // ... all your bpf.program_mut() and attach() calls remain the same ...
    
    let xdp_prog: &mut Xdp = bpf.program_mut("firewhal_xdp").unwrap().try_into()?;
    xdp_prog.load()?;
    let _xdp_link = xdp_prog.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach XDP program")?;
    info!("Attached XDP filter program to interface {}.", opt.iface);
    
    let cgroup_file = File::open(&opt.cgroup_path)?;
    let ingress_prog: &mut CgroupSockAddr = bpf.program_mut("firewhal_ingress_recvmsg4").unwrap().try_into()?;
    ingress_prog.load()?;
    let _ingress_link = ingress_prog.attach(&cgroup_file, CgroupAttachMode::Single)?;
    info!("Attached cgroup ingress recvmsg4 program.");

    let egress_connect_prog: &mut CgroupSockAddr = bpf.program_mut("firewhal_egress_connect4").unwrap().try_into()?;
    egress_connect_prog.load()?;
    let _egress_connect_link = egress_connect_prog.attach(&cgroup_file, CgroupAttachMode::Single)?;
    info!("Attached cgroup egress connect4 program.");

    let egress_bind_prog: &mut CgroupSockAddr = bpf.program_mut("firewhal_egress_bind4").unwrap().try_into()?;
    egress_bind_prog.load()?;
    let _egress_bind_link = egress_bind_prog.attach(&cgroup_file, CgroupAttachMode::Single)?;
    info!("Attached cgroup egress bind4 program.");

    let egress_send_prog: &mut CgroupSockAddr = bpf.program_mut("firewhal_egress_sendmsg4").unwrap().try_into()?;
    egress_send_prog.load()?;
    let _egress_send_link = egress_send_prog.attach(cgroup_file, CgroupAttachMode::Single)?;
    info!("Attached cgroup egress sendmsg4 program.");


    let mut icmp_block: HashMap<_, u8, u8> = HashMap::try_from(bpf.map_mut("ICMP_BLOCK_ENABLED").unwrap())?;
    icmp_block.insert(1, 1, 0)?;
    info!("[Rule] Blocking all incoming ICMP (ping) traffic via XDP.");

    let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
    let block_addr: u32 = Ipv4Addr::new(9, 9, 9, 9).into();
    blocklist.insert(block_addr, 0, 0)?;
    info!("[Rule] Blocking outgoing connections to 9.9.9.9");

    // The ZMQ Comms thread is not strictly needed for shutdown anymore,
    // but we can leave it for logging and future commands.
    // The ZMQ logic does not need to change.
    let (log_tx, log_rx) = mpsc::channel(1024);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(());

    thread::spawn(move || {
        zmq_comms_thread(log_rx, shutdown_tx);
    });

    if set_zmq_logger(log_tx).is_err() {
        warn!("Failed to set ZMQ logger. Logs will continue to file.");
    }

    info!("✅ Firewall is active. Waiting for shutdown signal...");

    // ---- START: MODIFICATION ----
    // Set up a SIGTERM listener
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("\nCtrl-C (SIGINT) received. Shutting down.");
        },
        _ = sigterm.recv() => {
            info!("SIGTERM received. Shutting down.");
        },
        _ = shutdown_rx.changed() => {
            // This branch remains as a backup or for other ZMQ-based commands
            info!("Shutdown signal received from ZMQ listener thread.");
        }
    };
    // ---- END: MODIFICATION ----

    // Give a moment for shutdown signals to propagate and for drop handlers to run.
    tokio::time::sleep(Duration::from_millis(100)).await;

    info!("🧹 Detaching eBPF programs and exiting...");
    Ok(())
}