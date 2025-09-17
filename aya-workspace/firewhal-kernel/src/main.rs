use anyhow::Context;
use aya::{
    maps::HashMap,
    include_bytes_aligned,
    programs::{CgroupAttachMode, CgroupSockAddr, Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, LevelFilter, Record};
use std::{
    fs::File,
    time::Duration,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use tokio::{
    signal, // Add mpsc to imports
    sync::{broadcast, mpsc},
    sync::mpsc::error::TryRecvError,
    task::spawn_blocking,
};
use zmq;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: String,
    #[clap(short, long, default_value = "wlp5s0")]
    iface: String,
}

struct ZmqLogger {
    tx: mpsc::Sender<String>,
}

impl log::Log for ZmqLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let msg = format!("[{}] {}", record.level(), record.args());
            // Use try_send to avoid blocking the logging call.
            if let Err(e) = self.tx.try_send(msg) {
                // If the channel is full or closed, print to stderr as a fallback.
                eprintln!("Fallback log (ZMQ channel error: {}): {}", e, record.args());
            }
        }
    }

    fn flush(&self) {}
}

async fn zmq_log_forwarder(
    mut log_rx: mpsc::Receiver<String>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    let blocking_task = spawn_blocking(move || -> Result<(), zmq::Error> {
        let context = zmq::Context::new();
        let dealer = context.socket(zmq::DEALER).unwrap();
        dealer.set_linger(0)?;
        assert!(dealer.connect("ipc:///tmp/firewhal_ipc.sock").is_ok());

        while running_clone.load(Ordering::Relaxed) {
            // Try to receive a message without blocking.
            match log_rx.try_recv() {
                Ok(msg) => {
                    // Message received, send it over ZMQ.
                    dealer.send(&msg, 0)?;
                }
                Err(TryRecvError::Empty) => {
                    // No message available. Sleep for a short duration to prevent
                    // busy-looping and yield the CPU. This allows the `running`
                    // flag to be checked periodically without consuming 100% CPU.
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(TryRecvError::Disconnected) => {
                    // The channel has been closed, so we can exit the loop.
                    info!("Log channel disconnected, shutting down ZMQ forwarder.");
                    break;
                }
            }
        }
        Ok(())
    });

    tokio::select! {
        _ = shutdown_rx.recv() => {
            info!("Shutdown signal received in ZMQ log forwarder.");
            running.store(false, Ordering::Relaxed);
        },
        _ = blocking_task => {
            warn!("ZMQ log forwarder task finished unexpectedly.");
        }
    };
}

async fn run(opt: Opt) -> Result<(), anyhow::Error> {
    // --- 1. SETUP GRACEFUL SHUTDOWN ---
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    // --- SETUP LOGGING ---
    let (log_tx, log_rx) = mpsc::channel(1024);
    let logger = ZmqLogger { tx: log_tx };
    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(LevelFilter::Info))
        .expect("Failed to set logger");

    // --- SPAWN ZMQ LOG FORWARDER ---
    let mut zmq_log_handle = tokio::spawn(zmq_log_forwarder(log_rx, shutdown_rx));

    // --- 2. LOAD AND ATTACH EBPF PROGRAMS ---
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewhal-kernel"
    )))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // Attach the XDP program and let the returned Link object manage its lifetime.
    let xdp_prog: &mut Xdp = bpf.program_mut("firewhal_xdp").unwrap().try_into()?;
    xdp_prog.load()?;
    let _xdp_link = xdp_prog.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach XDP program")?;
    info!("Attached XDP filter program to interface {}.", opt.iface);

    // Attach cgroup programs and let their Link objects manage their lifetimes.
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

    // --- 3. CONFIGURE EBPF MAPS ---
    let mut icmp_block: HashMap<_, u8, u8> = HashMap::try_from(bpf.map_mut("ICMP_BLOCK_ENABLED").unwrap())?;
    icmp_block.insert(1, 1, 0)?;
    info!("[Rule] Blocking all incoming ICMP (ping) traffic via XDP.");

    let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).into();
    blocklist.insert(block_addr, 0, 0)?;
    info!("[Rule] Blocking outgoing connections to 1.1.1.1");

    info!("✅ All eBPF programs attached. Waiting for Ctrl-C to exit.");
    
    // --- 4. RUN APPLICATION AND WAIT FOR SHUTDOWN SIGNAL ---
    tokio::select! {
        biased; // Prioritize the ctrl_c branch

        _ = signal::ctrl_c() => { // This branch is now prioritized
            info!("\nCtrl-C received. Sending shutdown signal...");
            let _ = shutdown_tx.send(());
        },
        _ = &mut zmq_log_handle => {
            warn!("ZMQ log forwarder exited on its own before shutdown signal.");
        }
    };

    // --- 5. WAIT FOR TASKS TO SHUT DOWN GRACEFULLY ---
    if let Err(e) = zmq_log_handle.await {
        eprintln!("ZMQ log forwarder did not shut down cleanly: {}", e);
    } else {
        info!("ZMQ task shut down gracefully.");
    }

    // --- 6. CLEANUP ---
    // The eBPF programs will be automatically detached when the `_..._link`
    // variables go out of scope here.
    info!("🧹 Detaching eBPF programs and exiting...");
    info!("Program exited.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    run(opt).await
}