use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{CgroupAttachMode, CgroupSockAddr, Xdp, XdpFlags},
    include_bytes_aligned,
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::{
    fs::File,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use tokio::{
    signal,
    sync::broadcast,
    task::spawn_blocking,
    time::{sleep, Duration},
};
use zmq;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: String,
    #[clap(short, long, default_value = "wlp5s0")]
    iface: String,
}

async fn nonblocking_zmq_message_sender(
    _msg: String,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    // This flag will be shared between our async task and the blocking ZMQ thread.
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    // The actual blocking ZMQ work is offloaded to a blocking thread.
    let blocking_task = spawn_blocking(move || -> Result<(), zmq::Error> {
        let context = zmq::Context::new();
        let dealer = context.socket(zmq::DEALER).unwrap();
        dealer.set_connect_timeout(1000)?;
        dealer.set_rcvtimeo(500)?; // Set a 500ms timeout on receive
        // Set linger period to 0 to prevent blocking on close.
        dealer.set_linger(0)?;
        assert!(dealer.connect("ipc:///tmp/firewhal_ipc.sock").is_ok());

        dealer.send(&"test from ebpf loader".to_string(), 0)?;

        // Loop until the shutdown flag is set
        while running_clone.load(Ordering::Relaxed) {
            let mut msg = zmq::Message::new(); // Create a new message for each receive
            match dealer.recv(&mut msg, 0) {
                Ok(_) => {
                    let msg_str = msg.as_str().unwrap_or("invalid utf-8");
                    println!("TUI received message from router: '{}'", msg_str);
                    if msg_str == "Hash has changed" {
                        let _ = dealer.send(&"Hash changed notification received".to_string(), 0);
                    }
                }
                Err(zmq::Error::EAGAIN) => {
                    // Timeout hit, this is expected. Loop again to check the `running` flag.
                    continue;
                }
                Err(e) => {
                    // A real error occurred.
                    eprintln!("ZMQ recv error: {}", e);
                    break;
                }
            }
        }

        println!("ZMQ blocking loop finished.");
        Ok(())
    });

    // This is our async control loop.
    let mut blocking_task = blocking_task;
    tokio::select! {
        // Wait for the shutdown signal
        res = shutdown_rx.recv() => {
            if res.is_err() {
                warn!("ZMQ task shutdown channel closed unexpectedly.");
            }
            info!("Shutdown signal received in ZMQ task. Stopping blocking thread.");
            running.store(false, Ordering::Relaxed);
        },
        // Or wait for the blocking task to finish on its own
        _ = &mut blocking_task => { // The handle is consumed here if this branch is taken
            warn!("ZMQ blocking task finished before shutdown signal.");
        }
    };

    // After signaling shutdown, we must wait for the blocking task to actually finish.
    if let Err(e) = blocking_task.await {
        eprintln!("ZMQ blocking task panicked or was cancelled: {}", e);
    }
}

async fn run(opt: Opt) -> Result<(), anyhow::Error> {
    // --- 1. SETUP GRACEFUL SHUTDOWN ---
    let (shutdown_tx, _) = broadcast::channel(1);
    let mut zmq_test_handle = tokio::spawn(nonblocking_zmq_message_sender(
        "loader program test message".to_string(),
        shutdown_tx.subscribe(),
    ));

    env_logger::init();

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
        _ = &mut zmq_test_handle => { // The handle is consumed here if this branch is taken
            warn!("ZMQ task exited on its own before shutdown signal.");
        }
    };

    // --- 5. WAIT FOR TASKS TO SHUT DOWN GRACEFULLY ---
    if let Err(e) = zmq_test_handle.await {
        eprintln!("ZMQ task did not shut down cleanly: {}", e);
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