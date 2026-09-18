// IPC smoke client: connect to the router as "TUI", register, ping, expect pongs.

use std::time::Duration;

use bincode::config;
use firewhal_core::{FireWhalMessage, StatusPing, StatusPong, StatusUpdate};
use zeromq::{DealerSocket, Socket, SocketOptions, SocketRecv, SocketSend, ZmqMessage};

#[tokio::main]
async fn main() {
    let endpoint = "ipc:///tmp/firewhal_ipc.sock";
    let cfg = config::standard().with_big_endian();

    let mut options = SocketOptions::default();
    options.no_connect_timeout();
    let mut socket = DealerSocket::with_options(options);
    socket.connect(endpoint).await.expect("connect to router");
    println!("[SMOKE] connected to {endpoint}");

    let reg = FireWhalMessage::Status(StatusUpdate {
        component: "TUI".to_string(),
        is_healthy: true,
        message: "Ready".to_string(),
    });
    socket.send(ZmqMessage::from(bincode::encode_to_vec(&reg, cfg).unwrap())).await.expect("register");
    println!("[SMOKE] registered as TUI (Ready)");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let ping = FireWhalMessage::Ping(StatusPing {
        source: "TUI".to_string(),
    });
    socket.send(ZmqMessage::from(bincode::encode_to_vec(&ping, cfg).unwrap())).await.expect("ping");
    println!("[SMOKE] sent Ping(source=TUI), collecting replies for 6s...");

    let mut got_ipc_pong = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let frame = match tokio::time::timeout(remaining, socket.recv()).await {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => {
                println!("[SMOKE] recv error: {e}");
                break;
            }
            Err(_) => break,
        };
        let payload = match frame.get(0) {
            Some(p) => p,
            None => {
                println!("[SMOKE] got empty multipart message");
                continue;
            }
        };
        match bincode::decode_from_slice::<FireWhalMessage, _>(payload, cfg) {
            Ok((FireWhalMessage::Pong(StatusPong { source }), _)) => {
                println!("[SMOKE] PONG from {source}");
                if source == "IPC" {
                    got_ipc_pong = true;
                }
            }
            Ok(other) => println!("[SMOKE] got: {other:?}"),
            Err(_) => println!("[SMOKE] got undecodable frame"),
        }
    }

    if got_ipc_pong {
        println!("[SMOKE] SUCCESS: router round-trip verified");
    } else {
        println!("[SMOKE] FAILURE: no Pong from IPC");
        std::process::exit(1);
    }
}
