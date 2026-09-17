//! End-to-end tests for the pure-Rust ZMQ IPC router: registration, routing,
//! slow-joiner clients, and reconnection after a router restart.

use std::time::Duration;

use firewhal_core::{
    DebugMessage, FireWhalMessage, InterfaceStateConfig, NetInterfaceResponse, StatusPing,
    StatusUpdate,
};
use tokio::sync::{broadcast, mpsc};
use zeromq::{DealerSocket, Socket, SocketOptions, SocketRecv, SocketSend, ZmqMessage};

fn unique_endpoint(name: &str) -> String {
    let dir = std::env::temp_dir();
    format!(
        "ipc://{}/firewhal_test_{}_{}.sock",
        dir.display(),
        std::process::id(),
        name
    )
}

fn bincode_config() -> bincode::config::Configuration<bincode::config::BigEndian> {
    bincode::config::standard().with_big_endian()
}

/// Connects a raw DEALER socket to the router, retrying internally until the
/// router is up (the connect call blocks until the endpoint exists).
async fn connect_dealer(endpoint: &str) -> DealerSocket {
    let mut options = SocketOptions::default();
    options.no_connect_timeout();
    let mut socket = DealerSocket::with_options(options);
    socket
        .connect(endpoint)
        .await
        .expect("failed to connect test client to router");
    socket
}

async fn send_msg(socket: &mut DealerSocket, message: &FireWhalMessage) {
    let payload = bincode::encode_to_vec(message, bincode_config()).expect("encode");
    socket
        .send(ZmqMessage::from(payload))
        .await
        .expect("send");
}

/// Receives messages until one satisfies `pred`, failing after `timeout`.
async fn recv_until<F>(socket: &mut DealerSocket, timeout: Duration, mut pred: F) -> FireWhalMessage
where
    F: FnMut(&FireWhalMessage) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .max(Duration::from_millis(1));
        let frames = tokio::time::timeout(remaining, socket.recv())
            .await
            .expect("timed out waiting for message")
            .expect("recv failed");
        let payload = frames.get(0).expect("empty message");
        let (message, _) = bincode::decode_from_slice::<FireWhalMessage, _>(payload, bincode_config())
            .expect("malformed message");
        if pred(&message) {
            return message;
        }
    }
}

fn register(component: &str) -> FireWhalMessage {
    FireWhalMessage::Status(StatusUpdate {
        component: component.to_string(),
        is_healthy: true,
        message: "Ready".to_string(),
    })
}

/// Waits until the socket's own registration has been processed by the
/// router. Ping/Pong travel over the same connection, so receiving the Pong
/// proves the Ready (sent just before it) was already handled.
async fn wait_until_registered(socket: &mut DealerSocket) {
    send_msg(
        socket,
        &FireWhalMessage::Ping(StatusPing { source: "TUI".into() }),
    )
    .await;
    recv_until(socket, Duration::from_secs(5), |m| matches!(m, FireWhalMessage::Pong(_)))
        .await;
}

#[tokio::test]
async fn router_registers_clients_and_routes_messages() {
    let endpoint = unique_endpoint("routing");
    let router = tokio::spawn(firewhal_ipc::run_router(endpoint.clone(), false));

    let mut tui = connect_dealer(&endpoint).await;
    let mut daemon = connect_dealer(&endpoint).await;

    send_msg(&mut tui, &register("TUI")).await;
    send_msg(&mut daemon, &register("Daemon")).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A TUI ping gets an immediate Pong back, and is fanned out to the other
    // registered components.
    send_msg(
        &mut tui,
        &FireWhalMessage::Ping(StatusPing { source: "TUI".into() }),
    )
    .await;

    let pong = recv_until(&mut tui, Duration::from_secs(3), |m| matches!(m, FireWhalMessage::Pong(_))).await;
    match pong {
        FireWhalMessage::Pong(p) => assert_eq!(p.source, "IPC"),
        other => panic!("expected Pong, got {:?}", other),
    }

    let ping = recv_until(&mut daemon, Duration::from_secs(3), |m| matches!(m, FireWhalMessage::Ping(_))).await;
    match ping {
        FireWhalMessage::Ping(p) => assert_eq!(p.source, "TUI"),
        other => panic!("expected Ping, got {:?}", other),
    }

    // Daemon debug messages are re-encoded and forwarded to the TUI.
    let debug = FireWhalMessage::Debug(DebugMessage {
        source: "Daemon".into(),
        content: "hello tui".into(),
    });
    send_msg(&mut daemon, &debug).await;
    let forwarded = recv_until(&mut tui, Duration::from_secs(3), |m| matches!(m, FireWhalMessage::Debug(_))).await;
    match forwarded {
        FireWhalMessage::Debug(d) => assert_eq!(d.content, format!("{:?}", debug)),
        other => panic!("expected Debug, got {:?}", other),
    }

    // Interface responses from the Daemon are forwarded to the TUI.
    let iface = FireWhalMessage::InterfaceResponse(NetInterfaceResponse {
        source: "Daemon".into(),
        interface_state: InterfaceStateConfig {
            enforced_interfaces: Default::default(),
        },
        current_interfaces: Default::default(),
    });
    send_msg(&mut daemon, &iface).await;
    let resp = recv_until(&mut tui, Duration::from_secs(3), |m| matches!(m, FireWhalMessage::InterfaceResponse(_))).await;
    match resp {
        FireWhalMessage::InterfaceResponse(r) => assert_eq!(r.source, "Daemon"),
        other => panic!("expected InterfaceResponse, got {:?}", other),
    }

    router.abort();
    let _ = std::fs::remove_file(endpoint.strip_prefix("ipc://").expect("ipc endpoint"));
}

#[tokio::test]
async fn client_connects_late_and_reregisters_after_router_restart() {
    let endpoint = unique_endpoint("reconnect");

    // The client starts BEFORE the router exists. It must wait, retry, and
    // then connect once the router appears (slow-joiner behavior).
    let (to_tx, to_rx) = mpsc::channel::<FireWhalMessage>(64);
    let (_from_tx, _from_rx) = mpsc::channel::<FireWhalMessage>(64);
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let client = tokio::spawn(firewhal_core::ipc_client_connection(
        endpoint.clone(),
        to_rx,
        _from_tx,
        shutdown_rx,
        "Daemon".to_string(),
        Some(Duration::from_millis(200)),
    ));

    // Give the client a head start in its connect-retry loop.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let router = tokio::spawn(firewhal_ipc::run_router(endpoint.clone(), false));

    // A raw TUI registers, then the client (which self-registers on connect)
    // sends a debug message that the router should forward to the TUI.
    let mut tui = connect_dealer(&endpoint).await;
    send_msg(&mut tui, &register("TUI")).await;
    wait_until_registered(&mut tui).await;

    let before_msg = FireWhalMessage::Debug(DebugMessage {
        source: "Daemon".into(),
        content: "before restart".into(),
    });
    to_tx.send(before_msg.clone()).await.expect("channel closed");
    let before = recv_until(&mut tui, Duration::from_secs(10), |m| matches!(m, FireWhalMessage::Debug(_))).await;
    match before {
        FireWhalMessage::Debug(d) => assert_eq!(d.content, format!("{:?}", before_msg)),
        other => panic!("expected Debug, got {:?}", other),
    }

    // Kill the router; the client's heartbeat must notice and start
    // reconnecting.
    router.abort();
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Restart the router on the same endpoint. The old TUI socket is dead; a
    // fresh one registers in its place.
    let router2 = tokio::spawn(firewhal_ipc::run_router(endpoint.clone(), false));
    drop(tui);
    let mut tui2 = connect_dealer(&endpoint).await;
    send_msg(&mut tui2, &register("TUI")).await;
    wait_until_registered(&mut tui2).await;

    // The client should have reconnected and re-registered itself; its next
    // message must be delivered.
    let after_msg = FireWhalMessage::Debug(DebugMessage {
        source: "Daemon".into(),
        content: "after restart".into(),
    });
    to_tx.send(after_msg.clone()).await.expect("channel closed");
    let after = recv_until(&mut tui2, Duration::from_secs(15), |m| matches!(m, FireWhalMessage::Debug(_))).await;
    match after {
        FireWhalMessage::Debug(d) => assert_eq!(d.content, format!("{:?}", after_msg)),
        other => panic!("expected Debug, got {:?}", other),
    }

    // Clean shutdown of the client via the broadcast signal.
    shutdown_tx.send(()).expect("shutdown broadcast");
    client
        .await
        .expect("client task panicked")
        .expect("client task failed");
    router2.abort();
    let _ = std::fs::remove_file(endpoint.strip_prefix("ipc://").expect("ipc endpoint"));
}
