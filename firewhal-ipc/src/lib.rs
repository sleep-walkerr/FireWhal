//! FireWhal IPC router.
//!
//! Pure-Rust (zeromq) ROUTER socket bound to a local IPC endpoint. Clients
//! register by sending `Status { message: "Ready" }` and are tracked by
//! component name; all other traffic is routed by message type.
//!
//! Resilience model:
//! - A dead client connection never kills the router: a failed send to one
//!   peer is logged and that peer is evicted from the client table. The peer's
//!   own client task reconnects and re-registers on its side.
//! - If the router's own transport dies, it unbinds, cleans up the socket
//!   file, and rebinds. All clients then reconnect and re-register.
//! - A stale socket file left by a previous run is removed before binding.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use nix::unistd::{chown, setgid, setuid, Group, User};
use zeromq::{RouterSocket, Socket, SocketRecv, SocketSend, ZmqMessage};

use firewhal_core::{DebugMessage, FireWhalMessage, NetInterfaceRequest, NetInterfaceResponse, StatusPing, StatusPong, StatusUpdate};

/// Sends one message to a client. Returns `false` if the send failed.
async fn send_to_identity(router: &mut RouterSocket, identity: &[u8], payload: Vec<u8>) -> bool {
    let mut message = ZmqMessage::from(payload);
    message.push_front(Bytes::copy_from_slice(identity));
    match router.send(message).await {
        Ok(()) => true,
        Err(e) => {
            eprintln!("[ROUTER] Failed to send to client {:?}: {}", identity, e);
            false
        }
    }
}

/// Maximum messages buffered per not-yet-registered component.
const MAX_PENDING_PER_COMPONENT: usize = 100;

/// Forwards `data` to a registered component, evicting that client from the
/// table if the send failed (its peer task will reconnect and re-register).
///
/// If the target component has not registered yet, the message is buffered
/// and delivered on registration: registration order between components is a
/// race (the router is a child of the Daemon, so the Daemon's own connect can
/// lose it), and dropping e.g. the Firewall's "Ready" would leave the Daemon
/// waiting forever for a notification that never comes.
async fn deliver(
    router: &mut RouterSocket,
    clients: &mut HashMap<String, Vec<u8>>,
    pending: &mut HashMap<String, Vec<Vec<u8>>>,
    to: &str,
    data: Vec<u8>,
) {
    match clients.get(to) {
        Some(identity) => {
            if !send_to_identity(router, identity, data).await {
                clients.remove(to);
            }
        }
        None => {
            let queue = pending.entry(to.to_string()).or_default();
            if queue.len() >= MAX_PENDING_PER_COMPONENT {
                eprintln!("[ROUTER] Pending queue for '{}' full; dropping oldest.", to);
                queue.remove(0);
            }
            queue.push(data);
            eprintln!("[ROUTER] Buffered message for '{}' (client not registered yet).", to);
        }
    }
}

/// Routes one decoded message to the right component(s).
async fn route_message(
    router: &mut RouterSocket,
    clients: &mut HashMap<String, Vec<u8>>,
    pending: &mut HashMap<String, Vec<Vec<u8>>>,
    message: &FireWhalMessage,
    sender_identity: &[u8],
    payload: &[u8],
) {
    let bincode_config = bincode::config::standard().with_big_endian();

    match message {
        // --- Registration ---
        FireWhalMessage::Status(status) if status.message == "Ready" => {
            println!("[ROUTER] Registered client '{}' with identity {:?}.", status.component, sender_identity);
            clients.insert(status.component.clone(), sender_identity.to_vec());
            // Deliver anything that was buffered while this component was away.
            if let Some(buffered) = pending.remove(&status.component) {
                for data in buffered {
                    deliver(router, clients, pending, &status.component, data).await;
                }
            }
            if status.component != "Daemon" {
                // Let the Daemon know the rest of the stack is up.
                deliver(router, clients, pending, "Daemon", payload.to_vec()).await;
            }
        }

        // --- Debug traffic ---
        FireWhalMessage::Debug(debug) => {
            if debug.source != "TUI" {
                // Re-encode in a consistent, debug-friendly format for the TUI.
                let forward = FireWhalMessage::Debug(DebugMessage {
                    source: debug.source.clone(),
                    content: format!("{:?}", message),
                });
                if let Ok(bytes) = bincode::encode_to_vec(&forward, bincode_config) {
                    deliver(router, clients, pending, "TUI", bytes).await;
                }
            }
        }

        // --- Firewall configuration ---
        FireWhalMessage::LoadRules(_) => {
            deliver(router, clients, pending, "Firewall", payload.to_vec()).await;
        }
        FireWhalMessage::LoadAppIds(_) => {
            deliver(router, clients, pending, "Firewall", payload.to_vec()).await;
        }
        FireWhalMessage::LoadInterfaceState(_) => {
            deliver(router, clients, pending, "Firewall", payload.to_vec()).await;
        }

        // --- Interface management (TUI <-> Daemon) ---
        FireWhalMessage::InterfaceRequest(req) => {
            if req.source == "TUI" {
                deliver(router, clients, pending, "Daemon", payload.to_vec()).await;
            }
        }
        FireWhalMessage::InterfaceResponse(resp) => {
            if resp.source == "Daemon" {
                deliver(router, clients, pending, "TUI", payload.to_vec()).await;
            }
        }
        FireWhalMessage::UpdateInterfaces(update) => {
            if update.source == "TUI" {
                deliver(router, clients, pending, "Daemon", payload.to_vec()).await;
            }
        }

        // --- Liveness ---
        FireWhalMessage::Ping(ping) => {
            if ping.source == "TUI" {
                let pong = FireWhalMessage::Pong(StatusPong { source: "IPC".to_string() });
                if let Ok(bytes) = bincode::encode_to_vec(&pong, bincode_config) {
                    deliver(router, clients, pending, "TUI", bytes).await;
                }
                for target in ["Firewall", "Daemon", "DiscordBot"] {
                    deliver(router, clients, pending, target, payload.to_vec()).await;
                }
            }
        }
        FireWhalMessage::Pong(_) => {
            deliver(router, clients, pending, "TUI", payload.to_vec()).await;
        }

        // --- Discord notifications ---
        FireWhalMessage::DiscordBlockNotify(_) => {
            deliver(router, clients, pending, "DiscordBot", payload.to_vec()).await;
        }

        // --- Permissive mode ---
        FireWhalMessage::EnablePermissiveMode(msg) => {
            if msg.component == "TUI" {
                deliver(router, clients, pending, "Firewall", payload.to_vec()).await;
            }
        }
        FireWhalMessage::DisablePermissiveMode(msg) => {
            if msg.component == "TUI" {
                deliver(router, clients, pending, "Firewall", payload.to_vec()).await;
            }
        }
        FireWhalMessage::PermissiveModeTuple(msg) => {
            if msg.component == "Firewall" {
                deliver(router, clients, pending, "TUI", payload.to_vec()).await;
            }
        }

        // --- App/rule management (TUI <-> Daemon) ---
        FireWhalMessage::AddAppIds(msg) => {
            if msg.component == "TUI" {
                deliver(router, clients, pending, "Daemon", payload.to_vec()).await;
            }
        }
        FireWhalMessage::RulesRequest(msg) => {
            if msg.component == "TUI" {
                deliver(router, clients, pending, "Daemon", payload.to_vec()).await;
            }
        }
        FireWhalMessage::RulesResponse(_) => {
            deliver(router, clients, pending, "TUI", payload.to_vec()).await;
        }
        FireWhalMessage::UpdateRules(_) => {
            deliver(router, clients, pending, "Daemon", payload.to_vec()).await;
        }
        FireWhalMessage::AppsRequest(msg) => {
            if msg.component == "TUI" {
                deliver(router, clients, pending, "Daemon", payload.to_vec()).await;
            }
        }
        FireWhalMessage::AppsResponse(_) => {
            deliver(router, clients, pending, "TUI", payload.to_vec()).await;
        }
        FireWhalMessage::UpdateAppIds(_) => {
            deliver(router, clients, pending, "Daemon", payload.to_vec()).await;
        }
        FireWhalMessage::HashRequest(_) => {
            deliver(router, clients, pending, "Daemon", payload.to_vec()).await;
        }
        FireWhalMessage::HashResponse(_) => {
            deliver(router, clients, pending, "TUI", payload.to_vec()).await;
        }
        FireWhalMessage::HashUpdateRequest(_) => {
            deliver(router, clients, pending, "Daemon", payload.to_vec()).await;
        }
        FireWhalMessage::HashUpdateResponse(_) => {
            deliver(router, clients, pending, "TUI", payload.to_vec()).await;
        }

        // CommandShutdown and RuleAddBlock currently have no route.
        _ => {}
    }
}

/// Serves on a bound router socket until the transport dies.
async fn serve(
    router: &mut RouterSocket,
    clients: &mut HashMap<String, Vec<u8>>,
    pending: &mut HashMap<String, Vec<Vec<u8>>>,
) -> Result<(), ()> {
    let bincode_config = bincode::config::standard().with_big_endian();

    loop {
        let frames = router.recv().await.map_err(|_| ())?;
        if frames.len() < 2 {
            // Identity-only frame: a peer closed. It will reconnect and
            // re-register on its side; nothing to do here.
            continue;
        }
        let sender_identity = frames.get(0).unwrap();
        let payload = frames.get(1).unwrap();

        let Ok((message, _)) = bincode::decode_from_slice::<FireWhalMessage, _>(payload, bincode_config) else {
            eprintln!("[ROUTER] Received malformed message, skipping.");
            continue;
        };
        let payload_bytes = payload.to_vec();

        route_message(router, clients, pending, &message, sender_identity, &payload_bytes).await;
    }
}

/// Runs the IPC router on `endpoint` forever, rebinding if the transport dies.
///
/// `drop_privileges` enables the production hardening (socket chown to
/// `firewhal-admin`, mode 0770, setuid to `nobody`). Pass `false` in tests.
pub async fn run_router(endpoint: String, drop_privileges: bool) -> Result<(), Box<dyn Error + Send + Sync>> {
    let socket_path = endpoint
        .strip_prefix("ipc://")
        .ok_or("Router endpoint must be an ipc:// endpoint.")?
        .to_string();

    let mut privileges_dropped = false;

    loop {
        // Remove a stale socket file left by a previous (crashed) run, then
        // bind.
        if Path::new(&socket_path).exists() {
            if let Err(e) = fs::remove_file(&socket_path) {
                eprintln!("[ROUTER] Could not remove stale socket file {}: {}", socket_path, e);
            }
        }

        let mut router = RouterSocket::new();
        match router.bind(&endpoint).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("[ROUTER] Failed to bind to {}: {}. Retrying in 1s.", endpoint, e);
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        }
        println!("[ROUTER] IPC router bound to {}", endpoint);

        if !privileges_dropped && drop_privileges {
            let admin_group = Group::from_name("firewhal-admin")?
                .ok_or("CRITICAL: 'firewhal-admin' group not found.")?;
            chown(socket_path.as_str(), None, Some(admin_group.gid))?;
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o770))?;
            println!("[ROUTER] Socket permissions set securely.");

            let target_user = User::from_name("nobody")?
                .ok_or("CRITICAL: 'nobody' user not found.")?;
            setgid(target_user.gid)?;
            setuid(target_user.uid)?;
            println!("[ROUTER] Privileges dropped to 'nobody'.");
            privileges_dropped = true;
        }

        // Client identities live with the socket; a rebind invalidates them
        // and every client will reconnect and re-register itself. Buffered
        // messages are tied to the same lifecycle: old identities are gone,
        // so anything buffered for them is stale too.
        let mut clients: HashMap<String, Vec<u8>> = HashMap::new();
        let mut pending: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        serve(&mut router, &mut clients, &mut pending).await;

        eprintln!("[ROUTER] Transport error; rebinding in 200ms...");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
