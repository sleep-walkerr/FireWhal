//! ZMQ IPC Router for Firewhal
//! Binds a ROUTER socket to an IPC endpoint and sets secure permissions.
//! This application must be started as root. It will drop privileges after setup.

use nix::unistd::{chown, setgid, setuid, Group, User};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::str;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let context = zmq::Context::new();
    let router = context.socket(zmq::ROUTER)?;

    let socket_path_str = "ipc:///tmp/firewhal_ipc.sock";
    router.bind(socket_path_str)?;
    println!("[ROUTER] IPC router bound to {}", socket_path_str);

    // --- PRIVILEGED SETUP (as root) ---
    let fs_path = socket_path_str.replace("ipc://", "");
    let admin_group = Group::from_name("firewhal-admin")?
        .ok_or("[ROUTER] CRITICAL: 'firewhal-admin' group not found.")?;
    chown(fs_path.as_str(), None, Some(admin_group.gid))
        .map_err(|e| format!("[ROUTER] CRITICAL: Failed to chown socket: {}", e))?;
    fs::set_permissions(&fs_path, fs::Permissions::from_mode(0o770))
        .map_err(|e| format!("[ROUTER] CRITICAL: Failed to set socket permissions: {}", e))?;
    println!("[ROUTER] Socket permissions set securely.");

    // --- DROP PRIVILEGES ---
    let target_user = User::from_name("nobody")?
        .ok_or("[ROUTER] CRITICAL: 'nobody' user not found.")?;
    setgid(target_user.gid).map_err(|e| format!("[ROUTER] CRITICAL: Failed to set gid: {}", e))?;
    setuid(target_user.uid).map_err(|e| format!("[ROUTER] CRITICAL: Failed to set uid: {}", e))?;
    println!("[ROUTER] Privileges dropped. Now running as 'nobody'.");

    let mut discord_bot_identity: Option<Vec<u8>> = None;
    let mut tui_identity: Option<Vec<u8>> = None;
    let mut kernel_identity: Option<Vec<u8>> = None;

    loop {
        let multipart = router.recv_multipart(0)?;
        let identity = &multipart[0];
        // It's possible to receive a message with only an identity (e.g., on disconnect)
        // so we guard against panics here.
        // **THE FIX**: Ensure both branches of the if/else return a `&[u8]` slice.
        let message_data: &[u8] = if multipart.len() > 1 { &multipart[1] } else { b"" };


        if let Ok(msg_str) = str::from_utf8(message_data) {
            println!("[ROUTER] Received message: '{}' from {:?}", msg_str, identity);

            // Forward all non-TUI registration messages to the TUI for debugging.
            if let Some(tui_id) = &tui_identity {
                if msg_str != "TUI_READY" {
                    // This is multipart: [TUI_ID, "", PAYLOAD]
                    router.send(tui_id, zmq::SNDMORE)?;
                    router.send(&[] as &[u8], zmq::SNDMORE)?;
                    router.send(&format!("[From: {:?}] {}", identity, msg_str), 0)?;
                }
            }

            match msg_str {
                "DISCORD_BOT_READY" => discord_bot_identity = Some(identity.to_vec()),
                "TUI_READY" => tui_identity = Some(identity.to_vec()),
                "KERNEL_READY" => kernel_identity = Some(identity.to_vec()),
                "CMD:SHUTDOWN:firewall" => {
                    if let Some(kernel_id) = &kernel_identity {
                        println!("[ROUTER] Forwarding shutdown command to firewall kernel.");
                        // Also need the delimiter here for the kernel's DEALER socket.
                        router.send(kernel_id, zmq::SNDMORE)?;
                        router.send(&[] as &[u8], zmq::SNDMORE)?;
                        router.send("CMD:SHUTDOWN:firewall", 0)?;
                    }
                }
                _ => {} // Ignore other messages for now
            }
        }
    }
}

