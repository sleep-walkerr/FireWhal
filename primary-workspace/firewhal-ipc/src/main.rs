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
    assert!(router.bind(socket_path_str).is_ok());
    println!("[ROUTER] IPC router bound to {}", socket_path_str);

    // --- PRIVILEGED SETUP (as root) ---
    let fs_path = socket_path_str.replace("ipc://", "");
    println!("[ROUTER] Setting secure permissions for socket at {}", fs_path);

    // 1. Find the GID of the 'firewhal-admin' group.
    let admin_group = Group::from_name("firewhal-admin")?
        .ok_or("[ROUTER] CRITICAL: 'firewhal-admin' group not found.")?;

    // 2. Change the group ownership of the socket file.
    chown(fs_path.as_str(), None, Some(admin_group.gid))
        .map_err(|e| format!("[ROUTER] CRITICAL: Failed to chown socket: {}", e))?;

    // 3. Set permissions to rwxrwx---.
    fs::set_permissions(&fs_path, fs::Permissions::from_mode(0o770))
        .map_err(|e| format!("[ROUTER] CRITICAL: Failed to set socket permissions: {}", e))?;

    println!("[ROUTER] Socket permissions set securely.");

    // --- DROP PRIVILEGES ---
    let target_user = User::from_name("nobody")?
        .ok_or("[ROUTER] CRITICAL: 'nobody' user not found.")?;

    setgid(target_user.gid).map_err(|e| format!("[ROUTER] CRITICAL: Failed to set gid: {}", e))?;
    setuid(target_user.uid).map_err(|e| format!("[ROUTER] CRITICAL: Failed to set uid: {}", e))?;

    println!("[ROUTER] Privileges dropped. Now running as 'nobody'.");
    // --- END PRIVILEGED OPERATIONS ---

    let mut discord_bot_identity: Option<Vec<u8>> = None;
    let mut tui_identity: Option<Vec<u8>> = None;

    loop {
        let multipart = router.recv_multipart(0)?;
        let identity = multipart[0].to_vec();
        let message_data = &multipart[1];

        if let Ok(msg_str) = str::from_utf8(message_data) {
            println!("[ROUTER] Received message: '{}'", msg_str);

            if let Some(tui_id) = &tui_identity {
                if msg_str != "TUI_READY" {
                    println!("[ROUTER] Forwarding message to TUI.");
                    router.send(tui_id, zmq::SNDMORE)?;
                    router.send(&format!("{:?} {}", identity, msg_str), 0)?;
                }
            }

            match msg_str {
                "DISCORD_BOT_READY" => {
                    println!("[ROUTER] Discord bot has connected and identified itself.");
                    discord_bot_identity = Some(identity);
                }
                "TUI_READY" => {
                    println!("[ROUTER] TUI has connected and identified itself.");
                    tui_identity = Some(identity);
                }
                "File hash changed" => {
                    if let Some(bot_id) = &discord_bot_identity {
                        println!("[ROUTER] Trigger met. Sending notification to Discord bot.");
                        router.send(bot_id, zmq::SNDMORE)?;
                        router.send("Send Notification", 0)?;
                    } else {
                        println!("[ROUTER] Trigger met, but Discord bot is not yet identified.");
                    }
                }
                "CMD:SHUTDOWN:firewall" => {
                    println!("[ROUTER] Received shutdown command for firewall.");
                    // In a real implementation, you'd need the firewall's ZMQ ID to forward this.
                }
                _ => {}
            }
        } else {
            println!("[ROUTER] Received a non-UTF8 message.");
        }
    }
}