//! ZMQ IPC Router for Firewhal (Updated for AppMessage)
//! Binds a ROUTER socket, sets permissions, drops privileges,
//! and forwards debug messages to the TUI.
use bincode::{self, config};
use firewhal_core::{
    ApplicationAllowlistConfig, DebugMessage, FireWhalConfig, FireWhalMessage,
    NetInterfaceRequest, NetInterfaceResponse, StatusPing, StatusPong, StatusUpdate,
};
use nix::unistd::{chown, setgid, setuid, Group, User};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use zeromq::{RouterSocket, Socket, SocketRecv, SocketSend, ZmqMessage};
use bytes::Bytes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut router = RouterSocket::new();
    let socket_path_str = "ipc:///tmp/firewhal_ipc.sock";
    router.bind(socket_path_str).await?;
    println!("[ROUTER] IPC router bound to {}", socket_path_str);

    // --- PRIVILEGED SETUP (as root) ---
    // This entire section remains the same as it's already using best practices.
    let fs_path = socket_path_str.replace("ipc://", "");
    let admin_group = Group::from_name("firewhal-admin")?
        .ok_or("CRITICAL: 'firewhal-admin' group not found.")?;
    chown(fs_path.as_str(), None, Some(admin_group.gid))?;
    fs::set_permissions(&fs_path, fs::Permissions::from_mode(0o770))?;
    println!("[ROUTER] Socket permissions set securely.");

    // --- DROP PRIVILEGES ---
    let target_user = User::from_name("nobody")?
        .ok_or("CRITICAL: 'nobody' user not found.")?;
    setgid(target_user.gid)?;
    setuid(target_user.uid)?;
    println!("[ROUTER] Privileges dropped. Now running as 'nobody'.");

    // Use a HashMap to store client identities for scalability.
    let mut clients: HashMap<String, Bytes> = HashMap::new();
    let bincode_config = bincode::config::standard().with_big_endian();

    println!("[ROUTER] Waiting for clients to connect...");
    loop {
        // A ROUTER socket receives multipart messages: [identity, payload]
        let multipart = router.recv().await?;
        let mut frames = multipart.into_vecdeque();
        
        println!("Received message");
        
        let mut identity = Bytes::new();
        let mut payload = Bytes::new();

        // Extract
        if let (Some(identity_frame), Some(payload_frame)) = (frames.pop_front(), frames.pop_front()) {
            identity = identity_frame;
            payload = payload_frame;
        }

        // Attempt to decode the payload into our AppMessage enum.
        let Ok((message, _)) = bincode::decode_from_slice::<FireWhalMessage, _>(&payload, bincode_config) else {
            eprintln!("[ROUTER] Received malformed message from {:?}, skipping.", identity);
            continue;
        };

        let mut source_component = "Unknown".to_string();

        // --- CLIENT IDENTIFICATION & MESSAGE HANDLING ---
        match &message {
            // Status registration message processing
            FireWhalMessage::Status(StatusUpdate { component, message, .. }) if message == "Ready" => {
                println!("[ROUTER] Registered client '{}' with identity {:?}", component, identity);
                source_component = component.clone();
                clients.insert(component.clone(), identity.clone());


                // Forward the registration message to the Daemon so it knows the Firewall is ready.
                if component != "Daemon" { // Don't forward the daemon's own ready message back to itself
                    if let Some(daemon_id) = clients.get("Daemon").cloned() {
                        // `payload` is the original, raw byte slice of the message
                        // Craft zmq message
                        let mut message_to_send = ZmqMessage::from(payload.clone());   
                        message_to_send.push_front(daemon_id);

                        router.send(message_to_send).await?;
                        
                    }
                }

                // Test Code 
                let mut message_to_send = ZmqMessage::from(identity.clone()); 
                message_to_send.push_back(payload);
                router.send(message_to_send).await?;
            
                
            }
            // Debug Message processing
            FireWhalMessage::Debug(DebugMessage { source, .. }) => {
                source_component = source.clone();
                // If a message somehow came from the TUI, don't forward it to itself
                if source_component != "TUI" {
                    // Check if the TUI client has registered itself yet.
                    if let Some(tui_id) = clients.get("TUI").cloned() {
                        // Create a new DebugMessage to forward. This ensures all forwarded
                        // messages have a consistent, debug-friendly format.
                        let debug_forward = FireWhalMessage::Debug(DebugMessage {
                            source: source_component,
                            content: format!("{:?}", message), // The content is the debug view of the original message
                        });

                        // Re-encode the new debug message to send to the TUI.
                        if let Ok(forward_payload) = bincode::encode_to_vec(&debug_forward, bincode_config) {
                            // Send as [tui_identity, payload]
                            let mut message_to_send = ZmqMessage::from(payload.clone());   
                            message_to_send.push_front(tui_id);

                            router.send(message_to_send).await?;
                        }
                    }
                }
            }
            // FireWall Config message processing
            FireWhalMessage::LoadRules(_) => {
                source_component = "Daemon".to_string(); // Add check here to make sure that it's coming from the Daemon

                if let Some(firewall_identity) = clients.get("Firewall").cloned() {
                    println!("[ROUTER] Forwarding LoadRules command to firewall.");
                    let mut message_to_send = ZmqMessage::from(payload.clone());   
                    message_to_send.push_front(firewall_identity);

                    router.send(message_to_send).await?;
                } else {
                    eprintln!("[ROUTER] Received LoadRules command, but firewall client is not registered!");

                }
            }
            FireWhalMessage::LoadAppIds(_) => {
                source_component = "Daemon".to_string();

                if let Some(firewall_identity) = clients.get("Firewall").cloned() {
                    println!("[ROUTER] Forwarding AppIDsUpdate command to firewall.");
                    let mut message_to_send = ZmqMessage::from(payload.clone());   
                        message_to_send.push_front(firewall_identity);

                        router.send(message_to_send).await?;
                } else {
                    eprintln!("[ROUTER] Received AppIDsUpdate command, but firewall client is not registered!");

                } 
            }
            // // Interface Request message processing
            // FireWhalMessage::InterfaceRequest(NetInterfaceRequest {source}) => {
            //     source_component = source.clone();
            //     if &source_component == "TUI" {
            //         if let Some(daemon_identity) = clients.get("Daemon").cloned() {
            //             println!("[ROUTER] Forwarding InterfaceRequest command to daemon.");
            //             router.send(vec![daemon_identity.clone(), payload.into()].into()).await?;
            //         } else {
            //             eprintln!("[ROUTER] Received InterfaceRequest command, but daemon client is not registered!");
            //         }
            //     }
            // }
            // // Interface Response message processing
            // FireWhalMessage::InterfaceResponse(NetInterfaceResponse {source, ..}) => {
            //     source_component = source.clone();
            //     if source_component == "Daemon" {
            //         println!("[ROUTER] Forwarding InterfaceResponse from daemon to TUI.");
            //         if let Some(tui_identity) = clients.get("TUI").cloned() {
            //             router.send(vec![tui_identity.clone(), payload.into()].into()).await?;
            //         } else {
            //             eprintln!("[ROUTER] Received InterfaceResponse, but TUI client is not registered!");
            //         }
            //     }
            // }
            // // Load Interface State message processing
            // FireWhalMessage::LoadInterfaceState(_) => {
            //     source_component = "Daemon".to_string();

            //     if let Some(firewall_identity) = clients.get("Firewall").cloned() {
            //         println!("[ROUTER] Forwarding LoadInterfaceState command to firewall.");
            //         router.send(vec![firewall_identity.clone(), payload.into()].into()).await?;
            //     } else {
            //         eprintln!("[ROUTER] Received LoadInterfaceState command, but firewall client is not registered!");
            //     }
            // }   
            // // Update Interfaces message processing
            // FireWhalMessage::UpdateInterfaces(update) => {
            //     source_component = update.source.clone();
            //     if source_component == "TUI" {
            //         if let Some(daemon_identity) = clients.get("Daemon").cloned() {
            //             println!("[ROUTER] Forwarding UpdateInterfaces command to daemon.");
            //             router.send(vec![daemon_identity.clone(), payload.into()].into()).await?;
            //         } else {
            //             eprintln!("[ROUTER] Received UpdateInterfaces command, but daemon client is not registered!");
            //         }
            //     }
            // }
            // Ping message processing
            FireWhalMessage::Ping(StatusPing {source}) => {
                source_component = source.clone();
                if source_component == "TUI" {
                    if let Some(tui_identity) = clients.get("TUI").cloned() {
                        println!("[ROUTER] Sending Pong command to TUI.");
                        let pong_message = FireWhalMessage::Pong( StatusPong {
                            source: "IPC".to_string()
                        });
                        let pong_payload = bincode::encode_to_vec(&pong_message, bincode_config)?;
                        let mut message_to_send = ZmqMessage::from(payload.clone());   
                        message_to_send.push_front(tui_identity);

                        router.send(message_to_send).await?;
                    } 
                    
                    if let Some(firewall_identity) = clients.get("Firewall").cloned() {
                        println!("[ROUTER] Forwarding Ping command to firewall.");
                        let mut message_to_send = ZmqMessage::from(payload.clone());   
                        message_to_send.push_front(firewall_identity);

                        router.send(message_to_send).await?;
                    } 
                    if let Some(daemon_identity) = clients.get("Daemon").cloned() {
                        println!("[ROUTER] Forwarding Ping command to daemon.");
                        let mut message_to_send = ZmqMessage::from(payload.clone());   
                        message_to_send.push_front(daemon_identity);

                        router.send(message_to_send).await?;
                    }
                    if let Some(discord_identity) = clients.get("DiscordBot").cloned() {
                        println!("[ROUTER] Forwarding Ping command to DiscordBot.");
                        let mut message_to_send = ZmqMessage::from(payload.clone());   
                        message_to_send.push_front(discord_identity);

                        router.send(message_to_send).await?;
                    }
                } else { println!("[Router] Received Ping message, but source is not TUI.")}
            }
            // Pong message processing
            FireWhalMessage::Pong(_) => {
                if let Some(tui_identity) = clients.get("TUI").cloned() {
                    println!("[ROUTER] Forwarding Pong command to TUI.");
                    let mut message_to_send = ZmqMessage::from(payload.clone());   
                        message_to_send.push_front(tui_identity);

                        router.send(message_to_send).await?;
                }
            }
            // FireWhalMessage::DiscordBlockNotify(_) => {
            //     if let Some(discord_identity) = clients.get("DiscordBot").cloned() {
            //         println!("[ROUTER] Forwarding DiscordBlockNotify command to DiscordBot.");
            //         router.send(vec![discord_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::EnablePermissiveMode(message) => {
            //     if let Some(firewall_identity) = clients.get("Firewall").cloned() && message.component == "TUI" {
            //         println!("[ROUTER] Forwarding EnablePermissiveMode command to Firewall.");
            //         router.send(vec![firewall_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::DisablePermissiveMode(message) => {
            //     if let Some(firewall_identity) = clients.get("Firewall").cloned() && message.component == "TUI" {
            //         println!("[ROUTER] Forwarding DisablePermissiveMode command to Firewall.");
            //         router.send(vec![firewall_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::PermissiveModeTuple(message) => {
            //     if let Some(tui_identity) = clients.get("TUI").cloned() && message.component == "Firewall" {
            //         println!("[ROUTER] Forwarding PermissiveModeTuple to TUI.");
            //        router.send(vec![tui_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::AddAppIds(message) => {
            //     if let Some(daemon_identity) = clients.get("Daemon").cloned() && message.component == "TUI" {
            //         println!("[ROUTER] Forwarding AddAppIds to Daemon.");
            //         router.send(vec![daemon_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::RulesRequest(message) => {
            //     if let Some(daemon_identity) = clients.get("Daemon").cloned() && message.component == "TUI" {
            //         println!("[ROUTER] Forwarding RuleRequest to Daemon.");
            //         router.send(vec![daemon_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::RulesResponse(message) => {
            //     if let Some(tui_identity) = clients.get("TUI").cloned() {
            //         println!("[ROUTER] Forwarding RuleResponse to TUI.");
            //         router.send(vec![tui_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::UpdateRules(message) => {
            //     if let Some(daemon_identity) = clients.get("Daemon").cloned() {
            //         println!("[ROUTER] Forwarding UpdateRules to Daemon.");
            //         router.send(vec![daemon_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::AppsRequest(message) => {
            //     if let Some(daemon_identity) = clients.get("Daemon").cloned() && message.component == "TUI" {
            //         println!("[ROUTER] Forwarding AppsRequest to Daemon.");
            //         router.send(vec![daemon_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::AppsResponse(message) => {
            //     if let Some(tui_identity) = clients.get("TUI").cloned() {
            //         println!("[ROUTER] Forwarding AppsResponse to TUI.");
            //         router.send(vec![tui_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::UpdateAppIds(_) => {
            //     if let Some(daemon_identity) = clients.get("Daemon").cloned() {
            //         println!("[ROUTER] Forwarding UpdateAppIds to Daemon.");
            //         router.send(vec![daemon_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::HashRequest(_) => {
            //     if let Some(daemon_identity) = clients.get("Daemon").cloned() {
            //         println!("[ROUTER] Forwarding HashesRequest to Daemon.");
            //         router.send(vec![daemon_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::HashResponse(_) => {
            //     if let Some(tui_identity) = clients.get("TUI").cloned() {
            //         println!("[ROUTER] Forwarding HashesResponse to TUI.");
            //         router.send(vec![tui_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::HashUpdateRequest(_) => {
            //     if let Some(daemon_identity) = clients.get("Daemon").cloned() {
            //         println!("[ROUTER] Forwarding HashUpdateRequest to Daemon.");
            //         router.send(vec![daemon_identity.clone(), payload.into()].into()).await?;
            //     }
            // }
            // FireWhalMessage::HashUpdateResponse(_) => {
            //     if let Some(tui_identity) = clients.get("TUI").cloned() {
            //         println!("[ROUTER] Forwarding HashUpdateResponse to TUI.");
            //         router.send(vec![tui_identity.clone(), payload.into()].into()).await?;
            //     }
            
            // }
            _ => {
                // For other messages, we might not know the source component unless it's registered.
                // We'll just identify it by its raw identity for the debug message.
                source_component = format!("{:?}", identity);
            }
        }
    }
}