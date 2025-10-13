use std::{fmt, fs};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use bincode::{config, Encode, Decode};
//use serde::de::{value, Error};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task;
use zmq::Context;
use tokio::time::{sleep, Duration, timeout};

//Test error implementation for Zero Message Queue related functionalities
#[derive(Debug)]
pub enum IpcError {
    Zmq(zmq::Error),
    Deserialization(String),
}

// Allow our error to be displayed
impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IpcError::Zmq(e) => write!(f, "ZMQ Error: {}", e),
            IpcError::Deserialization(e) => write!(f, "Deserialization Error: {}", e),
        }
    }
}

// Allow our error to be treated as a standard error
impl std::error::Error for IpcError {}



// ZMQ dealer client to be used by IPC clients
// One function instead of have a separate implementation inside of each subprogram
/// A task that handles two-way ZMQ communication.
pub async fn zmq_client_connection(
    mut to_zmq_rx: mpsc::Receiver<FireWhalMessage>,
    from_zmq_tx: mpsc::Sender<FireWhalMessage>,
    mut shutdown_rx: broadcast::Receiver<()>,
    component: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    
    let config = bincode::config::standard().with_big_endian();
    let context = zmq::Context::new();
    let socket = context.socket(zmq::DEALER)?;

    // Set ZMQ_IMMEDIATE to 0. This makes the .connect() call block until the
    // connection is fully established, preventing the "slow joiner" problem where
    // the first message can be silently dropped.
    socket.set_immediate(false)?;
    socket.connect("ipc:///tmp/firewhal_ipc.sock")?;

    println!("[{component} IPC Client] Connected to IPC router.");

    loop {
        tokio::select! {
            // Branch 1: Listen for shutdown signal.
            _ = shutdown_rx.recv() => {
                println!("[{component} IPC Client] Shutdown signal received. Terminating.");
                break; // Exit the loop
            },
            // Branch 2: Handle messages from the component TO the router
            Some(message) = to_zmq_rx.recv() => {
                if let Ok(payload) = bincode::encode_to_vec(&message, config) {
                    if socket.send(&payload, 0).is_err() {
                        eprintln!("[{component} IPC Client] Failed to send message to router.");
                    }
                }
            },

            // Branch 3: Poll for messages FROM the router
            _ = sleep(Duration::from_millis(1)) => {
                // Use a loop to drain any messages that have queued up
                loop {
                    // Poll the socket without blocking
                    match socket.recv_multipart(zmq::DONTWAIT) {
                        Ok(multipart) => {
                            if multipart.is_empty() { continue; }
                            let payload = &multipart[0];

                            match bincode::decode_from_slice::<FireWhalMessage, _>(payload, config) {
                                Ok((message, _)) => {
                                    if from_zmq_tx.send(message).await.is_err() {
                                        return Ok(()); // Component is gone, shut down.
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[{component} IPC Client] Received malformed message, discarding. Error: {}", e);
                                }
                            }
                        },
                        Err(zmq::Error::EAGAIN) => {
                            // No message was waiting, so we break the inner loop.
                            break;
                        },
                         Err(e) => {
                            eprintln!("[{component} IPC Client] ZMQ receive error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    }
    println!("[{component} IPC Client] Disconnected.");
    Ok(())
}

/// Serializes and sends any AppMessage over a ZMQ socket using bincode 2.0.
pub fn send_message(socket: &zmq::Socket, message: &FireWhalMessage) -> Result<(), zmq::Error> {
    // 1. Get the standard bincode configuration.
    let config = bincode::config::standard().with_big_endian();
    // 2. Encode the message directly into a Vec<u8>.
    let bytes = bincode::encode_to_vec(message, config)
        .expect("Failed to encode AppMessage");
    socket.send(&bytes, 0)
}

/// Receives and deserializes an AppMessage from a ZMQ socket using bincode 2.0.
pub fn recv_message(socket: &zmq::Socket) -> Result<FireWhalMessage, IpcError> {
    let bytes = socket.recv_bytes(0).map_err(IpcError::Zmq)?;

    // 1. Get the standard bincode configuration.
    let config = bincode::config::standard().with_big_endian();
    // 2. Decode the message from the received byte slice.
    let (message, len) = bincode::decode_from_slice(&bytes, config)
            .map_err(|e| IpcError::Deserialization(e.to_string()))?;

    // The `decode_from_slice` function also returns the number of bytes read.
    // You can use `len` to confirm the entire message was consumed, if needed.
    //println!("Decoded {} bytes.", len);

    Ok(message)
}


// DATA STRUCTURES


#[derive(Encode, Decode, Debug, Clone)]
pub enum Action {
    Allow,
    Deny
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum Protocol {
    Tcp = 6,
    Udp = 17,
    Icmp = 1
}


#[derive(Debug, Encode, Decode, Clone)]
pub struct Rule {
    pub action: Action,
    pub protocol: Protocol,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub description: String,
}

#[derive(Debug, Encode, Decode, Clone)]
pub struct FirewallConfig {
    pub rules: Vec<Rule>,
}


#[derive(Encode, Decode, Debug, Clone)]
pub enum FireWhalMessage {
    CommandShutdown(ShutdownCommand),
    RuleAddBlock(BlockAddressRule),
    Status(StatusUpdate),
    Debug(DebugMessage),
    LoadRules(FirewallConfig),
    InterfaceRequest(NetInterfaceRequest),
    InterfaceResponse(NetInterfaceResponse),
    UpdateInterfaces(UpdateInterfaces),
    Ping(StatusPing),
    Pong(StatusPong),
    DiscordBlockNotify(DiscordBlockNotification),
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct DiscordBlockNotification {
    pub component: String,
    pub content: String
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct StatusPing {
    pub source: String,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct StatusPong {
    pub source: String,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct UpdateInterfaces {
    pub source: String,
    pub interfaces: Vec<String>,
}


#[derive(Encode, Decode, Debug, Clone)]
pub struct NetInterfaceRequest {
    pub source: String,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct NetInterfaceResponse {
    pub source: String,
    pub interfaces: Vec<String>,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct StatusUpdate {
    pub component: String,
    pub is_healthy: bool,
    pub message: String, // e.g., "Ready", "Shutting down", "Error state"
}


#[derive(Encode, Decode, Debug, Clone)]
pub struct DebugMessage {
    pub source: String, // Changed from `component` for consistency
    pub content: String, // Changed from `message` for clarity
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct ShutdownCommand {
    pub target: String,
    pub delay_ms: u64,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct BlockAddressRule {
    pub source: String,
    pub address: String,
}
