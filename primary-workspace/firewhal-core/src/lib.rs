use std::fmt;
use bincode::{config, Encode, Decode};
use serde::de::{value, Error};
use serde::{Serialize, Deserialize};
use tokio::sync::{broadcast, mpsc, Mutex};
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
async fn zmq_bidi_client_task(
    // For sending messages TO the ZMQ router
    mut outgoing_rx: mpsc::Receiver<FireWhalMessage>,
    // For sending messages FROM the ZMQ router back to our app
    incoming_tx: mpsc::Sender<FireWhalMessage>,
) {
    let task = task::spawn_blocking(move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let context = zmq::Context::new();
        let dealer = context.socket(zmq::DEALER)?;
        dealer.connect("ipc:///tmp/firewhal_ipc.sock")?;
        println!("[ZMQ-Bidi-Client] Successfully connected to IPC router.");

        // 1. Set up poll item for the ZMQ socket to listen for incoming messages.
        let mut poll_items = [dealer.as_poll_item(zmq::POLLIN)];

        loop {
            // 2. Handle outgoing messages first (non-blocking).
            // This drains any queued messages before we wait.
            while let Ok(msg) = outgoing_rx.try_recv() {
                println!("[ZMQ-Bidi-Client] Sending message: {:?}", msg);
                if let Err(e) = send_message(&dealer, &msg) {
                    eprintln!("[ZMQ-Bidi-Client] Failed to send message: {}", e);
                    return Err(e.into()); // Exit on error
                }
            }

            // 3. Poll for incoming ZMQ messages with a timeout (e.g., 100ms).
            // This is the only part that blocks, and only for a short time.
            let rc = zmq::poll(&mut poll_items, 100)?;

            if rc > 0 {
                if poll_items[0].is_readable() {
                    // 4. If a message is ready, receive it.
                    match recv_message(&dealer) {
                        Ok(msg) => {
                            println!("[ZMQ-Bidi-Client] Received message: {:?}", msg);
                            // 5. Send it back to the main app via the incoming channel.
                            if incoming_tx.blocking_send(msg).is_err() {
                                // Main app has shut down the receiver, so we can exit.
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("[ZMQ-Bidi-Client] Error receiving message: {}", e);
                            break; // Exit on receive error
                        }
                    }
                }
            }

            // Check if the outgoing channel has been closed. If so, we are done sending.
            if outgoing_rx.is_closed() {
                println!("[ZMQ-Bidi-Client] Outgoing channel closed. Shutting down.");
                break;
            }
        }
        Ok(())
    });

    if let Err(e) = task.await {
        eprintln!("[ZMQ-Bidi-Client] Task failed: {}", e);
    }
}

/// Serializes and sends any AppMessage over a ZMQ socket using bincode 2.0.
pub fn send_message(socket: &zmq::Socket, message: &FireWhalMessage) -> Result<(), zmq::Error> {
    // 1. Get the standard bincode configuration.
    let config = config::standard();
    // 2. Encode the message directly into a Vec<u8>.
    let bytes = bincode::encode_to_vec(message, config)
        .expect("Failed to encode AppMessage");

    socket.send(&bytes, 0)
}

/// Receives and deserializes an AppMessage from a ZMQ socket using bincode 2.0.
pub fn recv_message(socket: &zmq::Socket) -> Result<FireWhalMessage, IpcError> {
    let bytes = socket.recv_bytes(0).map_err(IpcError::Zmq)?;

    // 1. Get the standard bincode configuration.
    let config = config::standard();
    // 2. Decode the message from the received byte slice.
    let (message, len) = bincode::decode_from_slice(&bytes, config)
            .map_err(|e| IpcError::Deserialization(e.to_string()))?;

    // The `decode_from_slice` function also returns the number of bytes read.
    // You can use `len` to confirm the entire message was consumed, if needed.
    println!("Decoded {} bytes.", len);

    Ok(message)
}




#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub enum FireWhalMessage { // Have one single enum type that all structs fit into (for type safety)
    CommandShutdown(ShutdownCommand),
    RuleAddBlock(BlockAddressRule),
    Status(StatusUpdate),
    Debug(DebugMessage)
}


#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub struct ShutdownCommand {
    pub target: String,
    pub delay_ms: u64,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub struct BlockAddressRule {
    pub source: String,
    pub address: String,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub struct StatusUpdate {
    pub component: String,
    pub is_healthy: bool,
    pub message: String,
}


#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub struct DebugMessage {
    pub component: String,
    pub message: String,
}

// *** This is a sample, change me later
// Example in firewhal-core/src/lib.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)] // Added Serialize, Deserialize if needed for config
// #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Action {
    Allow,
    Deny,
    Log,
}

#[derive(Debug, Clone, PartialEq)] // Added Serialize, Deserialize if rules are stored/transferred
// #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FirewallRule {
    pub id: u32,
    pub source_ip: Option<std::net::IpAddr>,
    pub destination_ip: Option<std::net::IpAddr>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>, // e.g., "TCP", "UDP", "ICMP"
    pub action: Action,
    pub description: String,
    pub enabled: bool,
}
// Example in firewhal-core/src/lib.rs
#[derive(Debug, Clone, PartialEq)] // Added Serialize, Deserialize if events are stored/transferred
// #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DaemonEvent {
    RuleTriggered { rule_id: u32, details: String },
    ConnectionBlocked { source_ip: std::net::IpAddr, destination_port: u16 },
    StatusUpdate { message: String },
    // ... other event types
}
// Example in firewhal-core/src/lib.rs
#[derive(Debug, Clone, PartialEq)] // Add Serialize, Deserialize from serde for config
// #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DaemonConfig {
    pub log_level: String,
    pub default_policy: Action,
    // ... other daemon settings
}

#[derive(Debug, Clone, PartialEq)] // Add Serialize, Deserialize from serde for config
// #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppConfig {
    pub daemon: DaemonConfig,
    pub discord_bot_token: Option<String>, // Or handle this separately
    // ... other global settings
}
// Example in firewhal-core/src/lib.rs
#[derive(Debug)]
pub enum FirewhalError {
    ConfigError(String),
    RuleParseError(String),
    IoError(std::io::Error),
    DaemonCommunicationError(String),
    // ... other error types
    #[cfg(feature = "serde_json")]
    SerializationError(serde_json::Error),
}

// Implement From traits for easier error conversion
impl From<std::io::Error> for FirewhalError {
    fn from(err: std::io::Error) -> Self {
        FirewhalError::IoError(err)
    }
}

#[cfg(feature = "serde_json")]
impl From<serde_json::Error> for FirewhalError {
    fn from(err: serde_json::Error) -> Self {
        FirewhalError::SerializationError(err)
    }
}

impl fmt::Display for FirewhalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirewhalError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            FirewhalError::RuleParseError(msg) => write!(f, "Rule parsing error: {}", msg),
            FirewhalError::IoError(err) => write!(f, "IO error: {}", err),
            FirewhalError::DaemonCommunicationError(msg) => write!(f, "Daemon communication error: {}", msg),
            #[cfg(feature = "serde_json")]
            FirewhalError::SerializationError(err) => write!(f, "Serialization error: {}", err),
        }
    }
}

impl std::error::Error for FirewhalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FirewhalError::IoError(err) => Some(err),
            #[cfg(feature = "serde_json")]
            FirewhalError::SerializationError(err) => Some(err),
            _ => None,
        }
    }
}