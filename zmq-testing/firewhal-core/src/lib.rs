use std::path::PathBuf;
use std::{fmt, fs, path};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::{HashMap, HashSet};
use bincode::{config, Encode, Decode};
//use serde::de::{value, Error};
use zeromq::{DealerSocket, Socket, SocketRecv, SocketSend};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task;

//Test error implementation for Zero Message Queue related functionalities
#[derive(Debug)]
pub enum IpcError {
    Zmq(zeromq::ZmqError),
    Deserialization(String),
}

// Allow our error to be displayed
impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IpcError::Deserialization(e) => write!(f, "Deserialization Error: {}", e),
            IpcError::Zmq(e) => write!(f, "ZMQ Error: {}", e),
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
    let mut socket = DealerSocket::new();
    socket.connect("ipc:///tmp/firewhal_ipc.sock").await?;

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
                    if socket.send(payload.into()).await.is_err() {
                        eprintln!("[{component} IPC Client] Failed to send message to router.");
                    }
                }
            },

            // Branch 3: Handle messages FROM the router
            Ok(multipart) = socket.recv() => {
                // A DEALER socket receiving from a ROUTER gets a 2-part message:
                // [empty_delimiter, payload]. We need the payload at index 1.
                // We use .get(1) which returns an Option<&Bytes>.
                if let Some(payload) = multipart.get(1) {
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
                }
            },
            else => {
                break;
            }
        }
    }
    println!("[{component} IPC Client] Disconnected.");
    Ok(())
}

// DATA STRUCTURES
#[derive(Clone, Debug, PartialEq, Eq, Hash)] 
pub struct ProcessInfo {
    pub path: PathBuf,
    pub hash: String, // Or whatever unique ID you get for the executable
    pub action: Action, // The decision (Allow/Deny) made for this process
}

#[derive(Encode, Decode, Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "PascalCase")]
pub enum Action {
    Allow,
    Deny
}

#[derive(Encode, Decode, Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum Protocol {
    Wildcard = 0,
    Tcp = 6,
    Udp = 17,
    Icmp = 1
}


#[derive(Encode, Decode, Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
pub struct Rule {
    // Consider adding rule ids to rules for debugging purposes
    pub action: Action,
    pub protocol: Option<Protocol>,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub app_id: Option<String>,
    pub description: String,
}

// List of rules to be sent to firewall
#[derive(Encode, Decode, Debug, Deserialize, Serialize, Clone)]
pub struct FireWhalConfig {
    pub outgoing_rules: Vec<Rule>,
    pub incoming_rules: Vec<Rule>
}

// Represents the value for an app id key in the app_id.toml file
#[derive(Debug, Deserialize, Serialize, Encode, Decode, Clone, Eq, PartialEq)]
pub struct AppIdentity {
    pub path: PathBuf,
    pub hash: String,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, Clone)]
pub struct ApplicationAllowlistConfig {
    pub apps: HashMap<String, AppIdentity>, // Key is the app_id
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, Clone)]
pub struct InterfaceStateConfig {
    pub enforced_interfaces: HashSet<String>, // Key is the app_id
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum FireWhalMessage {
    CommandShutdown(ShutdownCommand),
    RuleAddBlock(BlockAddressRule),
    Status(StatusUpdate),
    Debug(DebugMessage),
    LoadRules(FireWhalConfig),
    LoadAppIds(ApplicationAllowlistConfig),
    InterfaceRequest(NetInterfaceRequest),
    InterfaceResponse(NetInterfaceResponse),
    LoadInterfaceState(InterfaceStateConfig),
    UpdateInterfaces(UpdateInterfaces),
    Ping(StatusPing),
    Pong(StatusPong),
    DiscordBlockNotify(DiscordBlockNotification),
    EnablePermissiveMode(PermissiveModeEnable),
    DisablePermissiveMode(PermissiveModeDisable),
    PermissiveModeTuple(ProcessLineageTuple),
    AddAppIds(AppIdsToAdd),
    RulesRequest(TUIRulesRequest),
    RulesResponse(FireWhalConfig),
    UpdateRules(FireWhalConfig),
    AppsRequest(TUIAppsRequest),
    AppsResponse(ApplicationAllowlistConfig),
    UpdateAppIds(ApplicationAllowlistConfig),
    HashRequest(TUIHashRequest),
    HashResponse(DaemonHashResponse),
    HashUpdateRequest(RequestToUpdateHash),
    HashUpdateResponse(UpdatedHashResponse),
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct RequestToUpdateHash { // From TUI, request to update the hash for one or many applications
    pub component: String,
    pub app_to_update_hash_for: (String, AppIdentity)
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct UpdatedHashResponse {
    pub component: String,
    pub updated_app: (String, AppIdentity)
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct DaemonHashResponse {
    pub component: String,
    pub app_with_updated_hash: (String, AppIdentity)
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct TUIHashRequest {
    pub component: String,
    pub app_to_get_hash_for: (String, AppIdentity)
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct TUIAppsRequest {
    pub component: String,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct TUIRulesRequest {
    pub component: String,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct AppIdsToAdd {
    pub component: String,
    pub app_ids_to_add: Vec<(String, String)>
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct ProcessLineageTuple {
    pub component: String,
    pub lineage_tuple: Vec<(String, String)>
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct PermissiveModeEnable {
    pub component: String,
}
#[derive(Encode, Decode, Debug, Clone)]
pub struct PermissiveModeDisable {
    pub component: String,
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
    pub interfaces: HashSet<String>,
}


#[derive(Encode, Decode, Debug, Clone)]
pub struct NetInterfaceRequest {
    pub source: String,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct NetInterfaceResponse {
    pub source: String,
    pub interface_state: InterfaceStateConfig,
    pub current_interfaces: HashSet<String>,
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
