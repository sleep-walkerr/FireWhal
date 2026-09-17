use std::path::PathBuf;
use std::fmt;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::{HashMap, HashSet};
use bincode::{config, Encode, Decode};
//use serde::de::{value, Error};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task;
use tokio::time::{sleep, Duration, timeout};
use zeromq::{DealerSocket, Socket, SocketRecv, SocketSend, SocketOptions, ZmqError, ZmqMessage};

pub const DEFAULT_IPC_ENDPOINT: &str = "ipc:///tmp/firewhal_ipc.sock";

//Test error implementation for Zero Message Queue related functionalities
#[derive(Debug)]
pub enum IpcError {
    Zmq(ZmqError),
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
// One function instead of having a separate implementation inside of each subprogram

/// Creates a DEALER socket for `endpoint` and connects to the router.
///
/// The socket uses an unbounded connect timeout: if the router is not up yet,
/// the connect call keeps retrying internally (this is the pure-Rust equivalent
/// of the old `ZMQ_IMMEDIATE=0` slow-joiner workaround). The wait is raced
/// against the shutdown signal so the task can always be cancelled cleanly.
///
/// Returns `Err(IpcError::Zmq)` if the endpoint itself is malformed (a
/// configuration error that retrying would never fix); `Ok(None)` if shutdown
/// was requested while waiting; `Ok(Some(socket))` on a live connection.
async fn connect_dealer(
    endpoint: &str,
    shutdown_rx: &mut broadcast::Receiver<()>,
) -> Result<Option<DealerSocket>, IpcError> {
    // Fail fast on a malformed endpoint; otherwise the connect call retries
    // internally until the router appears.
    let _validated: zeromq::Endpoint = endpoint
        .parse()
        .map_err(ZmqError::from)
        .map_err(IpcError::Zmq)?;

    let mut options = SocketOptions::default();
    options.no_connect_timeout();
    let mut socket = DealerSocket::with_options(options);

    tokio::select! {
        _ = shutdown_rx.recv() => Ok(None),
        result = socket.connect(endpoint) => {
            result.map_err(IpcError::Zmq)?;
            Ok(Some(socket))
        }
    }
}

/// Sends this component's registration message so the router can route to it.
/// Called after every successful (re)connect.
async fn register_component(socket: &mut DealerSocket, component: &str) {
    let ready = FireWhalMessage::Status(StatusUpdate {
        component: component.to_string(),
        is_healthy: true,
        message: "Ready".to_string(),
    });
    let config = bincode::config::standard().with_big_endian();
    if let Ok(payload) = bincode::encode_to_vec(&ready, config) {
        if let Err(e) = socket.send(ZmqMessage::from(payload)).await {
            eprintln!("[{component} IPC Client] Failed to send registration message: {}", e);
        }
    }
}

/// Default interval between client heartbeats. The heartbeat keeps the
/// client's send path active so a dead router is detected even when the
/// component is otherwise idle (a pure recv wait would block forever).
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// A task that handles two-way ZMQ communication for a component.
///
/// Resilience guarantees:
/// - Slow joiner: waits (retrying) for the router to come up before sending,
///   so no message is lost to an unconnected socket.
/// - Reconnect: if the connection to the router is lost, the task recreates
///   its socket, reconnects (retrying until the router returns), and
///   re-registers this component.
/// - Liveness: a periodic (routed-to-nowhere) heartbeat detects a dead router
///   even while the component is idle.
/// - Clean exit: shuts down on the broadcast signal or when the component
///   drops its outbound channel.
pub async fn ipc_client_connection(
    endpoint: String,
    mut to_zmq_rx: mpsc::Receiver<FireWhalMessage>,
    from_zmq_tx: mpsc::Sender<FireWhalMessage>,
    mut shutdown_rx: broadcast::Receiver<()>,
    component: String,
    heartbeat_interval: Option<Duration>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = bincode::config::standard().with_big_endian();
    let heartbeat_interval = heartbeat_interval.unwrap_or(DEFAULT_HEARTBEAT_INTERVAL);
    let heartbeat_msg = FireWhalMessage::Status(StatusUpdate {
        component: component.clone(),
        is_healthy: true,
        message: "Heartbeat".to_string(),
    });

    // Initial connect, racing the shutdown signal.
    let mut socket = match connect_dealer(&endpoint, &mut shutdown_rx).await? {
        Some(socket) => socket,
        None => return Ok(()),
    };
    println!("[{component} IPC Client] Connected to IPC router at {}.", endpoint);
    register_component(&mut socket, &component).await;

    let mut heartbeat = tokio::time::interval(heartbeat_interval);
    heartbeat.tick().await; // first tick completes immediately; skip it

    loop {
        // One iteration of the connection loop. The send/recv operations are
        // only ever run on a live socket; any transport failure flips us into
        // the reconnect path instead of killing the task.
        enum Turn {
            Stay,
            Incoming(ZmqMessage),
            Lost,
            Bye,
        }

        let turn = tokio::select! {
            biased;
            // Listen for a shutdown signal from the component.
            _ = shutdown_rx.recv() => Turn::Bye,
            // Handle messages from the component's business logic.
            maybe_outgoing = to_zmq_rx.recv() => {
                match maybe_outgoing {
                    Some(message) => {
                        match bincode::encode_to_vec(&message, config) {
                            Ok(payload) => {
                                match socket.send(ZmqMessage::from(payload)).await {
                                    Ok(()) => Turn::Stay,
                                    Err(e) => {
                                        eprintln!("[{component} IPC Client] Send failed ({}), reconnecting.", e);
                                        Turn::Lost
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("[{component} IPC Client] Failed to encode message, discarding: {}", e);
                                Turn::Stay
                            }
                        }
                    }
                    // Component dropped its sender: nothing left to do.
                    None => Turn::Bye,
                }
            }
            // Liveness probe; also the idle-path way of noticing a dead router.
            _ = heartbeat.tick() => {
                if let Ok(payload) = bincode::encode_to_vec(&heartbeat_msg, config) {
                    match socket.send(ZmqMessage::from(payload)).await {
                        Ok(()) => Turn::Stay,
                        Err(e) => {
                            eprintln!("[{component} IPC Client] Heartbeat failed ({}), reconnecting.", e);
                            Turn::Lost
                        }
                    }
                } else {
                    Turn::Stay
                }
            }
            // Handle incoming messages from the router.
            result = socket.recv() => {
                match result {
                    Ok(frames) => Turn::Incoming(frames),
                    Err(e) => {
                        eprintln!("[{component} IPC Client] Receive failed ({}), reconnecting.", e);
                        Turn::Lost
                    }
                }
            }
        };

        match turn {
            Turn::Stay => {}
            Turn::Bye => break,
            Turn::Lost => {
                println!("[{component} IPC Client] Connection lost. Waiting for router to return...");
                match connect_dealer(&endpoint, &mut shutdown_rx).await? {
                    Some(new_socket) => {
                        socket = new_socket;
                        println!("[{component} IPC Client] Reconnected to IPC router at {}.", endpoint);
                        register_component(&mut socket, &component).await;
                    }
                    None => return Ok(()),
                }
            }
            Turn::Incoming(frames) => {
                if let Some(payload) = frames.get(0) {
                    match bincode::decode_from_slice::<FireWhalMessage, _>(payload, config) {
                        Ok((message, _)) => {
                            // If the channel is closed, the component has shut down, so we exit.
                            if from_zmq_tx.send(message).await.is_err() {
                                println!("[{component} IPC Client] Component channel closed. Shutting down IPC task.");
                                break;
                            }
                        }
                        Err(e) => eprintln!("[{component} IPC Client] Received malformed message, discarding. Error: {}", e),
                    }
                }
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
