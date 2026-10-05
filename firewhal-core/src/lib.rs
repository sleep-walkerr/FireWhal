use std::path::{Path, PathBuf};
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

/// Computes the SHA3-256 hash of the file at `path` (lowercase hex).
/// Streams in 128 KiB chunks on a blocking thread so the async runtime is not stalled.
/// Shared by the Daemon and the Kernel (userspace loader) so both hash identically.
pub async fn calculate_file_hash(path: PathBuf) -> anyhow::Result<String> {
    use anyhow::Context;

    let hash_result = task::spawn_blocking(move || {
        use sha3::Digest;
        use std::io::Read;

        let mut file = std::fs::File::open(&path)
            .map_err(|e| anyhow::anyhow!("Failed to open file {:?}: {}", path, e))?;
        let mut hasher = sha3::Sha3_256::new();
        let mut buffer = [0u8; 1024 * 128];

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 { break; }
            hasher.update(&buffer[..count]);
        }

        Ok::<String, anyhow::Error>(hex::encode(hasher.finalize()))
    }).await;

    hash_result.context("Hashing task panicked")?
}

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

/// The fallback verdict for traffic in a direction that matches no
/// explicit rule (UFW's `ufw default` analogue, #159).
///
/// `Block` is the serde default: if the key is absent from the file — a
/// generator bug that emitted the file without it, or an operator who
/// deleted the line by accident — the parse still succeeds and lands on
/// the fail-closed verdict, instead of rejecting the whole file or,
/// worse, failing open. This is safe-default enforcement, not backward
/// compatibility (AGENTS.md): every file generator (packaged template,
/// e2e rig) still emits the keys explicitly, so the on-disk state is
/// always complete and the default is a backstop, not a substitute.
#[derive(Encode, Decode, Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum DefaultVerdict {
    Allow,
    Block,
}

impl Default for DefaultVerdict {
    fn default() -> Self {
        DefaultVerdict::Block
    }
}

// List of rules to be sent to firewall
#[derive(Encode, Decode, Debug, Deserialize, Serialize, Clone)]
pub struct FireWhalConfig {
    pub outgoing_rules: Vec<Rule>,
    pub incoming_rules: Vec<Rule>,
    #[serde(default)]
    pub default_incoming: DefaultVerdict,
    #[serde(default)]
    pub default_outgoing: DefaultVerdict,
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

// ---------------------------------------------------------------------------
// State introspection (#182): on-demand snapshot of the firewall's live
// in-kernel state. The kernel loader owns the map handles and performs the
// dump (same iteration `bpftool map dump` uses); the daemon contributes the
// C1 config-health view. The TUI renders both; dumps run only on request.
// ---------------------------------------------------------------------------

/// TUI -> (Firewall + Daemon): "give me the current state view".
#[derive(Encode, Decode, Debug, Clone)]
pub struct TUIStateRequest {
    pub component: String,
}

/// One tracked/pending/handshake connection (a 5-tuple + owning TGID,
/// resolved to a process name by the loader).
#[derive(Encode, Decode, Debug, Clone)]
pub struct ConnStateEntry {
    pub src: String,     // "ip:port"
    pub dst: String,     // "ip:port"
    pub protocol: String,
    pub tgid: u32,
    pub process: String,
}

/// One TRUSTED_PIDS entry (TGID + verdict + resolved name).
#[derive(Encode, Decode, Debug, Clone)]
pub struct TrustedPidEntry {
    pub tgid: u32,
    pub action: Action,
    pub process: String,
}

/// One pending/trusted listening port (port + owner TGID + resolved name).
#[derive(Encode, Decode, Debug, Clone)]
pub struct ListenerEntry {
    pub port: u16,
    pub tgid: u32,
    pub process: String,
}

/// Per-interface TC attach state (the #181 enforcement signal).
#[derive(Encode, Decode, Debug, Clone)]
pub struct AttachEntry {
    pub interface: String,
    pub ingress: String, // aya link id (debug format)
    pub egress: String,  // aya link id (debug format)
}

/// Point-in-time dump of all display maps + loader attach state, sent by
/// the kernel in response to a StateRequest. Rules are decoded from the
/// in-kernel maps so the TUI can flag kernel-vs-on-disk divergence.
#[derive(Encode, Decode, Debug, Clone)]
pub struct StateSnapshot {
    pub source: String,
    pub captured_at_ms: u64,
    // Stateful (CONNECTION_MAP — an LRU, so a *window*, not history)
    pub connections: Vec<ConnStateEntry>,
    pub pending_connections: Vec<ConnStateEntry>,
    pub trusted_connections: Vec<ConnStateEntry>,
    pub handshake_allowed: Vec<ConnStateEntry>,
    // Trust tables
    pub trusted_pids: Vec<TrustedPidEntry>,
    pub pending_listeners: Vec<ListenerEntry>,
    pub trusted_listeners: Vec<ListenerEntry>,
    pub trusted_cookies_count: u32,
    pub socket_cookie_trust_count: u32,
    // Rules actually loaded in the kernel (for the divergence check)
    pub outgoing_rules: Vec<Rule>,
    pub incoming_rules: Vec<Rule>,
    pub default_outgoing: DefaultVerdict,
    pub default_incoming: DefaultVerdict,
    pub permissive_mode: bool,
    // Loader-owned attach state
    pub attach: Vec<AttachEntry>,
}

/// Per-config-file C1 health, sent by the daemon in response to a
/// StateRequest (the same state the C1 alarm mechanism tracks).
#[derive(Encode, Decode, Debug, Clone)]
pub struct ConfigFileHealth {
    pub file: String,
    pub healthy: bool,
    pub note: String,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct ConfigHealthView {
    pub source: String,
    pub all_healthy: bool,
    pub files: Vec<ConfigFileHealth>,
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
    StateRequest(TUIStateRequest),
    StateResponse(StateSnapshot),
    ConfigHealthResponse(ConfigHealthView),
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

// ---------------------------------------------------------------------------
// Config location (packaging, #136 "Option B"): the daemon, the
// `firewhal-health` validator, and everything else assume the config tomls
// live in one directory. The package installs templates there and pacman
// treats /etc files as config (preserved on upgrade, .pacnew on conflict).
// ---------------------------------------------------------------------------

/// The directory the daemon and `firewhal-health` read the config tomls from.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/firewhal";

/// Path of one config toml under [`DEFAULT_CONFIG_DIR`].
pub fn config_path(file_name: &str) -> PathBuf {
    PathBuf::from(DEFAULT_CONFIG_DIR).join(file_name)
}

// ---------------------------------------------------------------------------
// C1: config-path loading (design doc §2.4), shared by the daemon and
// `firewhal-health` so both parse with exactly the same semantics.
//
// Each loader returns a `ConfigLoadResult` that distinguishes "loaded and
// valid" from "missing" and "present but unreadable/malformed". The degraded
// states are NOT fatal: the caller applies the fail-closed default posture
// and announces it (daemon alarm bundle / `firewhal-health` exit code).
// ---------------------------------------------------------------------------

/// The outcome of loading one config toml (C1, design doc §2.4).
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigLoadResult<T> {
    /// The file is present, readable, and parsed.
    Loaded(T),
    /// The file does not exist.
    Missing,
    /// The file exists but could not be read or parsed.
    Malformed { reason: String },
}

impl<T> ConfigLoadResult<T> {
    /// `true` for Missing/Malformed — the degraded states that require the
    /// fail-closed default + announcement (C1).
    pub fn is_degraded(&self) -> bool {
        !matches!(self, Self::Loaded(_))
    }
}

/// Reads a toml file, classifying the failure modes the callers care about.
enum TomlRead {
    Content(String),
    Missing,
    Unreadable(String),
}

fn read_toml_file(path: &Path) -> TomlRead {
    match std::fs::read_to_string(path) {
        Ok(content) => TomlRead::Content(content),
        Err(e) if path.exists() => TomlRead::Unreadable(e.to_string()),
        Err(_) => TomlRead::Missing,
    }
}

/// Loads `firewall_rules.toml`. No bootstrap on missing: an empty rule set
/// is the fail-closed posture (default-deny), which the caller applies and
/// announces.
pub fn load_rules_config(path: &Path) -> ConfigLoadResult<FireWhalConfig> {
    match read_toml_file(path) {
        TomlRead::Content(content) => match toml::from_str(&content) {
            Ok(config) => ConfigLoadResult::Loaded(config),
            Err(e) => ConfigLoadResult::Malformed { reason: e.to_string() },
        },
        TomlRead::Missing => ConfigLoadResult::Missing,
        TomlRead::Unreadable(e) => ConfigLoadResult::Malformed { reason: format!("unreadable: {e}") },
    }
}

/// Loads `app_identity.toml` as a pure read — NO bootstrap: the daemon is
/// the one that creates the empty file when missing (preserving the
/// historical behavior); `firewhal-health` must not mutate state while
/// validating.
pub fn load_app_ids_config(path: &Path) -> ConfigLoadResult<ApplicationAllowlistConfig> {
    match read_toml_file(path) {
        TomlRead::Content(content) => match toml::from_str(&content) {
            Ok(config) => ConfigLoadResult::Loaded(config),
            Err(e) => ConfigLoadResult::Malformed { reason: e.to_string() },
        },
        TomlRead::Missing => ConfigLoadResult::Missing,
        TomlRead::Unreadable(e) => ConfigLoadResult::Malformed { reason: format!("unreadable: {e}") },
    }
}

/// Loads `interface_state.toml` as a pure read. No interface-existence
/// pruning here (that needs the live interface list — the daemon does it);
/// a missing/malformed/empty result makes the caller apply the fail-closed
/// default (all non-loopback interfaces) instead.
pub fn load_interface_state_config(path: &Path) -> ConfigLoadResult<InterfaceStateConfig> {
    match read_toml_file(path) {
        TomlRead::Content(content) => match toml::from_str(&content) {
            Ok(config) => ConfigLoadResult::Loaded(config),
            Err(e) => ConfigLoadResult::Malformed { reason: e.to_string() },
        },
        TomlRead::Missing => ConfigLoadResult::Missing,
        TomlRead::Unreadable(e) => ConfigLoadResult::Malformed { reason: format!("unreadable: {e}") },
    }
}

#[cfg(test)]
mod default_verdict_tests {
    use super::*;

    // Safe-default backstop (AGENTS.md): if the default_* keys are
    // missing — a generator bug or a user-deleted line — the parse
    // succeeds and lands on Block (fail-closed). Never rejected, never
    // Allow, and the rest of the file still loads.
    #[test]
    fn missing_defaults_land_on_block() {
        let legacy = r#"
            incoming_rules = []
            [[outgoing_rules]]
            action = "Deny"
            description = "legacy rule"
        "#;
        let config: FireWhalConfig = toml::from_str(legacy).expect("missing keys must default, not reject");
        assert_eq!(config.default_incoming, DefaultVerdict::Block);
        assert_eq!(config.default_outgoing, DefaultVerdict::Block);
        assert_eq!(config.outgoing_rules.len(), 1, "the rest of the file must still load");
    }

    // The same property pinned at the real load seam (`load_rules_config`),
    // not just `toml::from_str`: a file missing the keys loads cleanly,
    // fail-closed.
    #[test]
    fn load_path_defaults_missing_to_block() {
        let path = std::env::temp_dir().join(format!("fw-default-verdict-load-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "incoming_rules = []\n[[outgoing_rules]]\naction = \"Deny\"\ndescription = \"legacy rule\"\n",
        )
        .expect("write test file");
        let result = load_rules_config(&path);
        let _ = std::fs::remove_file(&path);
        match result {
            ConfigLoadResult::Loaded(config) => {
                assert_eq!(config.default_incoming, DefaultVerdict::Block);
                assert_eq!(config.default_outgoing, DefaultVerdict::Block);
            }
            other => panic!("expected the missing-keys file to load fail-closed, got: {other:?}"),
        }
    }

    #[test]
    fn explicit_defaults_parse() {
        let cfg = "outgoing_rules = []\nincoming_rules = []\ndefault_incoming = \"Allow\"\ndefault_outgoing = \"Allow\"\n";
        let config: FireWhalConfig = toml::from_str(cfg).expect("defaults must parse");
        assert_eq!(config.default_incoming, DefaultVerdict::Allow);
        assert_eq!(config.default_outgoing, DefaultVerdict::Allow);
    }

    #[test]
    fn defaults_round_trip() {
        let config = FireWhalConfig {
            outgoing_rules: vec![],
            incoming_rules: vec![],
            default_incoming: DefaultVerdict::Allow,
            default_outgoing: DefaultVerdict::Block,
        };
        let toml_str = toml::to_string(&config).expect("serialize");
        let back: FireWhalConfig = toml::from_str(&toml_str).expect("round-trip parse");
        assert_eq!(back.default_incoming, DefaultVerdict::Allow);
        assert_eq!(back.default_outgoing, DefaultVerdict::Block);
    }

    #[test]
    fn malformed_default_value_rejected() {
        // Valid shape, invalid enum value — must fail on the value itself.
        let cfg = "outgoing_rules = []\nincoming_rules = []\ndefault_outgoing = \"Maybe\"\n";
        let err = toml::from_str::<FireWhalConfig>(cfg).expect_err("must be rejected");
        assert!(
            err.to_string().contains("Maybe"),
            "expected the unknown variant to be named in the error, got: {err}"
        );
    }
}

#[cfg(test)]
mod state_introspection_tests {
    use super::*;

    fn sample_snapshot() -> StateSnapshot {
        StateSnapshot {
            source: "Firewall".to_string(),
            captured_at_ms: 1_791_055_000_000,
            connections: vec![ConnStateEntry {
                src: "10.0.0.1:51234".to_string(),
                dst: "1.1.1.1:443".to_string(),
                protocol: "Tcp".to_string(),
                tgid: 4242,
                process: "curl".to_string(),
            }],
            pending_connections: vec![],
            trusted_connections: vec![],
            handshake_allowed: vec![],
            trusted_pids: vec![TrustedPidEntry {
                tgid: 4242,
                action: Action::Allow,
                process: "curl".to_string(),
            }],
            pending_listeners: vec![ListenerEntry {
                port: 22,
                tgid: 1,
                process: "sshd".to_string(),
            }],
            trusted_listeners: vec![],
            trusted_cookies_count: 3,
            socket_cookie_trust_count: 2,
            outgoing_rules: vec![Rule {
                action: Action::Allow,
                protocol: Some(Protocol::Tcp),
                source_ip: None,
                source_port: None,
                dest_ip: Some(IpAddr::V4("1.1.1.1".parse().unwrap())),
                dest_port: Some(443),
                app_id: None,
                description: String::new(),
            }],
            incoming_rules: vec![],
            default_outgoing: DefaultVerdict::Block,
            default_incoming: DefaultVerdict::Block,
            permissive_mode: false,
            attach: vec![AttachEntry {
                interface: "wlp5s0".to_string(),
                ingress: "FdLinkId(1)".to_string(),
                egress: "FdLinkId(2)".to_string(),
            }],
        }
    }

    #[test]
    fn state_snapshot_bincode_round_trip() {
        let snapshot = sample_snapshot();
        let bytes = bincode::encode_to_vec(&snapshot, bincode::config::standard().with_big_endian())
            .expect("encode StateSnapshot");
        let back: StateSnapshot =
            bincode::decode_from_slice(&bytes, bincode::config::standard().with_big_endian())
                .expect("decode StateSnapshot")
                .0;
        assert_eq!(back.captured_at_ms, snapshot.captured_at_ms);
        assert_eq!(back.connections.len(), 1);
        assert_eq!(back.connections[0].process, "curl");
        assert_eq!(back.trusted_pids[0].action, Action::Allow);
        assert_eq!(back.outgoing_rules[0].dest_port, Some(443));
        assert_eq!(back.default_outgoing, DefaultVerdict::Block);
        assert_eq!(back.attach.len(), 1);
    }

    #[test]
    fn config_health_view_bincode_round_trip() {
        let view = ConfigHealthView {
            source: "Daemon".to_string(),
            all_healthy: false,
            files: vec![ConfigFileHealth {
                file: "firewall_rules.toml".to_string(),
                healthy: false,
                note: "missing — empty rule set (default-deny)".to_string(),
            }],
        };
        let bytes = bincode::encode_to_vec(&view, bincode::config::standard().with_big_endian())
            .expect("encode ConfigHealthView");
        let back: ConfigHealthView =
            bincode::decode_from_slice(&bytes, bincode::config::standard().with_big_endian())
                .expect("decode ConfigHealthView")
                .0;
        assert!(!back.all_healthy);
        assert_eq!(back.files[0].file, "firewall_rules.toml");
    }

    #[test]
    fn message_variants_round_trip() {
        let req = FireWhalMessage::StateRequest(TUIStateRequest {
            component: "TUI".to_string(),
        });
        let resp = FireWhalMessage::StateResponse(sample_snapshot());
        for msg in [req, resp, FireWhalMessage::ConfigHealthResponse(ConfigHealthView {
            source: "Daemon".to_string(),
            all_healthy: true,
            files: vec![],
        })] {
            let bytes =
                bincode::encode_to_vec(&msg, bincode::config::standard().with_big_endian())
                    .expect("encode FireWhalMessage");
            let back: FireWhalMessage = bincode::decode_from_slice(
                &bytes,
                bincode::config::standard().with_big_endian(),
            )
            .expect("decode FireWhalMessage")
            .0;
            match back {
                FireWhalMessage::StateRequest(r) => assert_eq!(r.component, "TUI"),
                FireWhalMessage::StateResponse(s) => assert_eq!(s.connections.len(), 1),
                FireWhalMessage::ConfigHealthResponse(v) => assert!(v.all_healthy),
                _ => panic!("unexpected variant on round trip"),
            }
        }
    }
}
