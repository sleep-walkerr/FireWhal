use std::fmt;
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
// ... and so on for other common errors
