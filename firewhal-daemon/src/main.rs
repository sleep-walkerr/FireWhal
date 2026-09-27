//! Supervisor Daemon for the Firewhal Firewall System
//! 
//! This daemon is responsible for:
//! 1. Starting as root, launching privileged components, then dropping its own privileges to 'nobody'.
//! 2. Launching, managing, and monitoring all other system components.
//!    - The eBPF Firewall (as root)
//!    - The ZMQ IPC Router (as root, which then drops its own privileges)
//!    - The Discord Bot (as nobody)
//! 3. Reporting status and errors via ZMQ to the IPC router.
//! 4. Handling graceful shutdown of all components.

// Crate imports
use daemonize::Daemonize;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{chdir, execv, fork, pipe, setgid, setuid, ForkResult, Pid};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task;
use tokio::time::{sleep, Duration};
use serde::Deserialize;
use toml;
use pnet::{datalink};
use anyhow::{bail, Context, Result};

// Standard library imports
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::{fs, fs::File};
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::sync::{Arc, Mutex as StdMutex};
use std::{path, path::{PathBuf}, vec};
use futures::stream::{self, StreamExt};
use std::process::{Command, Stdio};
use std::os::unix::process::CommandExt;


// Workspace imports
use firewhal_core::{AppIdentity, ApplicationAllowlistConfig, ConfigLoadResult, DaemonHashResponse, DebugMessage, DEFAULT_IPC_ENDPOINT, FireWhalConfig, FireWhalMessage, InterfaceStateConfig, NetInterfaceResponse, StatusPong, StatusUpdate, UpdatedHashResponse, calculate_file_hash, ipc_client_connection, load_app_ids_config, load_interface_state_config, load_rules_config};

// A type alias for clarity. Maps a component name (String) to its PID (i32).
type ChildProcesses = Arc<Mutex<HashMap<String, i32>>>;


// C1 (design doc §2.4): these thin wrappers keep the historical `Result`
// behavior for the TUI request handlers; the config-health machinery below
// uses the core loaders directly so it can tell Missing from Malformed.
fn load_rules(path: &path::Path) -> Result<FireWhalConfig, Box<dyn std::error::Error>> {
    match load_rules_config(path) {
        ConfigLoadResult::Loaded(config) => Ok(config),
        ConfigLoadResult::Missing => Err("config file missing".into()),
        ConfigLoadResult::Malformed { reason } => Err(reason.into()),
    }
}

// Serializes the new set of firewall rules to a file
fn save_rules(path: &path::Path, config: &FireWhalConfig) -> Result<(), Box<dyn std::error::Error>> {
    let toml_content = toml::to_string_pretty(config)?; // Serialize toml using string_pretty (makes it looks nice for humans)

    // write to file, overwriting contents
    fs::write(path, toml_content)?;

    Ok(())
}

// Loads and deserializes the defined applications that will be used in filtering
fn load_app_ids(path: &path::Path) -> Result<ApplicationAllowlistConfig, Box<dyn std::error::Error>> {
    match load_app_ids_config(path) {
        ConfigLoadResult::Loaded(config) => Ok(config),
        ConfigLoadResult::Missing => {
            eprintln!("[Supervisor] App identity file not found at '{}'. Creating a new, empty one.", path.display());
            // Create a default, empty config (historical behavior; the C1
            // config-health path announces this as a degraded state)
            let empty_config = ApplicationAllowlistConfig {
                apps: HashMap::new(),
            };
            // Save it to create the file with the correct empty structure.
            save_app_ids(path, &empty_config)?;
            // Return the empty config
            Ok(empty_config)
        }
        ConfigLoadResult::Malformed { reason } => Err(reason.into()),
    }
}

// Same as load_app_ids but this time adds new applications sent from permissive mode
// This function will load the app ids, add new ones to the struct, serialize the new struct, and then send the new struct to the firewall
fn add_app_ids(path: &path::Path, app_ids_to_add: Vec<(String, String)>) -> Result<(), Box<dyn std::error::Error>> {
    let toml_content = fs::read_to_string(path)?;
    let mut config: ApplicationAllowlistConfig = toml::from_str(&toml_content)?;

    // Use a label to break from the inner loop and continue the outer one
    'new_app_loop: for (new_app_path_str, new_app_hash) in app_ids_to_add {
        let new_app_path = PathBuf::from(new_app_path_str);

        // --- 1. THE FIX: Check for existing and continue 'new_app_loop ---
        for (_name, app_identity) in config.apps.iter_mut() {
            if app_identity.path == new_app_path {
                // Found it! This is the "update" logic.
                if app_identity.hash != new_app_hash {
                    // Move the hash here. This is fine, because
                    // we are about to 'continue' the outer loop.
                    app_identity.hash = new_app_hash; 
                }
                
                // We've handled this app. Skip the "add new" logic
                // entirely by continuing the outer loop.
                continue 'new_app_loop;
            }
        }

        // --- 2. If path was NOT found, ADD IT AS NEW ---
        // This code is now *only* reachable if the inner loop
        // completed without finding a match.

        let Some(file_name) = new_app_path.file_name() else {
            eprintln!("Skipping app with invalid path (no filename): {}", new_app_path.display());
            continue;
        };
        
        let new_app_name = file_name.to_string_lossy().to_string();

        // Handle name collisions
        let mut final_name = new_app_name.clone();
        let mut i = 1;
        while config.apps.contains_key(&final_name) {
            final_name = format!("{}_{}", new_app_name, i);
            i += 1;
        }
        
        // Move the hash here. This is the *only* other place
        // it can be moved, and the logic guarantees it's one or the other.
        config.apps.insert(final_name, AppIdentity {
            path: new_app_path,
            hash: new_app_hash,
        });
    }

    save_app_ids(path, &config)?;
    Ok(())
}

// Overwrites current app_identity.toml file with a new config
fn save_app_ids(path: &path::Path, config: &ApplicationAllowlistConfig) -> Result<(), Box<dyn std::error::Error>> {
    let toml_content = toml::to_string_pretty(config)?; // Serialize toml using string_pretty (makes it looks nice for humans)
    // write to file, overwriting contents
    fs::write(path, toml_content)?;
    Ok(())
}

// Gets a list of currently available interfaces
fn get_all_interfaces() -> HashSet<String> {
    datalink::interfaces()
        .into_iter()
        .map(|iface| iface.name)
        .collect()
}

// Loads enforced_interfaces.toml file that contains interfaces that the firewall is currently enforcing rules on
fn load_interface_state(path: &path::Path) -> Result<InterfaceStateConfig, Box<dyn std::error::Error>> {
    match load_interface_state_config(path) {
        ConfigLoadResult::Loaded(mut interface_state) => {
            // Remove interfaces that no longer exist
            let current_interfaces = get_all_interfaces();
            interface_state.enforced_interfaces.retain(|x| current_interfaces.contains(x));
            Ok(interface_state)
        }
        ConfigLoadResult::Missing => Err("config file missing".into()),
        ConfigLoadResult::Malformed { reason } => Err(reason.into()),
    }
}

fn save_interface_state(path: &path::Path, interfaces: &HashSet<String>) -> Result<(), Box<dyn std::error::Error>> {
    let interface_state = InterfaceStateConfig {
        enforced_interfaces: interfaces.clone(),
    };
    let toml_content = toml::to_string_pretty(&interface_state)?;
    fs::write(path, toml_content)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// C1: config-path health + alarm bundle (design doc §2.4).
//
// The daemon never exits on a config error: exiting detaches every eBPF
// hook, and a dead firewall is not "blocked" — it is *no* firewall
// (fail-open, the worst case). Instead the daemon applies the fail-closed
// default for whatever is missing/malformed and announces the degraded
// state on every channel: a persistent log line, a `wall` broadcast, and a
// degraded `Status` to the TUI (it never reports is_healthy=true while
// degraded). The alarm fires on state transitions only, in both directions.
//
// Postures (verified against the code, see the §2.4 matrix):
//   - rules missing/malformed   -> push an empty rule set: default-deny,
//                                  everything blocked (fail-closed)
//   - apps missing              -> bootstrap an empty allowlist file
//                                  (historical behavior) -> egress denied
//                                  at the app gate (fail-closed)
//   - interfaces missing/malformed/empty -> push ALL non-loopback interfaces
//                                  (fail-closed default: enforcement is on,
//                                  never left unattached)
// ---------------------------------------------------------------------------

/// Health of one config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileHealth {
    Healthy,
    Degraded,
}

/// Health of the three config files, plus the announcement text for each
/// degraded file (the fail-closed posture in plain language).
#[derive(Debug, Clone)]
struct ConfigHealthState {
    rules: (FileHealth, String),
    apps: (FileHealth, String),
    interfaces: (FileHealth, String),
}

impl ConfigHealthState {
    fn all_healthy(&self) -> bool {
        self.rules.0 == FileHealth::Healthy
            && self.apps.0 == FileHealth::Healthy
            && self.interfaces.0 == FileHealth::Healthy
    }
}

/// One health transition the alarm bundle must announce.
struct AlarmEvent {
    file: &'static str,
    healthy: bool, // the NEW state (false = now degraded)
    note: String,  // posture in plain language + the fix
}

/// Naive UTC timestamp (the daemon has no date library; this only feeds
/// log lines and the wall text).
fn utc_timestamp(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let sod = secs % 86400;
    let (h, m, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    // civil-from-days (Howard Hinnant)
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{y:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", mo, d, h, m, s)
}

/// The C1 alarm bundle: one persistent log line + one `wall` broadcast per
/// transition. The TUI is covered by the caller's `Status` message.
///
/// `/var/log/firewhal/` (never /tmp — S1 forensics proved /tmp non-durable
/// on the e2e image). `wall` is best-effort: the log line and the TUI state
/// remain authoritative if the binary is unavailable.
fn fire_config_alarm(events: &[AlarmEvent]) {
    let log_dir = "/var/log/firewhal";
    let log_path = format!("{log_dir}/config-alert.log");
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for ev in events {
        let ts = utc_timestamp(secs);
        let kind = if ev.healthy { "CONFIG RECOVERED" } else { "CONFIG ALERT" };
        let line = format!("[{ts}] {kind} {}: {}", ev.file, ev.note);

        // 1. persistent record
        match (|| -> std::io::Result<()> {
            std::fs::create_dir_all(log_dir)?;
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)?;
            writeln!(f, "{line}")?;
            Ok(())
        })() {
            Ok(()) => {}
            Err(e) => eprintln!("[Supervisor] C1: failed to write {log_path}: {e}"),
        }

        // 2. wall broadcast to every logged-in terminal (best effort)
        if let Err(e) = Command::new("wall")
            .arg(&line)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            eprintln!("[Supervisor] C1: wall broadcast failed (log line + TUI status remain): {e}");
        }
    }
}

/// C1: health state is persisted across daemon restarts (the state file
/// lives next to the alarm log) so a recovery alarm still fires when the
/// config is restored and the stack restarted — the in-memory state alone
/// would lose the transition (a fresh process sees a healthy config and has
/// no idea the previous one was degraded).
const HEALTH_STATE_PATH: &str = "/var/log/firewhal/config-health.state";

fn load_prev_health() -> Option<ConfigHealthState> {
    let content = std::fs::read_to_string(HEALTH_STATE_PATH).ok()?;
    let mut rules = FileHealth::Healthy;
    let mut apps = FileHealth::Healthy;
    let mut interfaces = FileHealth::Healthy;
    for line in content.lines() {
        let (k, v) = match line.split_once('=') {
            Some(t) => t,
            None => continue,
        };
        let h = if v == "Degraded" { FileHealth::Degraded } else { FileHealth::Healthy };
        match k {
            "rules" => rules = h,
            "apps" => apps = h,
            "interfaces" => interfaces = h,
            _ => {}
        }
    }
    Some(ConfigHealthState {
        rules: (rules, String::new()),
        apps: (apps, String::new()),
        interfaces: (interfaces, String::new()),
    })
}

fn save_health(st: &ConfigHealthState) {
    let dir = "/var/log/firewhal";
    let tmp = format!("{dir}/config-health.state.tmp");
    let body = format!(
        "rules={:?}\napps={:?}\ninterfaces={:?}\n",
        st.rules.0, st.apps.0, st.interfaces.0
    );
    let _ = std::fs::create_dir_all(dir);
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, HEALTH_STATE_PATH);
    }
}

/// C1: (re)evaluate the config after a change (startup, TUI update,
/// reload): evaluate, fire the alarm bundle on any state transition, and
/// send an honest daemon status (never is_healthy=true while degraded).
async fn apply_config_health(
    to_zmq_tx: &mpsc::Sender<FireWhalMessage>,
    config_health: &mut Option<ConfigHealthState>,
) {
    // Previous state: in-memory if this process already evaluated, else the
    // persisted state from the previous process (so recovery alarms survive
    // restarts).
    let mut persisted_prev: Option<ConfigHealthState> = None;
    let prev_ref: Option<&ConfigHealthState> = match config_health.as_ref() {
        Some(s) => Some(s),
        None => {
            persisted_prev = load_prev_health();
            persisted_prev.as_ref()
        }
    };
    let (new_state, events) = evaluate_config(to_zmq_tx, prev_ref).await;
    if !events.is_empty() {
        fire_config_alarm(&events);
        let degraded = !new_state.all_healthy();
        let msg = if degraded {
            format!(
                "DEGRADED: {}",
                events
                    .iter()
                    .filter(|e| !e.healthy)
                    .map(|e| format!("{} ({})", e.file, e.note))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        } else {
            "Ready (config fully valid)".to_string()
        };
        if let Err(e) = to_zmq_tx
            .send(FireWhalMessage::Status(StatusUpdate {
                component: "Daemon".to_string(),
                is_healthy: !degraded,
                message: msg,
            }))
            .await
        {
            eprintln!("[Supervisor] C1: failed to send config status: {e}");
        }
    }
    save_health(&new_state);
    *config_health = Some(new_state);
}

/// All non-loopback interfaces (the C1 fail-closed default set). Loopback
/// is excluded so local services on `lo` are never touched.
fn default_enforced_interfaces() -> HashSet<String> {
    get_all_interfaces()
        .into_iter()
        .filter(|name| !name.starts_with("lo"))
        .collect()
}

/// C1: (re)load all three config tomls, apply the fail-closed defaults
/// where needed, push the effective config to the firewall, and return the
/// new health state plus any transitions to announce.
///
/// `prev` is the last evaluated state (`None` at first evaluation, which is
/// treated as the all-healthy baseline: a broken config at startup still
/// announces).
async fn evaluate_config(
    to_zmq_tx: &mpsc::Sender<FireWhalMessage>,
    prev: Option<&ConfigHealthState>,
) -> (ConfigHealthState, Vec<AlarmEvent>) {
    let rules_path = path::Path::new("/opt/firewhal/bin/firewall_rules.toml");
    let apps_path = path::Path::new("/opt/firewhal/bin/app_identity.toml");
    let ifaces_path = path::Path::new("/opt/firewhal/bin/interface_state.toml");

    let mut events: Vec<AlarmEvent> = Vec::new();

    // --- rules: missing/malformed -> empty rule set (default-deny) ---
    let rules_load = load_rules_config(rules_path);
    let (rules_config, rules_health, rules_note) = match &rules_load {
        ConfigLoadResult::Loaded(c) => (
            c.clone(),
            FileHealth::Healthy,
            String::new(),
        ),
        ConfigLoadResult::Missing => (
            FireWhalConfig { outgoing_rules: vec![], incoming_rules: vec![] },
            FileHealth::Degraded,
            "missing — NO RULES loaded; all traffic is blocked (fail-closed default). Restore the file, then reload from the TUI (or restart the stack).".to_string(),
        ),
        ConfigLoadResult::Malformed { reason } => (
            FireWhalConfig { outgoing_rules: vec![], incoming_rules: vec![] },
            FileHealth::Degraded,
            format!("malformed ({reason}) — NO RULES loaded; all traffic is blocked (fail-closed default). Fix the file, then reload from the TUI (or restart the stack)."),
        ),
    };

    // --- apps: missing -> bootstrap empty allowlist (historical behavior);
    //     malformed -> empty allowlist (egress denied at the app gate).
    //     An EMPTY allowlist is a degraded posture in itself (all egress
    //     denied at the app gate) — same classification the firewhal-health
    //     validator uses, so daemon and validator can never disagree. ---
    let apps_load = load_app_ids_config(apps_path);
    let (apps_config, apps_health, apps_note) = match &apps_load {
        ConfigLoadResult::Loaded(c) if !c.apps.is_empty() => (c.clone(), FileHealth::Healthy, String::new()),
        ConfigLoadResult::Loaded(c) => (
            c.clone(),
            FileHealth::Degraded,
            "valid but EMPTY allowlist — all egress is denied at the app gate (fail-closed). Restore the allowlist.".to_string(),
        ),
        ConfigLoadResult::Missing => {
            eprintln!("[Supervisor] App identity file not found at '{apps_path:?}'. Creating a new, empty one (C1: announcing as degraded).");
            let empty = ApplicationAllowlistConfig { apps: HashMap::new() };
            if let Err(e) = save_app_ids(apps_path, &empty) {
                eprintln!("[Supervisor] C1: failed to bootstrap empty app allowlist: {e}");
            }
            (
                empty,
                FileHealth::Degraded,
                "missing — created an empty app allowlist; all egress is denied at the app gate (fail-closed). Restore the file, then reload from the TUI (or restart the stack).".to_string(),
            )
        }
        ConfigLoadResult::Malformed { reason } => (
            ApplicationAllowlistConfig { apps: HashMap::new() },
            FileHealth::Degraded,
            format!("malformed ({reason}) — an empty app allowlist is in effect; all egress is denied at the app gate (fail-closed). Fix the file, then reload from the TUI (or restart the stack)."),
        ),
    };

    // --- interfaces: missing/malformed/empty -> ALL non-loopback (the
    //     fail-closed default; the TC layer is never left unattached) ---
    let ifaces_load = load_interface_state_config(ifaces_path);
    let default_ifaces = default_enforced_interfaces();
    let default_list = {
        let mut v: Vec<String> = default_ifaces.iter().cloned().collect();
        v.sort();
        v.join(", ")
    };
    let (ifaces_config, ifaces_health, ifaces_note) = match &ifaces_load {
        ConfigLoadResult::Loaded(c) if !c.enforced_interfaces.is_empty() => {
            // Prune interfaces that no longer exist (historical behavior)
            let current = get_all_interfaces();
            let mut pruned = c.clone();
            pruned.enforced_interfaces.retain(|x| current.contains(x));
            if !pruned.enforced_interfaces.is_empty() {
                (pruned, FileHealth::Healthy, String::new())
            } else {
                // everything in the file is gone — fall through to the default
                (
                    InterfaceStateConfig { enforced_interfaces: default_ifaces.clone() },
                    FileHealth::Degraded,
                    format!("no declared interface still exists — defaulting to all non-loopback interfaces: {default_list} (fail-closed; your management path is protected only if your rules allow it). Restore the file to control the list."),
                )
            }
        }
        other => {
            let note = match other {
                ConfigLoadResult::Missing => "missing".to_string(),
                ConfigLoadResult::Malformed { reason } => format!("malformed ({reason})"),
                ConfigLoadResult::Loaded(_) => "empty interface list".to_string(),
                _ => unreachable!(),
            };
            (
                InterfaceStateConfig { enforced_interfaces: default_ifaces.clone() },
                FileHealth::Degraded,
                format!("{note} — defaulting to all non-loopback interfaces: {default_list} (fail-closed; your management path is protected only if your rules allow it). Restore the file to control the list."),
            )
        }
    };

    // --- push the effective config (loaded, or the fail-closed default) ---
    if let Err(e) = to_zmq_tx
        .send(FireWhalMessage::LoadRules(rules_config))
        .await
    {
        eprintln!("[Supervisor] C1: FAILED to send rules: {e}");
    } else {
        println!("[Supervisor] C1: rules sent ({}).", if rules_health == FileHealth::Healthy { "configured" } else { "fail-closed empty default" });
    }
    if let Err(e) = to_zmq_tx
        .send(FireWhalMessage::LoadAppIds(apps_config))
        .await
    {
        eprintln!("[Supervisor] C1: FAILED to send app ids: {e}");
    } else {
        println!("[Supervisor] C1: app ids sent ({}).", if apps_health == FileHealth::Healthy { "configured" } else { "fail-closed empty default" });
    }
    if let Err(e) = to_zmq_tx
        .send(FireWhalMessage::LoadInterfaceState(ifaces_config))
        .await
    {
        eprintln!("[Supervisor] C1: FAILED to send interface state: {e}");
    } else {
        println!("[Supervisor] C1: interface state sent ({}).", if ifaces_health == FileHealth::Healthy { "configured" } else { "fail-closed all-non-loopback default" });
    }

    let new_state = ConfigHealthState {
        rules: (rules_health, rules_note),
        apps: (apps_health, apps_note),
        interfaces: (ifaces_health, ifaces_note),
    };

    // --- announce the transitions (first evaluation: all-healthy baseline) ---
    let baseline = ConfigHealthState {
        rules: (FileHealth::Healthy, String::new()),
        apps: (FileHealth::Healthy, String::new()),
        interfaces: (FileHealth::Healthy, String::new()),
    };
    let prev = prev.unwrap_or(&baseline);
    if prev.rules.0 != new_state.rules.0 {
        events.push(AlarmEvent { file: "firewall_rules.toml", healthy: new_state.rules.0 == FileHealth::Healthy, note: if new_state.rules.0 == FileHealth::Healthy { "rules restored — the configured rule set is in effect again.".to_string() } else { new_state.rules.1.clone() } });
    }
    if prev.apps.0 != new_state.apps.0 {
        events.push(AlarmEvent { file: "app_identity.toml", healthy: new_state.apps.0 == FileHealth::Healthy, note: if new_state.apps.0 == FileHealth::Healthy { "app allowlist restored — the configured allowlist is in effect again.".to_string() } else { new_state.apps.1.clone() } });
    }
    if prev.interfaces.0 != new_state.interfaces.0 {
        events.push(AlarmEvent { file: "interface_state.toml", healthy: new_state.interfaces.0 == FileHealth::Healthy, note: if new_state.interfaces.0 == FileHealth::Healthy { "interface list restored — the declared enforced-interface set is in effect again.".to_string() } else { new_state.interfaces.1.clone() } });
    }

    (new_state, events)
}

/// Launches a child process, optionally as a specific user.
fn launch_process(
    program: &str,
    args: &[&str],
    user: Option<&str>,
    working_dir: Option<&str>,
) -> Result<u32, String> {
    let mut command = Command::new(program);
    command.args(args);

    if let Some(dir) = working_dir {
        command.current_dir(dir);
    }
    
    // If a user is specified, look them up and set the process UID/GID.
    if let Some(user_name) = user {
        let target_user = nix::unistd::User::from_name(user_name)
            .map_err(|e| e.to_string())?
            .ok_or(format!("User '{}' not found", user_name))?;
        
        // Take ownership of the user_name so it can be moved into the 'static closure.
        let user_name_owned = user_name.to_string();

        // Use pre_exec to correctly drop privileges, including supplementary groups.
        // This is unsafe because it runs in the child process after fork, where many
        // things are not safe to do. However, the nix calls are designed for this.
        let last_error = Arc::new(StdMutex::new(None));
        let last_error_clone = Arc::clone(&last_error);
        
        unsafe {
            command.pre_exec(move || {
                // Initialize supplementary groups for the target user.
                // Clone the string to create the CString, as CString::new consumes its input.
                if let Err(e) = nix::unistd::initgroups(&CString::new(user_name_owned.clone()).unwrap(), target_user.gid) {
                    *last_error_clone.lock().unwrap() = Some(std::io::Error::from_raw_os_error(e as i32));
                    return Err(std::io::Error::from_raw_os_error(e as i32));
                }
                // Set the primary group and user ID.
                nix::unistd::setgid(target_user.gid).map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
                nix::unistd::setuid(target_user.uid).map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
                Ok(())
            });
        }
    }
    // If `user` is `None`, the new process inherits the current user (root).
    
    match command.spawn() {
        Ok(child) => Ok(child.id()), // Return the process ID (PID)
        Err(e) => Err(format!("Failed to spawn '{}': {}", program, e)),
    }
}






/// Main entry point for the daemon.
fn main() {
    let stdout = File::create("/tmp/firewhal-daemon.out").unwrap();
    let stderr = File::create("/tmp/firewhal-daemon.err").unwrap();

    let (read_fd_owned, write_fd_owned) = pipe().expect("Failed to create pipe");
    let write_fd = write_fd_owned.into_raw_fd();
    let read_fd = read_fd_owned.into_raw_fd();

    let daemonize = Daemonize::new()
        .pid_file("/var/run/firewhal-daemon.pid")
        .working_directory("/tmp")
        .stdout(stdout)
        .stderr(stderr)
        .privileged_action(move || {
    let root_processes = vec![
        ("/opt/firewhal/bin/firewhal-ipc", vec![]),
        ("/opt/firewhal/bin/firewhal-kernel", vec![]),
    ];

    let mut writer = unsafe { File::from_raw_fd(write_fd) };

    for (path, args_vec) in root_processes {
        let args: Vec<&str> = args_vec.iter().map(|s| *s).collect();
        
        // Call the unified function with `user: None` to run as root.
        match launch_process(path, &args, None, None) {
            Ok(pid) => {
                // Write the PID to the pipe for the main logic.
                writer.write_all(&pid.to_ne_bytes()).unwrap();
            }
            Err(e) => eprintln!("[Privileged] Failed to launch {}: {}", path, e),
        }
    }
    drop(writer)
    
    

});

    match daemonize.start() {
        Ok(_) => {
            if let Err(e) = supervisor_logic(read_fd) {
                eprintln!("[Daemon] Supervisor logic failed: {}", e);
            }
        }
        Err(e) => eprintln!("[Daemon] Error starting daemon: {}", e),
    }
}

// Takes an app_id_config and then uses the hasher to rehash each application and then update the config with the updated hashes
async fn correct_hash_for_app_id(
    mut app_to_hash: (String, AppIdentity),
) -> Result<(String, AppIdentity), anyhow::Error> {
    // Reverting to a sequential loop. This is slower than concurrent versions
    // but has proven to be the most stable, as it avoids spawning many
    // processes at once, which was causing resource exhaustion and crashes.

    // Check if file at path actually exists.
    if app_to_hash.1.path.exists() && app_to_hash.1.path.is_file() { 
        println!("[Supervisor] Updating hash for '{}'.", app_to_hash.1.path.display());
        app_to_hash.1.hash = calculate_file_hash(app_to_hash.1.path.clone()).await?;
    } else {
        // Change path text to say INVALID PATH
        app_to_hash.1.path = PathBuf::from("INVALID PATH");
        app_to_hash.1.hash = "UNKNOWN".to_string();
    }


    // Return the modified map by value.
    Ok(app_to_hash)
}

/// The main async logic for the supervisor daemon.
#[tokio::main]
async fn supervisor_logic(root_pids_fd: i32) -> Result<(), Box<dyn std::error::Error>> {
    // ... all of your setup code remains exactly the same up to this point ...
    let children = Arc::new(Mutex::new(HashMap::new()));
    let mut config_health: Option<ConfigHealthState> = None; // C1: §2.4 config-path health
    let (to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(128);
    let (from_zmq_tx, mut from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
    let (zmq_shutdown_tx, zmq_shutdown_rx) = broadcast::channel::<()>(1);
    let zmq_task_handle = tokio::spawn(ipc_client_connection(DEFAULT_IPC_ENDPOINT.to_string(), to_zmq_rx, from_zmq_tx, zmq_shutdown_rx, "Daemon".to_string(), None));
    let ident_msg = FireWhalMessage::Status(StatusUpdate {
        component: "Daemon".to_string(),
        is_healthy: true,
        message: "Ready".to_string(),
    });
    to_zmq_tx.send(ident_msg).await?;
    let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);

    
    // ... all the code for launching child processes remains the same ...
    let mut children_guard = children.lock().await;
    let mut reader = unsafe { File::from_raw_fd(root_pids_fd) };
    let mut pid_buffer = [0u8; 4];
    reader.read_exact(&mut pid_buffer)?;
    let ipc_router_pid = i32::from_ne_bytes(pid_buffer);
    children_guard.insert("ipc_router".to_string(), ipc_router_pid);

    reader.read_exact(&mut pid_buffer)?;
    let firewall_pid = i32::from_ne_bytes(pid_buffer);
    children_guard.insert("firewall".to_string(), firewall_pid);
    drop(reader);

    let apps_to_launch = vec![(
        "discord_bot",
        "nobody",
        "/opt/firewhal/bin/firewhal-discord-bot",
        vec![],
        Some("/opt/firewhal"),
    )];
    for (name, user, path, args, workdir) in apps_to_launch {
        let name_str = name.to_string();
        let handle = task::spawn_blocking(move || { launch_process(path, &args, Some(user), workdir) });
        match handle.await? {
            Ok(pid) => {
                println!("[Supervisor] Launched '{}' with PID {}.", name, pid);
                children_guard.insert(name_str.clone(), pid as i32);
                let launch_message = FireWhalMessage::Debug(DebugMessage {
                    source: "Daemon".to_string(),
                    content: format!("[Supervisor] Launched '{}' with PID {}.", name, pid),
                });
                to_zmq_tx.send(launch_message).await.ok();
            }
            Err(e) => {
                eprintln!("[Supervisor] FAILED to launch '{}': {}", name, e);
                let launch_fail_message = FireWhalMessage::Debug(DebugMessage {
                    source: "Daemon".to_string(),
                    content: format!("[Supervisor] Failed to launch '{}': {}.", name, e),
                });
                to_zmq_tx.send(launch_fail_message).await.ok();
            } 
        }
    }
    drop(children_guard);

    // ====================== CHANGE IS HERE ======================

    // 1. Spawn the handlers as independent, concurrent background tasks.
    let shutdown_handler =
        handle_shutdown_signals(Arc::clone(&children), to_zmq_tx.clone(), shutdown_tx.clone());
    tokio::spawn(shutdown_handler);

    let child_exit_handler =
        handle_child_exits(Arc::clone(&children), to_zmq_tx.clone(), shutdown_tx.subscribe());
    tokio::spawn(child_exit_handler);
    
    println!("[Supervisor] All components launched. Monitoring for messages and signals...");

    // 2. The main loop now only handles incoming messages and the shutdown signal.
    // Clone receiver for receiving messages across arms
    loop {
        tokio::select! {
            // Biased select ensures we check for shutdown first if both are ready.
            biased;

            // Listen for the shutdown signal from the broadcast channel.
            _ = shutdown_rx.recv() => {
                println!("[Supervisor] Shutdown signal received, exiting main loop.");
                break; // Exit the loop
            },

            // Listen for incoming IPC messages.
            Some(message) = from_zmq_rx.recv() => {
                match message {
                    FireWhalMessage::Status(status) => {
                        if status.component == "Firewall" && status.message == "Ready" { // Wait for ready status to be forwarded from the IPC socket, then send rules
                            println!("[Supervisor] Firewall is ready. Loading and sending config (C1: health-evaluated)...");
                            // C1 (design doc §2.4): load all three config files with
                            // health tracking, apply the fail-closed defaults where
                            // needed, push the effective config, and announce any
                            // state transition (alarm bundle + honest TUI status).
                            apply_config_health(&to_zmq_tx, &mut config_health).await;
                        } else if status.component == "TUI" {
                            // C1: the TUI (re)connected — report the CURRENT config
                            // health so a TUI started after a degraded startup still
                            // shows the yellow degraded banner (transition-only
                            // announcements would miss it).
                            if let Some(st) = config_health.as_ref() {
                                if !st.all_healthy() {
                                    let msg = format!(
                                        "DEGRADED: {}",
                                        [
                                            (st.rules.0, st.rules.1.as_str()),
                                            (st.apps.0, st.apps.1.as_str()),
                                            (st.interfaces.0, st.interfaces.1.as_str()),
                                        ]
                                        .iter()
                                        .filter(|(h, _)| *h == FileHealth::Degraded)
                                        .map(|(_, note)| (*note).to_string())
                                        .collect::<Vec<_>>()
                                        .join("; ")
                                    );
                                    if let Err(e) = to_zmq_tx
                                        .send(FireWhalMessage::Status(StatusUpdate {
                                            component: "Daemon".to_string(),
                                            is_healthy: false,
                                            message: msg,
                                        }))
                                        .await
                                    {
                                        eprintln!("[Supervisor] C1: failed to send config status: {e}");
                                    }
                                }
                            }
                        }
                    }
                    FireWhalMessage::Ping(_) => {
                        let pong_message = FireWhalMessage::Pong( StatusPong {
                            source: "Daemon".to_string()
                        });
                        if let Err(e) = to_zmq_tx.send(pong_message).await {
                            eprintln!("[Supervisor] FAILED to send pong: {}", e);
                        }
                    }
                    FireWhalMessage::AddAppIds(message) => {
                        if message.component == "TUI" {
                            println!("[Supervisor] Received AddAppIds command from TUI");
                            let app_id_path = path::Path::new("/opt/firewhal/bin/app_identity.toml");
                            // Add app ids and then overwrite current file
                            add_app_ids(app_id_path, message.app_ids_to_add);
                            // C1: re-evaluate all config (the add may have healed a
                            // degraded allowlist); announces on transitions.
                            apply_config_health(&to_zmq_tx, &mut config_health).await;
                        }

                    }
                    FireWhalMessage::RulesRequest(message) => {
                        if message.component == "TUI" {
                            println!("[Supervisor] Received RuleRequest command from TUI");
                            match load_rules(path::Path::new("/opt/firewhal/bin/firewall_rules.toml")) {
                                Ok(config) => {
                                    let msg = FireWhalMessage::RulesResponse(config);
                                    if let Err(e) = to_zmq_tx.send(msg).await {
                                        eprintln!("[Supervisor] FAILED to send rules: {}", e);
                                    } else {
                                        println!("[Supervisor] Rules successfully sent to TUI");
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[Supervisor] FAILED to load rules for TUI: {}", e);
                                }
                            }
                        }
                    }
                    FireWhalMessage::UpdateRules(message) => {
                       println!("[Supervisor] Received UpdateRules command from TUI"); 
                       let path = path::Path::new("/opt/firewhal/bin/firewall_rules.toml");
                       save_rules(path, &message)?;
                       // C1: re-evaluate all config (the update may have healed a
                       // degraded rule file); announces on transitions.
                       apply_config_health(&to_zmq_tx, &mut config_health).await;
                    }
                    FireWhalMessage::AppsRequest(message) => {
                        println!("[Supervisor] Received AppsRequest command from TUI"); 
                        // Load app ids and hashes and send to userspace loader
                            let app_id_path = path::Path::new("/opt/firewhal/bin/app_identity.toml");
                            match load_app_ids(app_id_path) {
                                Ok(config) => {
                                    let msg = FireWhalMessage::AppsResponse(config);
                                    if let Err(e) = to_zmq_tx.send(msg).await {
                                        eprintln!("[Supervisor] Failed to send app id list: {}", e);
                                    } else {
                                        println!("[Supervisor] App ID list successfully sent to TUI.");
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[Supervisor] Failed to load app ids: {}", e);
                                }

                            }
                    }
                    FireWhalMessage::UpdateAppIds(message) => {
                        println!("[Supervisor] Received UpdateAppIds command from TUI");
                        let app_id_path = path::Path::new("/opt/firewhal/bin/app_identity.toml");
                        save_app_ids(app_id_path, &message)?;
                        // C1: re-evaluate all config (the update may have healed a
                        // degraded allowlist); announces on transitions.
                        apply_config_health(&to_zmq_tx, &mut config_health).await;
                    }
                    FireWhalMessage::InterfaceRequest(message) => {
                        println!("[Superivsor] Received InterfaceRequest command from TUI");
                        let path = path::Path::new("/opt/firewhal/bin/interface_state.toml");
                        match load_interface_state(path) {
                            Ok(interface_state) => {
                                let msg = FireWhalMessage::InterfaceResponse(
                                    NetInterfaceResponse {
                                        source: "Daemon".to_string(),
                                        interface_state: interface_state,
                                        current_interfaces: get_all_interfaces()
                                    }
                                );
                                if let Err(e) = to_zmq_tx.send(msg).await {
                                    eprintln!("[Supervisor] Failed to send interface list: {}", e);
                                } else {
                                    println!("[Supervisor] Interface list successfully sent to TUI.");
                                }
                            }
                            Err(e) => {
                                eprintln!("[Supervisor] Failed to load interface list: {}", e);
                            }
                        }
                    }
                    FireWhalMessage::UpdateInterfaces(message) => {
                        println!("[Supervisor] Received UpdateInterfaces command from TUI");
                        let path = path::Path::new("/opt/firewhal/bin/interface_state.toml");
                        save_interface_state(path, &message.interfaces)?;
                        // C1: re-evaluate all config (the update may have healed a
                        // degraded interface list); announces on transitions.
                        apply_config_health(&to_zmq_tx, &mut config_health).await;
                    }
                    FireWhalMessage::HashRequest(message) => {
                        println!("[Supervisor] Received HashesRequest command from TUI");
                        // Collect update all hashes in app list and then send back
                        let updated_hash = correct_hash_for_app_id(message.app_to_get_hash_for).await?;
                        let msg = FireWhalMessage::HashResponse(
                            DaemonHashResponse {
                                component: "Daemon".to_string(),
                                app_with_updated_hash: updated_hash,
                            }
                        );
                        if let Err(e) = to_zmq_tx.send(msg).await {
                            eprintln!("[Supervisor] Failed to send hashes: {}", e);
                        } else {
                            println!("[Supervisor] Hashes successfully sent to TUI.");
                        }
                    }
                    FireWhalMessage::HashUpdateRequest(message) => {
                        println!("[Supervisor] Received HashUpdateRequest command from TUI");
                        let updated_hash = correct_hash_for_app_id(message.app_to_update_hash_for).await?;
                        let msg = FireWhalMessage::HashUpdateResponse(
                            UpdatedHashResponse {
                                component: "Daemon".to_string(),
                                updated_app: updated_hash,
                            }
                        );
                        if let Err(e) = to_zmq_tx.send(msg).await {
                            eprintln!("[Supervisor] Failed to send hashes: {}", e);
                        }
                        
                    }
                    _ => {
                    }
                }
            },
        }
    }
    println!("[Supervisor] Main loop exited. Cleaning up remaining tasks...");

    // 1. Abort the ZMQ connection task. This will forcefully cancel it.
    zmq_shutdown_tx.send(()).unwrap();


    // 2. We can optionally await the handle to ensure it has shut down.
    //    The result will be an error because we aborted it, which is expected.
    let _ = zmq_task_handle.await;
    println!("[Supervisor] ZMQ client task has been shut down.");
    
    // The to_zmq_tx sender is dropped automatically when supervisor_logic exits.
    println!("[Supervisor] Exiting daemon.");
    Ok(())
}

/// An async task that listens for the SIGCHLD signal and cleans up zombie processes.
async fn handle_child_exits(
    children: ChildProcesses,
    zmq_tx: mpsc::Sender<FireWhalMessage>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let mut stream = signal(SignalKind::child()).unwrap();
    loop {
        tokio::select! {
            Ok(_) = shutdown_rx.recv() => {
                println!("[Monitor] Received shutdown. Will exit after reaping remaining children.");
                break; // Exit the infinite loop
            },
            _ = stream.recv() => {
                loop {
                    match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::Exited(pid, status)) => {
                            let mut children_guard = children.lock().await;
                            if let Some(name) = children_guard.iter().find_map(|(name, &p)| {
                                if p == pid.into() { Some(name.clone()) } else { None }
                            }) {
                                eprintln!("[Monitor] Child '{}' (PID {}) exited with status {}.", name, pid, status);
                                let msg = FireWhalMessage::Debug(DebugMessage {
                                    source: "Daemon".to_string(),
                                    content: format!("Child {} has exited.", name),
                                });
                                zmq_tx.send(msg).await.ok();
                                children_guard.remove(&name);
                            }
                        }
                        Ok(WaitStatus::StillAlive) | Ok(_) => break,
                        Err(_) => break,
                    }
                }
            }
        }
    }

    // After shutdown is signaled, continue reaping any remaining children that exit.
    println!("[Monitor] Shutdown mode: Reaping any stragglers.");
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, _)) | Ok(WaitStatus::Signaled(pid, _, _)) => {
                let mut children_guard = children.lock().await;
                if let Some(name) = children_guard.iter().find_map(|(name, &p)| if p == pid.into() { Some(name.clone()) } else { None }) {
                    eprintln!("[Monitor] Reaped final child '{}' (PID {}).", name, pid);
                    children_guard.remove(&name);
                }
            }
            Ok(WaitStatus::StillAlive) | Ok(_) => {
                if children.lock().await.is_empty() { break; }
                sleep(Duration::from_millis(50)).await;
            }
            Err(_) => break, // ECHILD, no more children to wait for.
        }
    }
    println!("[Monitor] Child monitor task finished.");
}

/// An async task that listens for SIGTERM/SIGINT and gracefully shuts down children.
async fn handle_shutdown_signals(
    children: ChildProcesses,
    zmq_tx: mpsc::Sender<FireWhalMessage>,
    shutdown_tx: broadcast::Sender<()>,
) {
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();

    tokio::select! {
        _ = sigterm.recv() => println!("[Shutdown] Received SIGTERM."),
        _ = sigint.recv() => println!("[Shutdown] Received SIGINT."),
    };
    
    // Notify all other internal tasks to shut down.
    if shutdown_tx.send(()).is_err() {
        eprintln!("[Shutdown] Failed to broadcast shutdown signal to other tasks.");
    }

    println!("[Shutdown] Starting graceful shutdown of child processes...");
    let msg = FireWhalMessage::Debug(DebugMessage {
        source: "Daemon".to_string(),
        content: "Daemon shutting down.".to_string(),
    });
    zmq_tx.send(msg).await.ok();

    // --- PHASE 1: GRACEFUL SHUTDOWN (SIGTERM) ---
    {
        let children_guard = children.lock().await;
        for (name, &pid) in children_guard.iter() {
            println!("[Shutdown] Sending SIGTERM to '{}' (PID {})...", name, pid);
            let _ = signal::kill(Pid::from_raw(pid), Signal::SIGTERM);
        }
    } // Lock is released

    // Wait for up to 5 seconds for children to exit gracefully.
    let wait_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if children.lock().await.is_empty() {
            println!("[Shutdown] All children have exited gracefully.");
            break; // Success! Exit the loop.
        }
        if tokio::time::Instant::now() > wait_deadline {
            eprintln!("[Shutdown] Timeout waiting for graceful exit. Escalating to SIGKILL.");
            break; // Timeout, proceed to forceful shutdown.
        }
        sleep(Duration::from_millis(200)).await;
    }

    // --- PHASE 2: FORCEFUL SHUTDOWN (SIGKILL) ---
    // This part only runs if the graceful shutdown timed out.
    let remaining_children = children.lock().await;
    if !remaining_children.is_empty() {
        println!("[Shutdown] Forcibly terminating stubborn children...");
        for (name, &pid) in remaining_children.iter() {
            println!("[Shutdown] Sending SIGKILL to '{}' (PID {})...", name, pid);
            let _ = signal::kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
    }
    
    println!("[Shutdown] Shutdown signals sent. Handler task is finished.");
}