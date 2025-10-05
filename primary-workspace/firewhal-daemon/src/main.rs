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
use bincode;

// Standard library imports
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::sync::{Arc, Mutex as StdMutex};
use std::{path, vec};
use std::process::{Command, Stdio};
use std::os::unix::process::CommandExt;


// Workspace imports
use firewhal_core::{zmq_client_connection, DebugMessage, FireWhalMessage, StatusUpdate, FirewallConfig};

// A type alias for clarity. Maps a component name (String) to its PID (i32).
type ChildProcesses = Arc<Mutex<HashMap<String, i32>>>;


//Loads and deserializes firewall rules from a binary file
fn load_rules(path: &path::Path) -> Result<FirewallConfig, Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let config = bincode::config::standard();
    let (decoded_rules, _len): (FirewallConfig, usize) =
        bincode::decode_from_slice(&data, config)?;
    Ok(decoded_rules)
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
    // TEST CODE, DELETE LATER
    // match launch_process("/opt/firewhal/bin/firewhal-discord-bot", &vec![], Some("nobody"), Some("/opt/firewhal")) {
    //     Ok(pid) => {
    //         writer.write_all(&pid.to_ne_bytes()).unwrap();
    //     }
    //     Err(e) => {
    //         eprintln!("[Privileged] Failed to launch /opt/firewhal/bin/firewhal-discord-bot: {}", e);
    //     }
    // }
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

/// The main async logic for the supervisor daemon.
#[tokio::main]
async fn supervisor_logic(root_pids_fd: i32) -> Result<(), Box<dyn std::error::Error>> {
    // ... all of your setup code remains exactly the same up to this point ...
    let children = Arc::new(Mutex::new(HashMap::new()));
    let (to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(128);
    let (from_zmq_tx, mut from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
    let zmq_task_handle = tokio::spawn(zmq_client_connection(to_zmq_rx, from_zmq_tx));
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
                if let FireWhalMessage::Status(status) = message {
                    if status.component == "Firewall" && status.message == "Ready" {
                        println!("[Supervisor] Firewall is ready. Loading and sending rules...");
                        let rules_path = path::Path::new("/opt/firewhal/bin/firewall.rules");
                        match load_rules(rules_path) {
                            Ok(config) => {
                                let msg = FireWhalMessage::LoadRules(config);
                                if let Err(e) = to_zmq_tx.send(msg).await {
                                    eprintln!("[Supervisor] FAILED to send rules: {}", e);
                                } else {
                                    println!("[Supervisor] Rules successfully sent to firewall.");
                                }
                            }
                            Err(e) => {
                                eprintln!("[Supervisor] FAILED to load firewall rules: {}", e);
                            }
                        }
                    }
                }
            },
        }
    }
    println!("[Supervisor] Main loop exited. Cleaning up remaining tasks...");

    // 1. Abort the ZMQ connection task. This will forcefully cancel it.
    zmq_task_handle.abort();

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