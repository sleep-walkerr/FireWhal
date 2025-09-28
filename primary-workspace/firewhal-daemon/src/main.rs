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

// Standard library imports
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::sync::Arc;

// Workspace imports
use firewhal_core::{zmq_client_connection, DebugMessage, FireWhalMessage, StatusUpdate};

// A type alias for clarity. Maps a component name (String) to its PID (i32).
type ChildProcesses = Arc<Mutex<HashMap<String, i32>>>;

/// Launches a child process as a specific user with an optional working directory.
/// (Used for non-privileged processes)
fn launch_child_process(
    user: &str,
    program: &str,
    args: &[&str],
    working_dir: Option<&str>,
) -> Result<i32, String> {
    let target_user = nix::unistd::User::from_name(user)
        .map_err(|e| e.to_string())?
        .ok_or(format!("User '{}' not found", user))?;
    let target_uid = target_user.uid;
    let target_gid = target_user.gid;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => Ok(child.into()),
        Ok(ForkResult::Child) => {
            if let Err(e) = setgid(target_gid) {
                eprintln!("[Child] Failed to set group ID for {}: {}", program, e);
                std::process::exit(1);
            }
            if let Err(e) = setuid(target_uid) {
                eprintln!("[Child] Failed to set user ID for {}: {}", program, e);
                std::process::exit(1);
            }
            if let Some(dir) = working_dir {
                if let Err(e) = chdir(dir) {
                    eprintln!(
                        "[Child] Failed to change working directory to '{}' for {}: {}",
                        dir, program, e
                    );
                    std::process::exit(1);
                }
            }
            let c_program = CString::new(program).unwrap();
            let c_args: Vec<CString> = args.iter().map(|&arg| CString::new(arg).unwrap()).collect();
            let c_args_refs: Vec<&CStr> = c_args.iter().map(|c| c.as_c_str()).collect();
            let _ = execv(&c_program, &c_args_refs).map_err(|e| {
                eprintln!("[Child] Failed to exec '{}': {}", program, e);
                std::process::exit(127);
            });
            unreachable!();
        }
        Err(e) => Err(format!("Fork failed: {}", e)),
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
            // This code runs as root before privileges are dropped.
            let root_processes = vec![
                ("/opt/firewhal/bin/firewhal-kernel", vec!["firewhal-kernel"]),
                ("/opt/firewhal/bin/firewhal-ipc", vec!["firewhal-ipc"]),
            ];
            let mut writer = unsafe { File::from_raw_fd(write_fd) };
            for (path, args_vec) in root_processes {
                let args: Vec<&str> = args_vec.iter().map(|s| *s).collect();
                match unsafe { fork() } {
                    Ok(ForkResult::Parent { child }) => {
                        writer.write_all(&i32::from(child).to_ne_bytes()).unwrap();
                    }
                    Ok(ForkResult::Child) => {
                        let c_program = CString::new(path).unwrap();
                        let c_args: Vec<CString> =
                            args.iter().map(|&arg| CString::new(arg).unwrap()).collect();
                        let c_args_refs: Vec<&CStr> = c_args.iter().map(|c| c.as_c_str()).collect();
                        let _ = execv(&c_program, &c_args_refs);
                        std::process::exit(127);
                    }
                    Err(e) => eprintln!("[Privileged] Fork failed for {}: {}", path, e),
                }
            }
            // Privileges are dropped after this closure returns.
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
    let children = Arc::new(Mutex::new(HashMap::new()));

    // Setup channels for the unified ZMQ client task.
    // `to_zmq_tx` is used by the supervisor to send messages out.
    let (to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(128);
    // The daemon doesn't currently process incoming messages, so we create a
    // channel for them but won't use the receiver.
    let (from_zmq_tx, _from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);

    // Spawn the unified ZMQ client connection task.
    let zmq_task_handle = tokio::spawn(zmq_client_connection(to_zmq_rx, from_zmq_tx));

    // Send a "Ready" message to register with the IPC router.
    let ident_msg = FireWhalMessage::Status(StatusUpdate {
        component: "Daemon".to_string(),
        is_healthy: true,
        message: "Ready".to_string(),
    });
    to_zmq_tx.send(ident_msg).await?;

    let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);

    let mut children_guard = children.lock().await;
    let mut reader = unsafe { File::from_raw_fd(root_pids_fd) };
    let mut pid_buffer = [0u8; 4];

    reader.read_exact(&mut pid_buffer)?;
    let firewall_pid = i32::from_ne_bytes(pid_buffer);
    children_guard.insert("firewall".to_string(), firewall_pid);

    reader.read_exact(&mut pid_buffer)?;
    let ipc_router_pid = i32::from_ne_bytes(pid_buffer);
    children_guard.insert("ipc_router".to_string(), ipc_router_pid);
    drop(reader);

    let apps_to_launch = vec![(
        "discord_bot",
        "nobody",
        "/opt/firewhal/bin/firewhal-discord-bot",
        vec!["firewhal-discord-bot"],
        Some("/opt/firewhal"),
    )];

    for (name, user, path, args, workdir) in apps_to_launch {
        let name_str = name.to_string();
        let handle = task::spawn_blocking(move || {
            let args_cstr: Vec<&str> = args.iter().map(|s| *s).collect();
            launch_child_process(user, path, &args_cstr, workdir)
        });
        match handle.await? {
            Ok(pid) => {
                println!("[Supervisor] Launched '{}' with PID {}.", name, pid);
                children_guard.insert(name_str.clone(), pid);
                let msg = FireWhalMessage::Debug(DebugMessage {
                    source: "Daemon".to_string(),
                    content: format!("Launched {} with PID {}", name_str, pid),
                });
                to_zmq_tx.send(msg).await.ok();
            }
            Err(e) => {
                eprintln!("[Supervisor] FAILED to launch '{}': {}", name, e);
                let msg = FireWhalMessage::Debug(DebugMessage {
                    source: "Daemon".to_string(),
                    content: format!("FAILED to launch {}", name_str),
                });
                to_zmq_tx.send(msg).await.ok();
            }
        }
    }
    drop(children_guard);

    // Pass the broadcast sender/receiver to the tasks.
    let shutdown_handler =
        handle_shutdown_signals(Arc::clone(&children), to_zmq_tx.clone(), shutdown_tx.clone());
    let child_exit_handler =
        handle_child_exits(Arc::clone(&children), to_zmq_tx.clone(), shutdown_tx.subscribe());

    println!("[Supervisor] All components launched. Monitoring for signals...");

    // Wait for a shutdown signal to be handled, or for the child monitor to exit.
    tokio::select! {
        _ = child_exit_handler => eprintln!("[Supervisor] Child exit handler unexpectedly finished."),
        _ = shutdown_handler => println!("[Supervisor] OS signal handler finished."),
    }

    // After shutdown is triggered, wait for the ZMQ client to finish its work.
    drop(to_zmq_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), zmq_task_handle).await;
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
    
    // Notify all other tasks to shut down.
    if shutdown_tx.send(()).is_err() {
        eprintln!("[Shutdown] Failed to broadcast shutdown signal to other tasks.");
    }

    println!("[Shutdown] Starting graceful shutdown of child processes...");
    let msg = FireWhalMessage::Debug(DebugMessage {
        source: "Daemon".to_string(),
        content: "Daemon shutting down.".to_string(),
    });
    zmq_tx.send(msg).await.ok();

    let children_guard = children.lock().await;
    let pids_to_reap: Vec<_> = children_guard.values().cloned().collect();
    for (name, &pid) in children_guard.iter() {
        println!("[Shutdown] Sending SIGTERM to '{}' (PID {})...", name, pid);
        let _ = signal::kill(Pid::from_raw(pid), Signal::SIGTERM);
    }
    drop(children_guard);

    // Wait for the child monitor to reap all processes.
    let wait_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if children.lock().await.is_empty() {
            println!("[Shutdown] All children have exited.");
            break;
        }
        if tokio::time::Instant::now() > wait_deadline {
            eprintln!("[Shutdown] Timeout waiting for children to exit. Some processes may remain.");
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }
}
