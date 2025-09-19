//! Supervisor Daemon for the Firewhal Firewall System
//!
//! This daemon is responsible for:
//! 1. Starting as root, launching privileged components, then dropping its own privileges to 'nobody'.
//! 2. Launching, managing, and monitoring all other system components.
//!    - The eBPF Firewall (as root)
//!    - The ZMQ IPC Router (as nobody)
//!    - The Discord Bot (as nobody)
//! 3. Reporting status and errors via ZMQ to the IPC router.
//! 4. Handling graceful shutdown of all components.

// Crate imports
use daemonize::Daemonize;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{chdir, execv, fork, pipe, setgid, setuid, ForkResult, Pid};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;
use tokio::task;
use zmq;

// Standard library imports
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::sync::Arc;

// A type alias for clarity. Maps a component name (String) to its PID (i32).
type ChildProcesses = Arc<Mutex<HashMap<String, i32>>>;

/// Launches a child process as a specific user with an optional working directory.
///
/// This is a **synchronous, blocking** function intended to be run inside `tokio::task::spawn_blocking`.
/// It forks the current process, the child drops privileges, changes its working directory,
/// and then replaces itself with the new program via `execv`.
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
        Ok(ForkResult::Parent { child }) => {
            Ok(child.into())
        }
        Ok(ForkResult::Child) => {
            // Set group first, then user.
            if let Err(e) = setgid(target_gid) {
                eprintln!("[Child] Failed to set group ID for {}: {}", program, e);
                std::process::exit(1);
            }
            if let Err(e) = setuid(target_uid) {
                eprintln!("[Child] Failed to set user ID for {}: {}", program, e);
                std::process::exit(1);
            }

            // **NEW**: Change the working directory if one is provided.
            if let Some(dir) = working_dir {
                if let Err(e) = chdir(dir) {
                    eprintln!("[Child] Failed to change working directory to '{}' for {}: {}", dir, program, e);
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
        Err(e) => {
            Err(format!("Fork failed: {}", e))
        }
    }
}

/// Sends a message to the ZMQ IPC router in a non-blocking way.
async fn nonblocking_zmq_message_sender(msg: String) {
    let result = task::spawn_blocking(move || -> Result<(), zmq::Error> {
        let context = zmq::Context::new();
        let dealer = context.socket(zmq::DEALER)?;
        dealer.set_linger(0)?;
        dealer.connect("ipc:///tmp/firewhal_ipc.sock")?;
        dealer.send(&msg, 0)?;
        Ok(())
    })
    .await;

    match result {
        Ok(Ok(())) => println!("[ZMQ] Sent status message."),
        Ok(Err(e)) => eprintln!("[ZMQ] Send error: {}", e),
        Err(e) => eprintln!("[ZMQ] Task panicked or was cancelled: {}", e),
    }
}

/// Main entry point for the daemon.
fn main() {
    let stdout = File::create("/tmp/firewhal_daemon.out").unwrap();
    let stderr = File::create("/tmp/firewhal_daemon.err").unwrap();

    let (read_fd_owned, write_fd_owned) = pipe().expect("Failed to create pipe");
    let write_fd = write_fd_owned.into_raw_fd();
    let read_fd = read_fd_owned.into_raw_fd();

    let daemonize = Daemonize::new()
        .pid_file("/var/run/firewhal_daemon.pid")
        .working_directory("/tmp")
        .user("nobody")
        .group("nobody")
        .stdout(stdout)
        .stderr(stderr)
        .privileged_action(move || {
            println!("[Privileged] Launching firewall as root...");
            let firewall_path = "/opt/firewhal/firewhal-kernel"; // Example path
            let firewall_args = &[firewall_path];

            match unsafe { fork() } {
                Ok(ForkResult::Parent { child }) => {
                    let mut writer = unsafe { File::from_raw_fd(write_fd) };
                    writer.write_all(&i32::from(child).to_ne_bytes()).unwrap();
                }
                Ok(ForkResult::Child) => {
                    let c_program = CString::new(firewall_path).unwrap();
                    let c_args: Vec<CString> =
                        firewall_args.iter().map(|&arg| CString::new(arg).unwrap()).collect();
                    let c_args_refs: Vec<&CStr> = c_args.iter().map(|c| c.as_c_str()).collect();
                    let _ = execv(&c_program, &c_args_refs);
                    std::process::exit(127);
                }
                Err(e) => {
                    eprintln!("[Privileged] Firewall fork failed: {}", e);
                }
            }
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
async fn supervisor_logic(firewall_pid_fd: i32) -> Result<(), Box<dyn std::error::Error>> {
    let children = Arc::new(Mutex::new(HashMap::new()));
    let mut children_guard = children.lock().await;

    let mut pid_buffer = [0u8; 4];
    let mut reader = unsafe { File::from_raw_fd(firewall_pid_fd) };
    reader.read_exact(&mut pid_buffer)?;
    let firewall_pid = i32::from_ne_bytes(pid_buffer);
    println!("[Supervisor] Received firewall PID {} from privileged action.", firewall_pid);
    children_guard.insert("firewall".to_string(), firewall_pid);
    drop(reader);

    // **MODIFIED**: Added a fifth element for the optional working directory.
    let apps_to_launch = vec![
        ( "ipc_router", "nobody", "/opt/firewhal/firewhal-ipc", vec!["firewhal-ipc"], None, ),
        ( "discord_bot", "nobody", "/opt/firewhal/firewhal-discord-bot", vec!["firewhal-discord-bot"], Some("/opt/firewhal"),),
    ];

    for (name, user, path, args, workdir) in apps_to_launch {
        let name_str = name.to_string();
        let user_str = user.to_string();
        let path_str = path.to_string();
        let workdir_opt = workdir.map(|d| d.to_string());
        let args_vec: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        let handle = task::spawn_blocking(move || {
            let args_cstr: Vec<&str> = args_vec.iter().map(|s| s.as_str()).collect();
            // **MODIFIED**: Pass the working directory to the launch function.
            launch_child_process(&user_str, &path_str, &args_cstr, workdir_opt.as_deref())
        });

        match handle.await? {
            Ok(pid) => {
                println!(
                    "[Supervisor] Launched '{}' as user '{}' with PID {}.",
                    name, user, pid
                );
                children_guard.insert(name_str.clone(), pid);
                tokio::spawn(nonblocking_zmq_message_sender(format!(
                    "Launched {} with PID {}",
                    name_str, pid
                )));
            }
            Err(e) => {
                eprintln!("[Supervisor] FAILED to launch '{}': {}", name, e);
                tokio::spawn(nonblocking_zmq_message_sender(format!(
                    "FAILED to launch {}",
                    name_str
                )));
            }
        }
    }
    drop(children_guard);

    let shutdown_handler = handle_shutdown_signals(Arc::clone(&children));
    let child_exit_handler = handle_child_exits(Arc::clone(&children));

    println!("[Supervisor] All components launched. Monitoring for signals...");

    tokio::select! {
        _ = child_exit_handler => eprintln!("[Supervisor] Child exit handler unexpectedly finished."),
        _ = shutdown_handler => println!("[Supervisor] Shutdown signal received. Exiting."),
    }

    Ok(())
}

/// An async task that listens for the SIGCHLD signal and cleans up zombie processes.
async fn handle_child_exits(children: ChildProcesses) {
    let mut stream = signal(SignalKind::child()).unwrap();
    loop {
        stream.recv().await;
        loop {
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(pid, status)) => {
                    let mut children_guard = children.lock().await;
                    if let Some(name) = children_guard.iter().find_map(|(name, &p)| {
                        if p == pid.into() { Some(name.clone()) } else { None }
                    }) {
                        eprintln!("[Monitor] Child '{}' (PID {}) exited with status {}.", name, pid, status);
                        tokio::spawn(nonblocking_zmq_message_sender(format!("Child {} has exited.", name)));
                        children_guard.remove(&name);
                    }
                }
                Ok(WaitStatus::StillAlive) | Ok(_) => break,
                Err(_) => break,
            }
        }
    }
}

/// An async task that listens for SIGTERM/SIGINT and gracefully shuts down children.
async fn handle_shutdown_signals(children: ChildProcesses) {
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();

    tokio::select! {
        _ = sigterm.recv() => println!("[Shutdown] Received SIGTERM."),
        _ = sigint.recv() => println!("[Shutdown] Received SIGINT."),
    };

    println!("[Shutdown] Starting graceful shutdown of child processes...");
    tokio::spawn(nonblocking_zmq_message_sender("Daemon shutting down.".to_string()));
    let children_guard = children.lock().await;
    for (name, &pid) in children_guard.iter() {
        println!("[Shutdown] Sending SIGTERM to '{}' (PID {})...", name, pid);
        let _ = signal::kill(Pid::from_raw(pid), Signal::SIGTERM);
    }
}