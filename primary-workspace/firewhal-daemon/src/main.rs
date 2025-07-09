//! Hello World client

// Crate imports
use hex;
use sha3::{digest::Output, Digest, Sha3_256};
use tokio::{
    task::spawn_blocking,
    time::{sleep, Duration},
};
use zmq;

// Standard library imports
use std::{
    fs::{self, File}, // For File and fs::write
    io::{BufReader, Read},
    path::{Path, PathBuf},
};

// Helper function to perform the blocking file read and hash calculation.
fn calculate_hash_for_file(file_path: &Path) -> Result<Output<Sha3_256>, std::io::Error> {
    let input = File::open(file_path)?;
    let mut reader = BufReader::new(input);
    let mut hasher = Sha3_256::new();
    let mut buffer = [0; 1024]; // Standard buffer size for reading

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break; // End of file
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize())
}

/// Periodically checks the hash of the specified file and prints a message if it changes.
/// This function spawns a Tokio task that runs indefinitely.
async fn periodic_hash_checker(file_to_watch: PathBuf, check_interval: Duration) {
    println!(
        "Starting periodic hash checker for '{}' with interval {:?}",
        file_to_watch.display(),
        check_interval
    );

    // This async function will now directly contain the loop,
    // making it the long-running operation that the caller can await.
    let mut previous_hash_opt: Option<Output<Sha3_256>> = None;

    loop {
        // Clone file_path for use in the blocking task. PathBuf cloning is cheap.
        let file_path_clone = file_to_watch.clone();

        // Offload the blocking file I/O and hashing to a blocking thread.
        let hash_result = spawn_blocking(move || {
            calculate_hash_for_file(&file_path_clone)
        }).await;

        match hash_result {
            Ok(Ok(current_hash)) => { // Successfully joined and hash calculated
                match previous_hash_opt.as_ref() {
                    Some(prev_hash) => {
                        if *prev_hash != current_hash {
                            println!("File '{}' hash changed.", file_to_watch.display());
                            // Spawn ZMQ sender as a fire-and-forget task.
                            // If sending the message is critical and should block the checker,
                            // you might await it and handle its result.
                            tokio::spawn(nonblocking_zmq_message_sender(
                                "File hash changed".to_string(),
                            ));
                            previous_hash_opt = Some(current_hash);
                        }
                    }
                    None => {
                        println!("Initial hash for {}: {}", file_to_watch.display(), hex::encode(&current_hash));
                        previous_hash_opt = Some(current_hash);
                    }
                }
            }
            Ok(Err(io_error)) => { // Successfully joined, but hashing failed with I/O error
                eprintln!("Error calculating hash for {}: {}. Will retry.", file_to_watch.display(), io_error);
            }
            Err(join_error) => { // The blocking task panicked
                eprintln!("Hashing task panicked for {}: {}. Will retry.", file_to_watch.display(), join_error);
            }
        }
        // Wait for the specified interval before the next check.
        sleep(check_interval).await;
    }
    // This part is unreachable due to the infinite loop.
}

// Renamed for clarity, as this is a ZMQ REQ (client) socket.
// This function will run the ZMQ client loop.
// It's designed to be spawned as a Tokio task.
async fn nonblocking_zmq_message_sender(msg: String) {
    // The actual blocking ZMQ work is offloaded to a blocking thread.
    let result = spawn_blocking(move || -> Result<(), zmq::Error> {
        let context = zmq::Context::new();
        // Use a DEALER socket to talk to a ROUTER. REQ sockets are for REP sockets.
        let dealer = context.socket(zmq::DEALER).unwrap();
        assert!(dealer.connect("ipc:///tmp/firewhal_ipc.sock").is_ok());

        // It's good practice to give the connection a moment to establish,
        // especially for a fire-and-forget message.
        sleep(Duration::from_millis(50));

        dealer.send(&msg, 0)?; // Propagate ZMQ errors
        Ok(()) // Explicitly return Ok on success
    })
    .await; // This outer .await is for the JoinHandle from spawn_blocking.

    // Handle the result of the blocking task execution.
    match result {
        Ok(Ok(())) => println!("ZMQ message sent successfully."),
        Ok(Err(e)) => eprintln!("ZMQ send error: {}", e),
        Err(e) => eprintln!("ZMQ panicked or was cancelled: {}", e), // JoinError
    }
}




#[tokio::main]
async fn main() {
    // Example: Hash a dummy file
    // Using a local path for the dummy file to avoid permission issues with /var/log/ during dev.
    // You can change this path if your daemon has appropriate permissions for other files.
    let file_to_watch = PathBuf::from("example_daemon_hash_input.txt");
    // Create a dummy file for testing (in a real app, the file would exist)
    if !file_to_watch.exists() {
        fs::write(&file_to_watch, "Initial daemon test data for hashing.").expect("Failed to create dummy file for hashing"); // Use imported `fs`
    }

    // Define the interval for hash checks
    let check_interval = Duration::from_secs(5);

    // Spawn the periodic hash checker task.
    // It will run in the background.
    // The `periodic_hash_checker` function itself returns immediately after spawning the task.
    let checker_handle = tokio::spawn(periodic_hash_checker(file_to_watch.clone(), check_interval));

    // Optional: Clean up the dummy file on exit, though for a daemon this might not be typical.
    // std::fs::remove_file(file_to_watch).ok();

    // Await the checker_handle. Since periodic_hash_checker now contains an infinite loop,
    // this will keep main alive indefinitely, allowing the checker to run.
    // If periodic_hash_checker somehow exits (e.g., due to an unhandled panic not caught by its own error handling),
    // the error would be propagated here.
    if let Err(e) = checker_handle.await {
        eprintln!("Periodic hash checker task exited with an error: {:?}", e);
    }
}
