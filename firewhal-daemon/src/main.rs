//! Hello World client
use sha3::{Digest, Sha3_256};
use tokio::task::spawn_blocking;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

async fn hash_file_sha3_256(file_path: &Path) -> Result<String, std::io::Error> {
    // File I/O is blocking, so we use spawn_blocking
    let file_path_owned = file_path.to_owned();
    tokio::task::spawn_blocking(move || {
        let input = File::open(&file_path_owned)?;
        let mut reader = BufReader::new(input);
        let mut hasher = Sha3_256::new();
        let mut buffer = [0; 1024];

        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        let hash_bytes = hasher.finalize();
        Ok(hex::encode(hash_bytes))
    })
    .await
    .unwrap() // Unwrap the JoinError from spawn_blocking
}


// Renamed for clarity, as this is a ZMQ REQ (client) socket.
// This function will run the ZMQ client loop.
// It's designed to be spawned as a Tokio task.
async fn run_zmq_client_loop() {
    // The actual blocking ZMQ work is offloaded to a blocking thread.
    let result = tokio::task::spawn_blocking(move || -> Result<(), zmq::Error> {
        let context = zmq::Context::new();
        let requester = context.socket(zmq::REQ).unwrap();
        assert!(requester.connect("ipc:///tmp/firewhal_ipc.sock").is_ok());
        let mut msg = zmq::Message::new();

        // This loop runs indefinitely, sending requests and receiving replies.
        loop {
            println!("Sending Hello...");
            requester.send("Hello", 0)?; // Propagate ZMQ errors

            requester.recv(&mut msg, 0)?; // Propagate ZMQ errors
            println!("Received World: {}", msg.as_str().unwrap_or("invalid UTF-8"));

            // Optional: add a delay to prevent spamming in this example loop
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        // This part is unreachable if the loop is infinite.
        // If the loop could terminate, you'd have Ok(()) here.
    })
    .await; // This outer .await is for the JoinHandle from spawn_blocking.

    // Handle the result of the blocking task execution.
    match result {
        Ok(Ok(())) => println!("ZMQ client loop completed successfully."), // Should not happen with infinite loop
        Ok(Err(e)) => eprintln!("ZMQ client loop operation error: {}", e),
        Err(e) => eprintln!("ZMQ client loop task panicked or was cancelled: {}", e), // JoinError
    }
}

#[tokio::main]
async fn main() {
    // Example: Hash a dummy file
    // Using a local path for the dummy file to avoid permission issues with /var/log/ during dev.
    // You can change this path if your daemon has appropriate permissions for other files.
    let test_file_to_hash = Path::new("example_daemon_hash_input.txt");
    // Create a dummy file for testing (in a real app, the file would exist)
    std::fs::write(test_file_to_hash, "Daemon test data for hashing.").expect("Failed to create dummy file for hashing");

    match hash_file_sha3_256(test_file_to_hash).await {
        Ok(hash_hex) => {
            println!("SHA3-256 hash of '{}': {}", test_file_to_hash.display(), hash_hex);
        }
        Err(e) => {
            eprintln!("Error hashing file: {}", e);
        }
    }
    // std::fs::remove_file(test_file_to_hash).ok(); // Clean up dummy file

    println!("\nStarting ZMQ client loop...\n");

    // Spawn the ZMQ client loop to run concurrently.
    let zmq_client_handle = tokio::spawn(run_zmq_client_loop());

    // The main function will now wait for the ZMQ client task to complete.
    // If run_zmq_client_loop has an infinite loop, main will also run indefinitely here.
    println!("ZMQ client loop task spawned. Main thread will now wait (Press Ctrl+C to exit).");
    if let Err(e) = zmq_client_handle.await {
        eprintln!("ZMQ client task failed: {:?}", e);
    } else {
        println!("ZMQ client task completed."); // This would only be reached if the loop terminates.
    }
}
