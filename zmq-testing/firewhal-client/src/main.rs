
use tokio::net::unix::pipe::Sender;
use tokio::sync::{mpsc, Mutex, oneshot, broadcast};
use firewhal_core::{FireWhalMessage, zmq_client_connection, StatusUpdate};
use std::sync::Arc;

#[tokio::main]
async fn main() {


    // Create the channels required by the unified IPC function.
    let (to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(128);
    let (from_zmq_tx, mut from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

    // Create a sharable reference to our zmq_sender
    let zmq_sender = Arc::new(Mutex::new(to_zmq_tx.clone()));

    // Spawn the unified ZMQ connection task.
    tokio::spawn(zmq_client_connection(to_zmq_rx, from_zmq_tx, shutdown_rx, "DiscordBot".to_string()));

    let registration_message = FireWhalMessage::Status(StatusUpdate { component: "Client Test".to_string(), is_healthy: true, message: "Ready".to_string() });
    to_zmq_tx.clone().send(registration_message).await.unwrap();

    loop {
        tokio::select! {
            Some(message) = from_zmq_rx.recv() => {
                println!("Message received!");
            }
        }
    }

}