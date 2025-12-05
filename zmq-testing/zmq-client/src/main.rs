use zeromq::{Socket, SocketRecv, SocketSend, ZmqMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut socket = zeromq::DealerSocket::new();

    let client_id = "Client-IPC-1";

    let endpoint = "ipc:///tmp/firewhal_ipc.sock";
    socket.connect(endpoint).await?;
    println!("{} connected via IPC.", client_id);

    // 1. Send message
    // ZmqMessage::from("string") creates a message with one frame containing the string
    let msg = ZmqMessage::from("Hello via Unix Sockets!");
    socket.send(msg).await?;

    // 2. Receive reply
    let repl = socket.recv().await?;
    
    // 3. Extract payload
    let mut frames = repl.into_vecdeque();
    
    // DEALER receives only the payload (Router stripped the identity)
    if let Some(payload) = frames.pop_front() {
        println!("Received: {:?}", std::str::from_utf8(&payload)?);
    }

    Ok(())
}