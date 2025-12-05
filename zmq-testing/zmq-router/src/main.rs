use zeromq::{Socket, SocketRecv, SocketSend, ZmqMessage};
use bytes::Bytes; // Essential for handling frames

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut socket = zeromq::RouterSocket::new();
    let endpoint = "ipc:///tmp/zeromq-demo.sock";
    
    socket.bind(endpoint).await?;
    println!("Server (ROUTER) listening on {}", endpoint);

    loop {
        let message = socket.recv().await?;

        // 1. Read: Use into_vecdeque() to consume the message and get the frames
        // We use this because calling methods directly on 'message' can be restrictive
        let mut frames = message.into_vecdeque();

        // 2. Extract Frames safely
        // The first frame is the Identity (needed to route the reply)
        // The second frame is the content
        if let (Some(identity), Some(content)) = (frames.pop_front(), frames.pop_front()) {
            let content_str = std::str::from_utf8(&content).unwrap_or("<invalid utf8>");
            println!("Server received: {}", content_str);

            // 3. Write: Construct the Reply Manually
            // create a fresh, empty message
            let mut response: ZmqMessage = ZmqMessage::from(identity);
            
            // Push the payload second
            let reply_text = format!("Ack: {}", content_str);
            response.push_back(Bytes::from(reply_text));

            socket.send(response).await?;
        }
    }
}