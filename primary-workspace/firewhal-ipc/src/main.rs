//! Hello World server in Rust
//! Binds REP socket to tcp://*:5555
//! Expects "Hello" from client, replies with "World"

use std::str;

fn main() {
    let context = zmq::Context::new();
    let router = context.socket(zmq::ROUTER).unwrap();

    // Use an IPC endpoint. The path should be a file path.
    assert!(router.bind("ipc:///tmp/firewhal_ipc.sock").is_ok());
    println!("[ROUTER] IPC router bound to ipc:///tmp/firewhal_ipc.sock");

    // We need a way to know which connected client is the Discord bot.
    // We'll store its unique ZMQ identity when it connects and tells us who it is.
    let mut discord_bot_identity: Option<Vec<u8>> = None;

    //Keep track of TUI connection
    let mut TUI_identity: Option<Vec<u8>> = None;

    loop {
        // ROUTER sockets receive multipart messages.
        // Frame 1: The identity of the sender.
        // Frame 2: The actual message payload.
        let multipart = router.recv_multipart(0).unwrap();
        let identity = multipart[0].to_vec();
        let message_data = &multipart[1];

        if let Ok(msg_str) = str::from_utf8(message_data) {
            println!("[ROUTER] Received message: '{}'", msg_str);

            // Indisciminately send messages to TUI
            if  let Some(tui_id) = &TUI_identity{
                    //Test send to TUI
                    println!("Sending to TUI");
                    router.send(tui_id, zmq::SNDMORE).unwrap();
                    router.send(msg_str,0).unwrap();
                }

            // Check for the Discord bot's one-time identification message
            if msg_str == "DISCORD_BOT_READY" {
                println!("[ROUTER] Discord bot has connected and identified itself.");
                discord_bot_identity = Some(identity);
                // We don't need to reply, just register the identity and wait for other messages.
                continue;
            }else if  msg_str == "TUI_READY" {
                TUI_identity = Some(identity);
                continue;

            }

            // Check for the trigger message from the other program
            if msg_str == "File hash changed" {
                if  let Some(tui_id) = &TUI_identity{
                    //Test send to TUI
                    println!("Sending to TUI");
                    router.send(tui_id, zmq::SNDMORE).unwrap();
                    router.send("Hash has changed",0).unwrap();
                }
                if let Some(bot_id) = &discord_bot_identity {
                    println!("[ROUTER] Trigger met. Sending notification to Discord bot.");
                    // Send a multipart message to the bot: [identity, payload]
                    router.send(bot_id, zmq::SNDMORE).unwrap();
                    router.send("Send Notification", 0).unwrap();

                } else {
                    println!("[ROUTER] Trigger met, but Discord bot is not yet identified.");
                }
            } else {
                println!("[ROUTER] Received unhandled message: '{}'", msg_str);
            }
        } else {
            println!("[ROUTER] Received a non-UTF8 message.");
        }
    }
}