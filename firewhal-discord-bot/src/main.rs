use std::env;
use std::sync::Arc;
use serenity::async_trait;
use serenity::model::gateway::{GatewayIntents, Ready};
use serenity::model::id::UserId;
use serenity::prelude::*;
use serenity::http::Http;
use dotenvy::dotenv;
use tokio::net::unix::pipe::Sender;
use tokio::sync::{mpsc, Mutex, oneshot, broadcast};

// Import the necessary items from your shared core library
use firewhal_core::{zmq_client_connection, DebugMessage, FireWhalMessage, StatusPong, StatusUpdate, DiscordBlockNotification};

struct Handler;

struct ZmqTxKey;

impl TypeMapKey for ZmqTxKey {
    type Value = Arc<Mutex<mpsc::Sender<FireWhalMessage>>>;
}



/// This task handles incoming messages from the IPC router.
async fn message_handler(to_zmq_tx: Arc<Mutex<mpsc::Sender<FireWhalMessage>>>, mut from_zmq_rx: mpsc::Receiver<FireWhalMessage>, http: Arc<Http>) {
    // This loop waits for messages from the zmq_client_connection task.
    while let Some(message) = from_zmq_rx.recv().await {

        // Match on the message type to decide what to do.
        match message {
            // For example, forward any Debug messages to the Discord user.
            FireWhalMessage::Debug(DebugMessage { source, content }) => {
                let discord_msg = format!("**[Debug: {}]**\n```\n{}\n```", source, content);
                send_dm_to_target(&http, &discord_msg).await;
            }
            FireWhalMessage::Ping(_) => {
                let zmq_tx_guard = to_zmq_tx.lock().await;
                let pong_message = FireWhalMessage::Pong(StatusPong {
                    source: "DiscordBot".to_string(),
                });
                if let Err(e) = zmq_tx_guard.send(pong_message).await {
                    eprintln!("[DiscordBot IPC] Failed to send Pong message to router: {}", e);
                } else {
                    println!("[DiscordBot IPC] Successfully sent Pong message to router.");
                }
            }
            FireWhalMessage::DiscordBlockNotify(notification) => {
                send_dm_to_target(&http, format!("[{}]: {}", notification.component, notification.content).as_str()).await;
            }
            _ => {
                // Ignore other message types for now.
            }
        }
    }
}

/// Helper function to send a direct message to the configured target user.
async fn send_dm_to_target(http: &Http, message: &str) {
    let user_id_str = match env::var("TARGET_USER_ID") {
        Ok(id) => id,
        Err(_) => return, // Don't try to send if the ID isn't configured
    };
    let user_id_u64 = match user_id_str.parse::<u64>() {
        Ok(id) => id,
        Err(_) => return,
    };
    
    let user_id = UserId::new(user_id_u64);
    if let Ok(private_channel) = user_id.create_dm_channel(&http).await {
        if let Err(why) = private_channel.say(&http, message).await {
            eprintln!("[Discord] Error sending DM: {:?}", why);
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        println!("[Discord] {} is connected!", ready.user.name);

        // --- Retrieve the sender from the shared context ---
        let data = ctx.data.read().await;
        // .get returns an Option, but we can .unwrap() because we *know* we inserted it at startup.
        let to_zmq_tx = data.get::<ZmqTxKey>().unwrap().clone();
        // lock zmq_sender
        let mut zmq_sender_guard = to_zmq_tx.lock().await;


        // --- Identification ---
        let ident_msg = FireWhalMessage::Status(StatusUpdate {
            component: "DiscordBot".to_string(),
            is_healthy: true,
            message: "Ready".to_string(),
        });

        if let Err(e) = zmq_sender_guard.send(ident_msg).await {
            eprintln!("[DiscordBot IPC] Failed to send Ready message to router: {}", e);
        } else {
            println!("[DiscordBot IPC] Successfully identified to router as 'DiscordBot'.");
        }

        // Send a startup DM to the target user.
        send_dm_to_target(&ctx.http.clone(), "✅ Discord Bot is online and connected to the IPC router.").await;
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Create the channels required by the unified IPC function.
    let (to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(128);
    let (from_zmq_tx, from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

    // Create a sharable reference to our zmq_sender
    let zmq_sender = Arc::new(Mutex::new(to_zmq_tx));

    // Spawn the unified ZMQ connection task.
    tokio::spawn(zmq_client_connection(to_zmq_rx, from_zmq_tx, shutdown_rx, "DiscordBot".to_string()));

    

    let token = env::var("DISCORD_TOKEN").expect("Expected a token in the environment");
    let intents = GatewayIntents::GUILDS | GatewayIntents::DIRECT_MESSAGES;
    let mut client =
        Client::builder(&token, intents).event_handler(Handler).await.expect("Err creating client");

    {
        let mut data = client.data.write().await;
        data.insert::<ZmqTxKey>(zmq_sender.clone());
        // We'll also store the shutdown sender if we need to trigger a shutdown later.
        // For now, let's focus on the message sender.
    }
    // Spawn our new message handler task.
    tokio::spawn(message_handler(zmq_sender.clone(), from_zmq_rx, client.http.clone()));

    if let Err(why) = client.start().await {
        println!("Client error: {why:?}");
    }

    
}