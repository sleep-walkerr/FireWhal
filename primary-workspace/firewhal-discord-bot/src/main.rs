use std::env;
use std::sync::Arc;
use serenity::async_trait;
use serenity::model::gateway::{GatewayIntents, Ready};
use serenity::model::id::UserId;
use serenity::prelude::*;
use dotenvy::dotenv;
use tokio::sync::{mpsc, Mutex, oneshot, broadcast};

// Import the necessary items from your shared core library
use firewhal_core::{zmq_client_connection, DebugMessage, FireWhalMessage, StatusUpdate};

struct Handler;

/// This task handles incoming messages from the IPC router.
async fn message_handler(mut from_zmq_rx: mpsc::Receiver<FireWhalMessage>, ctx: Context) {
    println!("[Handler] Message handler task started.");
    // This loop waits for messages from the zmq_client_connection task.
    while let Some(message) = from_zmq_rx.recv().await {
        println!("[Handler] Received message: {:?}", message);

        // Match on the message type to decide what to do.
        match message {
            // For example, forward any Debug messages to the Discord user.
            FireWhalMessage::Debug(DebugMessage { source, content }) => {
                let discord_msg = format!("**[Debug: {}]**\n```\n{}\n```", source, content);
                send_dm_to_target(&ctx, &discord_msg).await;
            }
            // You can add other arms here to handle different message types.
            _ => {
                // Ignore other message types for now.
            }
        }
    }
}

/// Helper function to send a direct message to the configured target user.
async fn send_dm_to_target(ctx: &Context, message: &str) {
    let user_id_str = match env::var("TARGET_USER_ID") {
        Ok(id) => id,
        Err(_) => return, // Don't try to send if the ID isn't configured
    };
    let user_id_u64 = match user_id_str.parse::<u64>() {
        Ok(id) => id,
        Err(_) => return,
    };
    
    let user_id = UserId::new(user_id_u64);
    if let Ok(private_channel) = user_id.create_dm_channel(&ctx.http).await {
        if let Err(why) = private_channel.say(&ctx.http, message).await {
            eprintln!("[Discord] Error sending DM: {:?}", why);
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        println!("[Discord] {} is connected!", ready.user.name);



    
        // --- NEW IPC SETUP ---
        // Create the channels required by the unified IPC function.
        let (to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(128);
        let (from_zmq_tx, from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

        // Spawn the unified ZMQ connection task.
        tokio::spawn(zmq_client_connection(to_zmq_rx, from_zmq_tx, shutdown_rx));

        // Spawn our new message handler task.
        tokio::spawn(message_handler(from_zmq_rx, ctx.clone()));

        //tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

        // --- Identification ---
        // Send a "Ready" status message to the router to identify this component.
        let ident_msg = FireWhalMessage::Status(StatusUpdate {
            component: "DiscordBot".to_string(),
            is_healthy: true,
            message: "Ready".to_string(),
        });

        if let Err(e) = to_zmq_tx.send(ident_msg).await {
            eprintln!("[IPC] Failed to send Ready message to router: {}", e);
        } else {
            println!("[IPC] Successfully identified to router as 'DiscordBot'.");
        }


        // You can now use `to_zmq_tx` anywhere else you need to send messages
        // from the bot to other components.

        // Send a startup DM to the target user.
        send_dm_to_target(&ctx, "✅ Discord Bot is online and connected to the IPC router.").await;
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let token = env::var("DISCORD_TOKEN").expect("Expected a token in the environment");
    let intents = GatewayIntents::GUILDS | GatewayIntents::DIRECT_MESSAGES;
    let mut client =
        Client::builder(&token, intents).event_handler(Handler).await.expect("Err creating client");

    if let Err(why) = client.start().await {
        println!("Client error: {why:?}");
    }
}