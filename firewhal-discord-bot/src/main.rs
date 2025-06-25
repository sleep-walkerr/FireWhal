use core::time;
use std::env;
use std::time::Duration;
use std::thread::sleep;

use serenity::async_trait;
use serenity::model::gateway::{GatewayIntents, Ready};
use serenity::model::Timestamp;
use serenity::prelude::*;
use serenity::model::id::UserId; // For ChannelId type

use dotenvy::dotenv;
use tokio::task::spawn_blocking;
use tokio::time::interval; // For the timer


use zmq;

struct Handler;

async fn zmq_ipc_task() {
    let subtask_result = spawn_blocking(move || -> Result<(), zmq::Error> {
        let context = zmq::Context::new();
        let requester = context.socket(zmq::REQ).unwrap();
        assert!(requester.connect("ipc:///tmp/firewhal_ipc.sock").is_ok());
        
        loop{
            println!("[ZMQ REQ] Sending request: data");
            requester.send("data", 0)?;
            
            // Wait for the reply
            let mut msg = zmq::Message::new();
            requester.recv(&mut msg, 0)?;
            println!("[ZMQ REQ] Received reply: {}", msg.as_str().unwrap_or("<invalid UTF-8>"));
            sleep(time::Duration::from_secs(3));
        }
        
    }).await;
    
    match subtask_result {
        Ok(Ok(())) => println!("ZMQ monitor broke out of loop."),
        Ok(Err(e)) => eprintln!("ZMQ monitor handleable error: {}", e),
        Err(e) => eprintln!("ZMQ panicked or was cancelled: {}", e), // JoinError
    }
}

async fn periodic_message_sender(ctx: Context) {
    // 1. Get TARGET_USER_ID from environment
    let user_id_str = match env::var("TARGET_USER_ID") {
        Ok(id) => id,
        Err(_) => {
            println!("TARGET_USER_ID environment variable not set. Periodic DMs will not be sent.");
            return;
        }
    };

    // 2. Parse User ID string to u64
    let user_id_u64 = match user_id_str.parse::<u64>() {
        Ok(id) => id,
        Err(_) => {
            println!("Invalid TARGET_USER_ID: '{}'. Must be a valid u64. Periodic DMs will not be sent.", user_id_str);
            return;
        }
    };
    let user_id = UserId::new(user_id_u64);

    // 3. Try to create a DM channel with the user
    match user_id.create_dm_channel(&ctx.http).await {
        Ok(private_channel) => {
            println!("Successfully created/retrieved DM channel with user {}", user_id);
            let mut timer = interval(Duration::from_secs(10)); // Send message every 10 seconds
            loop {
                timer.tick().await;
                let message_content = format!("This is an automated message from FireWhal! Current time: {}", Timestamp::now());
                if let Err(why) = private_channel.say(&ctx.http, &message_content).await {
                    println!("Error sending periodic DM to user {}: {:?}", user_id, why);
                } else {
                    println!("Periodic DM sent to user {}.", user_id);
                }
            }
        }
        Err(why) => {
            println!("Could not create DM channel with user {}: {:?}. Periodic DMs will not be sent.", user_id, why);
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
        tokio::spawn(periodic_message_sender(ctx.clone())); // ctx.clone() is important here
    }
}

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenv().ok(); // .ok() will ignore if .env is not found, which is fine for production
    tokio::spawn(zmq_ipc_task());


    // Configure the client with your Discord bot token in the environment.
    let token = env::var("DISCORD_TOKEN").expect("Expected a token in the environment");
    let intents = GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::DIRECT_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT
        | GatewayIntents::GUILDS; // Crucial for fetching guild and channel information
    let mut client =
        Client::builder(&token, intents).event_handler(Handler).await.expect("Err creating client");



    if let Err(why) = client.start().await {
        println!("Client error: {why:?}");
    }
}
