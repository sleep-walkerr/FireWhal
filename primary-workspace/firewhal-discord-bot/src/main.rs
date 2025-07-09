use core::time;
use std::env;

use serenity::async_trait;
use serenity::model::gateway::{GatewayIntents, Ready};
use serenity::model::Timestamp;
use serenity::model::channel::PrivateChannel; // Added for PrivateChannel type
use serenity::prelude::*;
use serenity::model::id::UserId; // For ChannelId type

use dotenvy::dotenv;
use tokio::task::{spawn_blocking, JoinHandle};
use tokio::sync::OnceCell; // Added for OnceCell


use zmq;

struct Handler;
// We will store the PrivateChannel and the ZMQ task handle in static variables
// to ensure they are initialized only once and are globally accessible.
static TARGET_CHANNEL: OnceCell<PrivateChannel> = OnceCell::const_new();
static ZMQ_TASK_HANDLE: OnceCell<JoinHandle<()>> = OnceCell::const_new();

// The ZMQ task now accepts the Serenity Context to be able to send messages.
async fn zmq_ipc_task(ctx: Context) {
    let subtask_result = spawn_blocking(move || -> Result<(), zmq::Error> {
        let context = zmq::Context::new();
        let dealer = context.socket(zmq::DEALER).unwrap();
        assert!(dealer.connect("ipc:///tmp/firewhal_ipc.sock").is_ok());

        // Send a one-time message to identify this client to the router.
        dealer.send("DISCORD_BOT_READY", 0)?;
        println!("[DEALER] Identified to router. Now listening for messages...");

        loop {
            // Block and wait for a message from the router.
            let mut msg = zmq::Message::new();
            dealer.recv(&mut msg, 0)?;
            let msg_str = msg.as_str().unwrap_or("");
            println!("[DEALER] Received from router: '{}'", msg_str);

            if msg_str == "Send Notification" {
                // To call an async function from this blocking thread,
                // we spawn it onto the Tokio runtime.
                let ctx_clone = ctx.clone();
                tokio::spawn(async move {
                    send_on_demand_dm(&ctx_clone, "Received a notification request via ZMQ!").await;
                });
            }
        }

    }).await;

    match subtask_result {
        Ok(Ok(())) => println!("ZMQ monitor broke out of loop."),
        Ok(Err(e)) => eprintln!("ZMQ monitor handleable error: {}", e),
        Err(e) => eprintln!("ZMQ panicked or was cancelled: {}", e), // JoinError
    }
}

// This function can be called from anywhere that has access to the Context.
async fn send_on_demand_dm(ctx: &Context, message_content: &str) {
    // Get the initialized channel from the static variable.
    if let Some(channel) = TARGET_CHANNEL.get() {
        // Directly use the channel as we assume single-threaded access for sending
        if let Err(why) = channel.say(&ctx.http, message_content).await {
            println!("Error sending on-demand DM: {:?}", why);
        } else {
            println!("On-demand DM sent successfully.");
        }
    }
    else {
        // This case should ideally not be hit if initialization in `ready` is successful.
        println!("Error: Target DM channel has not been initialized.");
    }
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);

        // Spawn the ZMQ IPC task, but only once.
        // `get_or_init` ensures that even if `ready` is called multiple times
        // (e.g., on reconnect), the task is only spawned on the first call.
        let ctx_clone = ctx.clone();
        ZMQ_TASK_HANDLE.get_or_init(|| async {
            println!("Spawning ZMQ IPC task...");
            tokio::spawn(zmq_ipc_task(ctx_clone))
        }).await;

        // Initialize the static TARGET_CHANNEL in the ready event.
        let user_id_str = match env::var("TARGET_USER_ID") {
            Ok(id) => id,
            Err(_) => {
                println!("TARGET_USER_ID environment variable not set. On-demand DMs will not be available.");
                return;
            }
        };

        let user_id_u64 = match user_id_str.parse::<u64>() {
            Ok(id) => id,
            Err(_) => {
                println!("Invalid TARGET_USER_ID: '{}'. Must be a valid u64. On-demand DMs will not be available.", user_id_str);
                return;
            }
        };
        let user_id = UserId::new(user_id_u64);

        match user_id.create_dm_channel(&ctx.http).await {
            Ok(private_channel) => {
                // `get_or_init` is idempotent. The async block will only be executed once.
                // On subsequent calls (e.g. on reconnect), it returns the existing value.
                TARGET_CHANNEL.get_or_init(|| async { private_channel }).await;
                println!("Successfully created/retrieved DM channel with user {}", user_id);

                // Example of sending an on-demand message right after initialization
                send_on_demand_dm(&ctx, &format!("Bot is ready and DM channel is initialized! Current time: {}", Timestamp::now())).await;
            }
            Err(why) => {
                println!("Could not create DM channel with user {}: {:?}. On-demand DMs will not be available.", user_id, why);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenv().ok(); // .ok() will ignore if .env is not found, which is fine for production

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
