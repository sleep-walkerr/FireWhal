use std::env;
use std::time::Duration;

use serenity::async_trait;
use serenity::model::gateway::{GatewayIntents, Ready};
use serenity::model::Timestamp;
use serenity::prelude::*;
use serenity::model::id::ChannelId; // For ChannelId type

use dotenvy::dotenv;
use tokio::time::interval; // For the timer

struct Handler;

async fn periodic_message_sender(ctx: Context) {
    let mut general_channel_id: Option<ChannelId> = None;

    // Iterate over the guilds the bot is in to find a "general" channel
    // We need to ensure the bot has GUILDS intent for this to work.
    if ctx.cache.guilds().is_empty() {
        println!("Bot is not in any guilds or GUILDS intent might be missing/cache not ready.");
    }

    for guild_id in ctx.cache.guilds() {
        match guild_id.channels(&ctx.http).await {
            Ok(channels) => {
                for (channel_id, guild_channel) in channels {
                    if guild_channel.name.to_lowercase() == "general" {
                        general_channel_id = Some(channel_id);
                        println!("Found 'general' channel: {} in guild {}", channel_id, guild_id);
                        break; // Found "general" channel in this guild
                    }
                }
            }
            Err(why) => {
                println!("Could not fetch channels for guild {}: {:?}", guild_id, why);
                continue; // Skip to the next guild
            }
        }
        if general_channel_id.is_some() {
            break; // Found "general" channel, no need to check other guilds
        }
    }

    if let Some(channel_id) = general_channel_id {
        let mut timer = interval(Duration::from_secs(10));
        loop {
            timer.tick().await;
            let message_content = format!("This is an automated message from FireWhal! Current time: {}", Timestamp::now());
            if let Err(why) = channel_id.say(&ctx.http, &message_content).await {
                println!("Error sending periodic message to channel {}: {:?}", channel_id, why);
            } else {
                println!("Periodic message sent to channel {}.", channel_id);
            }
        }
    } else {
        println!("Could not find a 'general' channel. Periodic messages will not be sent.");
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
