use std::env;

use serenity::async_trait;
use serenity::builder::{CreateAttachment, CreateEmbed, CreateEmbedFooter, CreateMessage};
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::model::Timestamp;
use serenity::prelude::*;

use dotenvy::dotenv;
struct Handler;

#[async_trait]
impl EventHandler for Handler {
    async fn message(&self, ctx: Context, msg: Message) {
        // 1. Log every message received to see if the handler is triggered
        println!(
            "Message received: Author='{}', Content='{}', Channel='{}'",
            msg.author.name, msg.content, msg.channel_id
        );

        if msg.author.bot { // Optional: ignore messages from other bots (and self)
            // println!("Ignoring message from bot: {}", msg.author.name);
            return;
        }

        if msg.content == "!hello" {
            println!("'!hello' command detected. Preparing response..."); // 2. Log command detection

            // 3. Robust file handling (example)
            let attachment_result = CreateAttachment::path("./ferris_eyes.png").await;
            let attachment_path_for_embed = "attachment://ferris_eyes.png"; // Keep this consistent with filename

            match attachment_result {
                Ok(attachment_file) => {
                    println!("Successfully prepared attachment: ferris_eyes.png");
                    let footer = CreateEmbedFooter::new("This is a footer");
                    let embed = CreateEmbed::new()
                        .title("This is a title")
                        .description("This is a description")
                        .image(attachment_path_for_embed) // Use the constant string here
                        .fields(vec![
                            ("This is the first field", "This is a field body", true),
                            ("This is the second field", "Both fields are inline", true),
                        ])
                        .field("This is the third field", "This is not an inline field", false)
                        .footer(footer)
                        .timestamp(Timestamp::now());

                    let builder = CreateMessage::new()
                        .content("Hello, World!")
                        .embed(embed)
                        .add_file(attachment_file); // Use the Ok result

                    println!("Attempting to send message with embed and attachment...");
                    if let Err(why) = msg.channel_id.send_message(&ctx.http, builder).await {
                        println!("Error sending message: {why:?}"); // 4. This will now catch send errors
                    } else {
                        println!("Message sent successfully!");
                    }
                }
                Err(e) => {
                    println!("Failed to create attachment: {e:?}. Sending message without attachment.");
                    // Optionally, send a message without the attachment if it fails
                    let footer = CreateEmbedFooter::new("This is a footer (no image)");
                    let embed = CreateEmbed::new()
                        .title("This is a title (Image Failed)")
                        .description("This is a description")
                        // .image("attachment://ferris_eyes.png") // Omit if file failed
                        .fields(vec![
                            ("This is the first field", "This is a field body", true),
                            ("This is the second field", "Both fields are inline", true),
                        ])
                        .field("This is the third field", "This is not an inline field", false)
                        .footer(footer)
                        .timestamp(Timestamp::now());
                    let builder = CreateMessage::new()
                        .content("Hello, World! (Image attachment failed)")
                        .embed(embed);
                     if let Err(why) = msg.channel_id.send_message(&ctx.http, builder).await {
                        println!("Error sending fallback message: {why:?}");
                     } else {
                        println!("Fallback message sent successfully!");
                     }
                }
            }
        }
    }

    async fn ready(&self, _: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
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
        | GatewayIntents::MESSAGE_CONTENT;
    let mut client =
        Client::builder(&token, intents).event_handler(Handler).await.expect("Err creating client");

    if let Err(why) = client.start().await {
        println!("Client error: {why:?}");
    }
}
