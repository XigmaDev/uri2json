mod utils;

use chrono::Local;
use commands::Command;
use singbox::config;
use teloxide::{prelude::*, types::InputFile, utils::command::BotCommands};

mod commands {
    // teloxide-macros 0.8 parses `String` arguments with
    // `from_str(s).map_err(|e| e.into())`. `String`'s parse error is
    // `Infallible`, which newer rustc reports as an unreachable call in the
    // generated code. The allow is scoped to this module so it only covers
    // the derive output.
    #![allow(unreachable_code)]

    use teloxide::utils::command::BotCommands;

    #[derive(BotCommands, Clone)]
    #[command(rename_rule = "lowercase")]
    #[command(description = "Commands:")]
    pub enum Command {
        #[command(description = "Start")]
        Start,
        #[command(description = "Help")]
        Help,
        #[command(description = "Process singbox URI - /singbox <version> <URI>")]
        Singbox(String),
        #[command(description = "Xray Coming Soon")]
        Xray,
    }
}

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    pretty_env_logger::init();
    log::info!("Starting Uri2Json bot...");

    let bot = Bot::from_env();
    if let Err(e) = bot.set_my_commands(Command::bot_commands()).await {
        log::warn!("Failed to set bot commands: {}", e);
    }

    let handler = Update::filter_message()
        .filter_command::<Command>()
        .endpoint(schema);

    Dispatcher::builder(bot, handler)
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;
}

async fn schema(bot: Bot, msg: Message, cmd: Command) -> HandlerResult {
    match cmd {
        Command::Singbox(args) => handle_singbox(&bot, &msg, &args).await?,
        Command::Start => {
            bot.send_message(msg.chat.id, utils::welcome_message())
                .await?;
        }
        Command::Help => {
            bot.send_message(msg.chat.id, utils::help_message()).await?;
        }
        Command::Xray => {
            bot.send_message(msg.chat.id, "🚧 Xray support is coming soon. Stay tuned!")
                .await?;
        }
    }
    Ok(())
}

async fn handle_singbox(bot: &Bot, msg: &Message, args: &str) -> HandlerResult {
    let mut parts = args.split_whitespace();
    let (Some(version), Some(uri)) = (parts.next(), parts.next()) else {
        bot.send_message(
            msg.chat.id,
            format!(
                "Invalid format. Use /singbox <version> <URI>\nSupported versions: {}",
                utils::supported_versions_text()
            ),
        )
        .await?;
        return Ok(());
    };

    let Some(version) = utils::normalize_version(version) else {
        bot.send_message(
            msg.chat.id,
            format!(
                "Unsupported version. Currently supported: {}",
                utils::supported_versions_text()
            ),
        )
        .await?;
        return Ok(());
    };

    match config::generate(&version, uri) {
        Ok(json) => {
            let filename = format!(
                "singbox_{}_{}.json",
                version,
                Local::now().format("%Y%m%d_%H%M%S")
            );
            let file = InputFile::memory(json.into_bytes()).file_name(filename);
            bot.send_document(msg.chat.id, file).await?;
        }
        Err(e) => {
            log::debug!("Conversion failed: {}", e);
            bot.send_message(msg.chat.id, format!("❌ Error processing URI: {}", e))
                .await?;
        }
    }
    Ok(())
}
