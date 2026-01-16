mod health;
mod proto;
mod snmp;
mod version;
mod websocket_client;

use chrono::Local;
use clap::Parser;
use log::{info, warn, LevelFilter, Metadata, Record};
use std::env;
use websocket_client::AgentClient;

/// Minimal logger that writes to stderr with timestamps
struct SimpleLogger {
    level: LevelFilter,
}

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            eprintln!("[{}] [{}] {}", timestamp, record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

fn init_logger() {
    let level = env::var("RUST_LOG")
        .unwrap_or_else(|_| "info".to_string())
        .parse::<LevelFilter>()
        .unwrap_or(LevelFilter::Info);

    let logger = SimpleLogger { level };
    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(level))
        .ok();
}

#[derive(Parser)]
#[command(name = "towerops-agent")]
#[command(about = "Towerops remote SNMP polling agent", long_about = None)]
struct Args {
    /// API URL (e.g., wss://app.towerops.com or https://app.towerops.com)
    #[arg(long, env = "TOWEROPS_API_URL")]
    api_url: String,

    /// Agent authentication token
    #[arg(long, env = "TOWEROPS_AGENT_TOKEN")]
    token: String,
}

#[tokio::main]
async fn main() {
    // Initialize logging
    init_logger();

    let args = Args::parse();

    info!("Towerops agent starting");

    // Check for newer Docker image version
    version::check_for_updates();

    // Convert HTTP(S) URL to WebSocket URL
    let ws_url = if args.api_url.starts_with("http://") {
        args.api_url.replace("http://", "ws://")
    } else if args.api_url.starts_with("https://") {
        args.api_url.replace("https://", "wss://")
    } else if args.api_url.starts_with("ws://") || args.api_url.starts_with("wss://") {
        args.api_url.clone()
    } else {
        // Default to wss:// for bare domains
        format!("wss://{}", args.api_url)
    };

    info!("WebSocket URL: {}", ws_url);

    // Start simple health endpoint (no storage needed for WebSocket mode)
    tokio::spawn(async {
        if let Err(e) = health::start_health_server(8080).await {
            warn!("Health server error: {}", e);
        }
    });

    // Connect to Towerops server via WebSocket
    let mut client = match AgentClient::connect(&ws_url, &args.token).await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to server: {}", e);
            std::process::exit(1);
        }
    };

    // Run the agent event loop
    if let Err(e) = client.run().await {
        eprintln!("Agent error: {}", e);
        std::process::exit(1);
    }

    info!("Agent shutting down");
}
