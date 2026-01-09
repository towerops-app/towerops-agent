mod api_client;
mod buffer;
mod config;
mod metrics;
mod poller;
mod snmp;

use anyhow::Result;
use clap::Parser;
use poller::Scheduler;
use tracing::info;

#[derive(Parser)]
#[command(name = "towerops-agent")]
#[command(about = "Towerops remote SNMP polling agent", long_about = None)]
struct Args {
    /// API URL (e.g., https://app.towerops.com)
    #[arg(long, env = "TOWEROPS_API_URL")]
    api_url: String,

    /// Agent authentication token
    #[arg(long, env = "TOWEROPS_AGENT_TOKEN")]
    token: String,

    /// Configuration refresh interval in seconds
    #[arg(long, env = "CONFIG_REFRESH_SECONDS", default_value = "300")]
    config_refresh_seconds: u64,

    /// Database path for metrics buffering
    #[arg(long, env = "DATABASE_PATH", default_value = "/data/towerops-agent.db")]
    database_path: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    info!("Towerops agent starting");
    info!("API URL: {}", args.api_url);
    info!(
        "Config refresh interval: {} seconds",
        args.config_refresh_seconds
    );
    info!("Database path: {}", args.database_path);

    // Initialize components
    let api_client = api_client::ApiClient::new(args.api_url, args.token)?;
    let storage = buffer::Storage::new(args.database_path)?;
    let snmp_client = snmp::SnmpClient::new();

    // Create and run scheduler
    let mut scheduler = Scheduler::new(
        api_client,
        storage,
        snmp_client,
        args.config_refresh_seconds,
    );

    scheduler.run().await
}
