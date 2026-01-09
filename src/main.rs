mod api_client;
mod buffer;
mod config;
mod metrics;
mod poller;
mod snmp;

use clap::Parser;
use log::info;
use poller::Scheduler;

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
async fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    info!("Towerops agent starting");
    info!("API URL: {}", args.api_url);
    info!(
        "Config refresh interval: {} seconds",
        args.config_refresh_seconds
    );
    info!("Database path: {}", args.database_path);

    // Initialize components
    let api_client = match api_client::ApiClient::new(args.api_url, args.token) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to create API client: {}", e);
            std::process::exit(1);
        }
    };

    let storage = match buffer::Storage::new(args.database_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create storage: {}", e);
            std::process::exit(1);
        }
    };

    let snmp_client = snmp::SnmpClient::new();

    // Create and run scheduler
    let mut scheduler = Scheduler::new(
        api_client,
        storage,
        snmp_client,
        args.config_refresh_seconds,
    );

    if let Err(e) = scheduler.run().await {
        eprintln!("Scheduler error: {}", e);
        std::process::exit(1);
    }
}
