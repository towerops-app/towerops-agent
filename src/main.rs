mod proto;
mod snmp;
mod version;
mod websocket_client;

use clap::Parser;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing_subscriber::EnvFilter;
use websocket_client::AgentClient;

fn init_logger() {
    // Use LOG_LEVEL env var (fall back to RUST_LOG for backwards compatibility)
    let filter = env::var("LOG_LEVEL")
        .or_else(|_| env::var("RUST_LOG"))
        .unwrap_or_else(|_| "info".to_string());

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&filter))
        .with_target(false)
        .init();
}

/// Convert HTTP(S) URL to WebSocket URL
fn convert_to_websocket_url(url: &str) -> String {
    if url.starts_with("http://") {
        url.replace("http://", "ws://")
    } else if url.starts_with("https://") {
        url.replace("https://", "wss://")
    } else if url.starts_with("ws://") || url.starts_with("wss://") {
        url.to_string()
    } else {
        // Default to wss:// for bare domains
        format!("wss://{}", url)
    }
}

#[derive(Parser)]
#[command(name = "towerops-agent")]
#[command(about = "Towerops remote SNMP polling agent", long_about = None)]
struct Args {
    /// API URL (e.g., wss://towerops.net or https://towerops.net)
    #[arg(long, env = "TOWEROPS_API_URL")]
    api_url: String,

    /// Agent authentication token
    #[arg(long, env = "TOWEROPS_AGENT_TOKEN")]
    token: String,

    /// UDP port for SNMP trap listener
    #[arg(long, env = "TRAP_PORT", default_value_t = snmp::DEFAULT_TRAP_PORT)]
    trap_port: u16,

    /// Enable SNMP trap listener
    #[arg(long, env = "TRAP_ENABLED", default_value_t = false)]
    trap_enabled: bool,
}

#[tokio::main]
async fn main() {
    // Initialize logging
    init_logger();

    let args = Args::parse();

    tracing::info!("Towerops agent starting");

    // Check for newer Docker image version
    version::check_for_updates();

    // Start SNMP trap listener if enabled
    if args.trap_enabled {
        let trap_port = args.trap_port;
        tokio::spawn(async move {
            let (trap_tx, mut trap_rx) = tokio::sync::mpsc::channel::<snmp::SnmpTrap>(100);
            let trap_listener = snmp::TrapListener::new(trap_port);

            // Spawn the listener
            tokio::spawn(async move {
                trap_listener.run(trap_tx).await;
            });

            // Log received traps
            while let Some(trap) = trap_rx.recv().await {
                tracing::info!("{}", trap);
            }
        });
    }

    // Convert HTTP(S) URL to WebSocket URL
    let ws_url = convert_to_websocket_url(&args.api_url);

    tracing::info!("WebSocket URL: {}", ws_url);

    // Shared connection state
    // Starts as false (not connected), updated when WebSocket connects/disconnects
    let connected = Arc::new(AtomicBool::new(false));

    // Create shutdown signal channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn signal handler for graceful shutdown
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        tracing::info!("Shutdown signal received, initiating graceful shutdown...");
        let _ = shutdown_tx.send(true);
    });

    // Retry loop with exponential backoff
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(60);
    let mut attempt = 0;

    loop {
        // Check if shutdown was requested
        if *shutdown_rx.borrow() {
            tracing::info!("Shutdown requested, exiting main loop");
            break;
        }

        attempt += 1;

        if attempt > 1 {
            tracing::info!(
                "Retry attempt {} - waiting {} seconds before reconnecting",
                attempt,
                retry_delay.as_secs()
            );
            sleep(retry_delay).await;

            // Exponential backoff: double the delay, capped at max
            retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
        }

        // Connect to Towerops server via WebSocket
        let mut client = match AgentClient::connect(&ws_url, &args.token).await {
            Ok(client) => {
                tracing::info!("Successfully connected to server");
                // Mark as connected for health check
                connected.store(true, Ordering::Relaxed);
                // Reset retry delay on successful connection
                retry_delay = Duration::from_secs(1);
                attempt = 0;
                client
            }
            Err(e) => {
                tracing::error!("Failed to connect to server: {}", e);
                // Mark as disconnected for health check
                connected.store(false, Ordering::Relaxed);
                continue;
            }
        };

        // Run the agent event loop with shutdown signal
        match client.run(shutdown_rx.clone()).await {
            Ok(()) => {
                // Clean shutdown requested
                if *shutdown_rx.borrow() {
                    tracing::info!("Agent shutdown complete");
                    break;
                }
            }
            Err(e) => {
                tracing::error!("Agent disconnected: {}", e);
            }
        }

        // Mark as disconnected for health check
        connected.store(false, Ordering::Relaxed);
        // Loop will retry with backoff (unless shutdown was requested)
    }

    tracing::info!("Towerops agent stopped");
}

/// Wait for SIGTERM or SIGINT shutdown signal.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
        let mut sigint =
            signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT");
            }
        }
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, just wait for Ctrl+C
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to register Ctrl+C handler");
        tracing::info!("Received Ctrl+C");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_http_to_websocket() {
        assert_eq!(
            convert_to_websocket_url("http://localhost:4000"),
            "ws://localhost:4000"
        );
    }

    #[test]
    fn test_convert_https_to_websocket() {
        assert_eq!(
            convert_to_websocket_url("https://towerops.net"),
            "wss://towerops.net"
        );
    }

    #[test]
    fn test_websocket_url_unchanged() {
        assert_eq!(
            convert_to_websocket_url("ws://localhost:4000"),
            "ws://localhost:4000"
        );
        assert_eq!(
            convert_to_websocket_url("wss://towerops.net"),
            "wss://towerops.net"
        );
    }

    #[test]
    fn test_bare_domain_gets_wss() {
        assert_eq!(
            convert_to_websocket_url("towerops.net"),
            "wss://towerops.net"
        );
        assert_eq!(
            convert_to_websocket_url("localhost:4000"),
            "wss://localhost:4000"
        );
    }
}
