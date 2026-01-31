mod proto;
mod snmp;
mod version;
mod websocket_client;

use clap::Parser;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::time::sleep;
use websocket_client::AgentClient;

// Log levels
pub(crate) static LOG_LEVEL: std::sync::OnceLock<LogLevel> = std::sync::OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LogLevel {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
}

impl LogLevel {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "error" => LogLevel::Error,
            "warn" => LogLevel::Warn,
            "info" => LogLevel::Info,
            "debug" => LogLevel::Debug,
            _ => LogLevel::Info,
        }
    }
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {{
        let level = $crate::LOG_LEVEL.get().copied().unwrap_or($crate::LogLevel::Info);
        if level >= $crate::LogLevel::Error {
            let ts = $crate::format_timestamp();
            eprintln!("[{}] [ERROR] {}", ts, format!($($arg)*));
        }
    }};
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {{
        let level = $crate::LOG_LEVEL.get().copied().unwrap_or($crate::LogLevel::Info);
        if level >= $crate::LogLevel::Warn {
            let ts = $crate::format_timestamp();
            eprintln!("[{}] [WARN] {}", ts, format!($($arg)*));
        }
    }};
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {{
        let level = $crate::LOG_LEVEL.get().copied().unwrap_or($crate::LogLevel::Info);
        if level >= $crate::LogLevel::Info {
            let ts = $crate::format_timestamp();
            eprintln!("[{}] [INFO] {}", ts, format!($($arg)*));
        }
    }};
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {{
        let level = $crate::LOG_LEVEL.get().copied().unwrap_or($crate::LogLevel::Info);
        if level >= $crate::LogLevel::Debug {
            let ts = $crate::format_timestamp();
            eprintln!("[{}] [DEBUG] {}", ts, format!($($arg)*));
        }
    }};
}

/// Format current timestamp as "YYYY-MM-DD HH:MM:SS.mmm"
pub fn format_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();
    let millis = now.subsec_millis();

    // Calculate date/time components
    const SECS_PER_DAY: u64 = 86400;
    const SECS_PER_HOUR: u64 = 3600;
    const SECS_PER_MIN: u64 = 60;

    let days_since_epoch = secs / SECS_PER_DAY;
    let secs_today = secs % SECS_PER_DAY;

    let hour = (secs_today / SECS_PER_HOUR) as u8;
    let min = ((secs_today % SECS_PER_HOUR) / SECS_PER_MIN) as u8;
    let sec = (secs_today % SECS_PER_MIN) as u8;

    // Simple epoch to date conversion (good enough for logging)
    // Days since 1970-01-01
    let mut year = 1970;
    let mut days_left = days_since_epoch;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days_left >= days_in_year {
            days_left -= days_in_year;
            year += 1;
        } else {
            break;
        }
    }

    let (month, day) = days_to_month_day(days_left as u16, is_leap_year(year));

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        year, month, day, hour, min, sec, millis
    )
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_to_month_day(days: u16, is_leap: bool) -> (u8, u8) {
    let days_in_month = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut days_left = days;
    for (month_idx, &days_in_month) in days_in_month.iter().enumerate() {
        if days_left < days_in_month as u16 {
            return ((month_idx + 1) as u8, (days_left + 1) as u8);
        }
        days_left -= days_in_month as u16;
    }

    (12, 31) // Fallback
}

fn init_logger() {
    // Use LOG_LEVEL env var (fall back to RUST_LOG for backwards compatibility)
    let level_str = env::var("LOG_LEVEL")
        .or_else(|_| env::var("RUST_LOG"))
        .unwrap_or_else(|_| "info".to_string());
    let level = LogLevel::from_str(&level_str);
    LOG_LEVEL.set(level).ok();
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

    log_info!("Towerops agent starting");

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
                log_info!("{}", trap);
            }
        });
    }

    // Convert HTTP(S) URL to WebSocket URL
    let ws_url = convert_to_websocket_url(&args.api_url);

    log_info!("WebSocket URL: {}", ws_url);

    // Shared connection state
    // Starts as false (not connected), updated when WebSocket connects/disconnects
    let connected = Arc::new(AtomicBool::new(false));

    // Create shutdown signal channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn signal handler for graceful shutdown
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        log_info!("Shutdown signal received, initiating graceful shutdown...");
        let _ = shutdown_tx.send(true);
    });

    // Retry loop with exponential backoff
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(60);
    let mut attempt = 0;

    loop {
        // Check if shutdown was requested
        if *shutdown_rx.borrow() {
            log_info!("Shutdown requested, exiting main loop");
            break;
        }

        attempt += 1;

        if attempt > 1 {
            log_info!(
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
                log_info!("Successfully connected to server");
                // Mark as connected for health check
                connected.store(true, Ordering::Relaxed);
                // Reset retry delay on successful connection
                retry_delay = Duration::from_secs(1);
                attempt = 0;
                client
            }
            Err(e) => {
                log_error!("Failed to connect to server: {}", e);
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
                    log_info!("Agent shutdown complete");
                    break;
                }
            }
            Err(e) => {
                log_error!("Agent disconnected: {}", e);
            }
        }

        // Mark as disconnected for health check
        connected.store(false, Ordering::Relaxed);
        // Loop will retry with backoff (unless shutdown was requested)
    }

    log_info!("Towerops agent stopped");
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
                log_info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                log_info!("Received SIGINT");
            }
        }
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, just wait for Ctrl+C
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to register Ctrl+C handler");
        log_info!("Received Ctrl+C");
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

    #[test]
    fn test_format_timestamp() {
        let timestamp = format_timestamp();
        // Should be in format "YYYY-MM-DD HH:MM:SS.mmm"
        assert!(timestamp.len() >= 23); // Minimum length
        assert!(timestamp.contains('-'));
        assert!(timestamp.contains(':'));
        assert!(timestamp.contains('.'));
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000)); // Divisible by 400
        assert!(is_leap_year(2024)); // Divisible by 4, not by 100
        assert!(!is_leap_year(1900)); // Divisible by 100, not by 400
        assert!(!is_leap_year(2023)); // Not divisible by 4
    }

    #[test]
    fn test_days_to_month_day() {
        // January 1st (day 0)
        assert_eq!(days_to_month_day(0, false), (1, 1));

        // January 31st (day 30)
        assert_eq!(days_to_month_day(30, false), (1, 31));

        // February 1st (day 31)
        assert_eq!(days_to_month_day(31, false), (2, 1));

        // March 1st in non-leap year (day 59)
        assert_eq!(days_to_month_day(59, false), (3, 1));

        // March 1st in leap year (day 60)
        assert_eq!(days_to_month_day(60, true), (3, 1));

        // December 31st in non-leap year (day 364)
        assert_eq!(days_to_month_day(364, false), (12, 31));
    }

    #[test]
    fn test_log_level_from_str_error() {
        assert_eq!(LogLevel::from_str("error"), LogLevel::Error);
        assert_eq!(LogLevel::from_str("ERROR"), LogLevel::Error);
        assert_eq!(LogLevel::from_str("Error"), LogLevel::Error);
    }

    #[test]
    fn test_log_level_from_str_warn() {
        assert_eq!(LogLevel::from_str("warn"), LogLevel::Warn);
        assert_eq!(LogLevel::from_str("WARN"), LogLevel::Warn);
        assert_eq!(LogLevel::from_str("Warn"), LogLevel::Warn);
    }

    #[test]
    fn test_log_level_from_str_info() {
        assert_eq!(LogLevel::from_str("info"), LogLevel::Info);
        assert_eq!(LogLevel::from_str("INFO"), LogLevel::Info);
        assert_eq!(LogLevel::from_str("Info"), LogLevel::Info);
    }

    #[test]
    fn test_log_level_from_str_debug() {
        assert_eq!(LogLevel::from_str("debug"), LogLevel::Debug);
        assert_eq!(LogLevel::from_str("DEBUG"), LogLevel::Debug);
        assert_eq!(LogLevel::from_str("Debug"), LogLevel::Debug);
    }

    #[test]
    fn test_log_level_from_str_unknown() {
        // Unknown values default to Info
        assert_eq!(LogLevel::from_str("unknown"), LogLevel::Info);
        assert_eq!(LogLevel::from_str("trace"), LogLevel::Info);
        assert_eq!(LogLevel::from_str(""), LogLevel::Info);
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Debug);
    }

    #[test]
    fn test_log_level_eq() {
        assert_eq!(LogLevel::Error, LogLevel::Error);
        assert_eq!(LogLevel::Warn, LogLevel::Warn);
        assert_eq!(LogLevel::Info, LogLevel::Info);
        assert_eq!(LogLevel::Debug, LogLevel::Debug);
    }

    #[test]
    fn test_log_level_copy() {
        let level = LogLevel::Debug;
        let copied = level;
        assert_eq!(copied, LogLevel::Debug);
    }

    #[test]
    fn test_log_level_clone() {
        let level = LogLevel::Warn;
        let cloned = level.clone();
        assert_eq!(cloned, LogLevel::Warn);
    }

    #[test]
    fn test_days_to_month_day_february() {
        // February 28th in non-leap year (day 58)
        assert_eq!(days_to_month_day(58, false), (2, 28));

        // February 29th in leap year (day 59)
        assert_eq!(days_to_month_day(59, true), (2, 29));
    }

    #[test]
    fn test_days_to_month_day_later_months() {
        // April 15th in non-leap year (day 105)
        // Jan=31, Feb=28, Mar=31, Apr 1-15 = 31+28+31+14 = 104 (0-indexed day 104)
        assert_eq!(days_to_month_day(104, false), (4, 15));

        // July 4th in non-leap year
        // Jan=31, Feb=28, Mar=31, Apr=30, May=31, Jun=30, Jul 1-4 = 31+28+31+30+31+30+3 = 184 (day 184)
        assert_eq!(days_to_month_day(184, false), (7, 4));
    }

    #[test]
    fn test_days_to_month_day_end_of_year() {
        // December 31st in leap year (day 365)
        assert_eq!(days_to_month_day(365, true), (12, 31));

        // December 25th in non-leap year
        // 31+28+31+30+31+30+31+31+30+31+30+24 = 358 (day 358)
        assert_eq!(days_to_month_day(358, false), (12, 25));
    }

    #[test]
    fn test_days_to_month_day_overflow_fallback() {
        // Day 400 is beyond year - should fallback to Dec 31
        assert_eq!(days_to_month_day(400, false), (12, 31));
    }

    #[test]
    fn test_format_timestamp_structure() {
        let timestamp = format_timestamp();
        // Should be in format "YYYY-MM-DD HH:MM:SS.mmm"
        let parts: Vec<&str> = timestamp.split(' ').collect();
        assert_eq!(parts.len(), 2, "Expected date and time parts");

        let date_parts: Vec<&str> = parts[0].split('-').collect();
        assert_eq!(date_parts.len(), 3, "Expected year-month-day");

        let time_parts: Vec<&str> = parts[1].split(':').collect();
        assert_eq!(time_parts.len(), 3, "Expected hour:min:sec.ms");
    }
}
