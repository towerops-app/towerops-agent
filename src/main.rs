mod health;
mod ping;
mod proto;
mod snmp;
mod version;
mod websocket_client;

use clap::Parser;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
    let level_str = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
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

    log_info!("Towerops agent starting");

    // Check for newer Docker image version
    version::check_for_updates();

    // Convert HTTP(S) URL to WebSocket URL
    let ws_url = convert_to_websocket_url(&args.api_url);

    log_info!("WebSocket URL: {}", ws_url);

    // Shared connection state for health check
    // Starts as false (not connected), updated when WebSocket connects/disconnects
    let connected = Arc::new(AtomicBool::new(false));
    let connected_for_health = Arc::clone(&connected);

    // Start simple health endpoint with connection state
    tokio::spawn(async move {
        if let Err(e) = health::start_health_server(8080, connected_for_health).await {
            log_warn!("Health server error: {}", e);
        }
    });

    // Retry loop with exponential backoff
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(60);
    let mut attempt = 0;

    loop {
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

        // Run the agent event loop
        if let Err(e) = client.run().await {
            log_error!("Agent disconnected: {}", e);
            // Mark as disconnected for health check
            connected.store(false, Ordering::Relaxed);
            // Loop will retry with backoff
        }
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
            convert_to_websocket_url("https://app.towerops.com"),
            "wss://app.towerops.com"
        );
    }

    #[test]
    fn test_websocket_url_unchanged() {
        assert_eq!(
            convert_to_websocket_url("ws://localhost:4000"),
            "ws://localhost:4000"
        );
        assert_eq!(
            convert_to_websocket_url("wss://app.towerops.com"),
            "wss://app.towerops.com"
        );
    }

    #[test]
    fn test_bare_domain_gets_wss() {
        assert_eq!(
            convert_to_websocket_url("app.towerops.com"),
            "wss://app.towerops.com"
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

    // Note: main() function and init_logger() are not unit tested as they
    // involve global state and tokio runtime initialization.
    // They are tested via manual/integration testing.
}
