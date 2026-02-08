use anyhow::{Context, Result};
use std::net::IpAddr;
use std::time::Duration;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use tokio::time::timeout;

/// Ping a device and return response time in milliseconds.
///
/// Returns Ok(response_time_ms) on success, Err on failure.
pub async fn ping_device(ip_address: &str, timeout_ms: u64) -> Result<f64> {
    let ip: IpAddr = ip_address
        .parse()
        .context(format!("Invalid IP address: {}", ip_address))?;

    // Create ICMP client
    let client = Client::new(&Config::default())
        .context("Failed to create ping client - may require root/admin privileges")?;

    // Send ping with timeout
    let payload = [0; 56]; // Standard ping payload size
    let identifier = PingIdentifier(rand::random());
    let sequence = PingSequence(1);

    let ping_future = async {
        match ip {
            IpAddr::V4(addr) => {
                client
                    .pinger(addr.into(), identifier)
                    .await
                    .ping(sequence, &payload)
                    .await
            }
            IpAddr::V6(addr) => {
                client
                    .pinger(addr.into(), identifier)
                    .await
                    .ping(sequence, &payload)
                    .await
            }
        }
    };

    // Apply timeout
    let (_, duration) = timeout(Duration::from_millis(timeout_ms), ping_future)
        .await
        .context("Ping timeout")?
        .context("Ping failed")?;

    // Convert Duration to milliseconds (f64 for sub-millisecond precision)
    let ms = duration.as_secs_f64() * 1000.0;

    Ok(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access and elevated privileges
    async fn test_ping_localhost() {
        let result = ping_device("127.0.0.1", 5000).await;
        assert!(result.is_ok());
        let response_time = result.unwrap();
        assert!(response_time > 0.0);
        assert!(response_time < 100.0); // Localhost should be fast
    }
}
