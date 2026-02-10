use anyhow::{Context, Result};
use std::net::IpAddr;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Ping a device using command-line ping and return response time in milliseconds.
///
/// Uses the system ping command (from iputils package) which has setuid root
/// and doesn't require CAP_NET_RAW capability.
///
/// Returns Ok(response_time_ms) on success, Err on failure.
pub async fn ping_device(ip_address: &str, timeout_ms: u64) -> Result<f64> {
    let ip: IpAddr = ip_address
        .parse()
        .context(format!("Invalid IP address: {}", ip_address))?;

    // Determine ping command based on IP version
    let ping_cmd = match ip {
        IpAddr::V4(_) => "ping",
        IpAddr::V6(_) => "ping6",
    };

    // Convert timeout to seconds (ping uses seconds, min 1)
    let timeout_secs = std::cmp::max(1, timeout_ms / 1000);

    // Execute ping command: -c 1 (count=1), -W timeout (wait time)
    // Output format: time=X.XX ms
    let output = timeout(
        Duration::from_millis(timeout_ms + 1000), // Add 1s buffer to tokio timeout
        Command::new(ping_cmd)
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg(timeout_secs.to_string())
            .arg(ip_address)
            .output(),
    )
    .await
    .context("Ping command timed out")?
    .context("Failed to execute ping command")?;

    // Check if ping succeeded (exit code 0)
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Ping failed: {}", stderr.trim()));
    }

    // Parse response time from stdout
    // Example output: "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.3 ms"
    let stdout = String::from_utf8_lossy(&output.stdout);
    let response_time =
        parse_ping_time(&stdout).context("Failed to parse ping response time from output")?;

    Ok(response_time)
}

/// Parse the response time from ping output.
///
/// Looks for "time=X.XX ms" or "time=X.XX" pattern in the output.
fn parse_ping_time(output: &str) -> Result<f64> {
    for line in output.lines() {
        if let Some(time_start) = line.find("time=") {
            let time_str = &line[time_start + 5..]; // Skip "time="

            // Extract number before " ms" or end of string
            let time_end = time_str
                .find(" ms")
                .or_else(|| time_str.find(' '))
                .unwrap_or(time_str.len());

            let time_value = &time_str[..time_end];

            return time_value
                .parse::<f64>()
                .context(format!("Invalid time value: {}", time_value));
        }
    }

    Err(anyhow::anyhow!("No time= field found in ping output"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ping_time() {
        let output = "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.3 ms";
        assert_eq!(parse_ping_time(output).unwrap(), 12.3);

        let output = "64 bytes from localhost: icmp_seq=1 ttl=64 time=0.123 ms";
        assert_eq!(parse_ping_time(output).unwrap(), 0.123);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_ping_localhost() {
        let result = ping_device("127.0.0.1", 5000).await;
        assert!(result.is_ok());
        let response_time = result.unwrap();
        assert!(response_time > 0.0);
        assert!(response_time < 100.0); // Localhost should be fast
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_ping_timeout() {
        // Try to ping a non-routable address with short timeout
        let result = ping_device("192.0.2.1", 1000).await;
        assert!(result.is_err());
    }
}
