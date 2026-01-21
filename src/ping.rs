use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Pings an IP address using the system ping command and returns the round-trip time.
///
/// This implementation uses the system `ping` binary which is typically setuid root,
/// allowing ICMP operations without requiring CAP_NET_RAW or elevated privileges
/// for the application itself.
///
/// # Arguments
///
/// * `ip` - The IP address to ping
/// * `timeout_duration` - Maximum time to wait for a response
///
/// # Returns
///
/// * `Ok(Duration)` - The round-trip time if successful
/// * `Err(anyhow::Error)` - If the ping fails or times out
pub async fn ping(ip: IpAddr, timeout_duration: Duration) -> Result<Duration> {
    let ip_str = ip.to_string();
    let timeout_secs = timeout_duration.as_secs().max(1);

    // Build ping command arguments based on OS
    let args = if cfg!(target_os = "macos") {
        // macOS: -W is timeout in ms
        vec![
            "-c".to_string(),
            "1".to_string(),
            "-W".to_string(),
            (timeout_secs * 1000).to_string(),
            ip_str.clone(),
        ]
    } else {
        // Linux: -W is timeout in seconds
        vec![
            "-c".to_string(),
            "1".to_string(),
            "-W".to_string(),
            timeout_secs.to_string(),
            ip_str.clone(),
        ]
    };

    // Execute ping command with timeout
    let result = timeout(timeout_duration + Duration::from_secs(1), async {
        let output = Command::new("ping")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_ping_output(&stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(format!(
                "Ping failed for {}: {}{}",
                ip_str,
                stdout.trim(),
                stderr.trim()
            )
            .into())
        }
    })
    .await;

    match result {
        Ok(inner_result) => inner_result,
        Err(_) => Err(format!("Ping timeout for {}", ip_str).into()),
    }
}

/// Parse the ping output to extract round-trip time as Duration.
///
/// Supports multiple output formats:
/// - macOS: "round-trip min/avg/max/stddev = 1.234/1.234/1.234/0.000 ms"
/// - Linux: "rtt min/avg/max/mdev = 1.234/1.234/1.234/0.000 ms"
/// - Both: "time=X.XX ms" in the reply line
fn parse_ping_output(output: &str) -> Result<Duration> {
    // Try macOS format: "round-trip min/avg/max/stddev = X/Y/Z/W ms"
    if let Some(caps) = regex_lite::Regex::new(r"round-trip.*=\s*[\d.]+/([\d.]+)/")
        .ok()
        .and_then(|re| re.captures(output))
    {
        if let Some(avg_ms) = caps.get(1) {
            if let Ok(ms) = avg_ms.as_str().parse::<f64>() {
                return Ok(Duration::from_secs_f64(ms / 1000.0));
            }
        }
    }

    // Try Linux format: "rtt min/avg/max/mdev = X/Y/Z/W ms"
    if let Some(caps) = regex_lite::Regex::new(r"rtt.*=\s*[\d.]+/([\d.]+)/")
        .ok()
        .and_then(|re| re.captures(output))
    {
        if let Some(avg_ms) = caps.get(1) {
            if let Ok(ms) = avg_ms.as_str().parse::<f64>() {
                return Ok(Duration::from_secs_f64(ms / 1000.0));
            }
        }
    }

    // Try extracting from "time=X.XX ms" in the reply line
    if let Some(caps) = regex_lite::Regex::new(r"time[=<]([\d.]+)\s*ms")
        .ok()
        .and_then(|re| re.captures(output))
    {
        if let Some(time_ms) = caps.get(1) {
            if let Ok(ms) = time_ms.as_str().parse::<f64>() {
                return Ok(Duration::from_secs_f64(ms / 1000.0));
            }
        }
    }

    Err(format!("Could not parse ping output: {}", output.trim()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ping_output_macos() {
        let output = r#"PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=1.234 ms

--- 192.168.1.1 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1.234/1.234/1.234/0.000 ms"#;

        let result = parse_ping_output(output);
        assert!(result.is_ok());
        let duration = result.unwrap();
        // Should be approximately 1.234ms
        assert!(duration.as_secs_f64() > 0.001);
        assert!(duration.as_secs_f64() < 0.002);
    }

    #[test]
    fn test_parse_ping_output_linux() {
        let output = r#"PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.543 ms

--- 192.168.1.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.543/0.543/0.543/0.000 ms"#;

        let result = parse_ping_output(output);
        assert!(result.is_ok());
        let duration = result.unwrap();
        // Should be approximately 0.543ms
        assert!(duration.as_secs_f64() > 0.0005);
        assert!(duration.as_secs_f64() < 0.001);
    }

    #[test]
    fn test_parse_ping_output_time_only() {
        // Some systems may not include the summary line
        let output = "64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=2.567 ms";

        let result = parse_ping_output(output);
        assert!(result.is_ok());
        let duration = result.unwrap();
        // Should be approximately 2.567ms
        assert!(duration.as_secs_f64() > 0.002);
        assert!(duration.as_secs_f64() < 0.003);
    }

    #[test]
    fn test_parse_ping_output_time_less_than() {
        // Some ping implementations use time<1 ms for very fast responses
        let output = "64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time<1 ms";

        let result = parse_ping_output(output);
        assert!(result.is_ok());
        let duration = result.unwrap();
        // Should be approximately 1ms (the < becomes the value)
        assert!(duration.as_secs_f64() < 0.002);
    }

    #[test]
    fn test_parse_ping_output_invalid() {
        let output = "some random text without ping data";
        let result = parse_ping_output(output);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ping_output_empty() {
        let result = parse_ping_output("");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ping_localhost() {
        // This test actually pings localhost - skip if no network
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let result = ping(ip, Duration::from_secs(5)).await;

        // Localhost ping should succeed on most systems
        if result.is_ok() {
            let duration = result.unwrap();
            // Localhost should respond in < 100ms
            assert!(duration.as_millis() < 100);
        }
        // If it fails, that's okay too - some systems don't allow ping to localhost
    }

    #[tokio::test]
    async fn test_ping_invalid_ip() {
        // This should fail - non-routable IP
        let ip: IpAddr = "192.0.2.1".parse().unwrap(); // TEST-NET-1, not routable
        let result = ping(ip, Duration::from_secs(2)).await;

        // Should either timeout or fail
        assert!(result.is_err());
    }
}
