use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
}

/// Start a simple health check HTTP server using raw TCP
pub async fn start_health_server(port: u16) -> Result<()> {
    let start_time = Arc::new(Instant::now());
    let addr = format!("0.0.0.0:{}", port);

    crate::log_info!("Starting health endpoint on {}", addr);
    let listener = TcpListener::bind(&addr).await?;

    loop {
        match listener.accept().await {
            Ok((mut socket, _)) => {
                let start_time = Arc::clone(&start_time);

                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];

                    // Read the HTTP request
                    if let Ok(n) = socket.read(&mut buffer).await {
                        if n > 0 {
                            let request = String::from_utf8_lossy(&buffer[..n]);

                            // Check if this is a GET request to /health
                            if request.starts_with("GET /health") {
                                let uptime = start_time.elapsed().as_secs();
                                let status = HealthStatus {
                                    status: "healthy".to_string(),
                                    version: env!("CARGO_PKG_VERSION").to_string(),
                                    uptime_seconds: uptime,
                                };

                                let json = serde_json::to_string(&status).unwrap_or_else(|_| {
                                    r#"{"status":"error","message":"Failed to serialize health status"}"#
                                        .to_string()
                                });

                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                    json.len(),
                                    json
                                );

                                let _ = socket.write_all(response.as_bytes()).await;
                            } else {
                                // 404 for other paths
                                let response =
                                    "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot found";
                                let _ = socket.write_all(response.as_bytes()).await;
                            }
                        }
                    }

                    let _ = socket.shutdown().await;
                });
            }
            Err(e) => {
                crate::log_warn!("Failed to accept health check connection: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_serialization() {
        let status = HealthStatus {
            status: "healthy".to_string(),
            version: "0.1.0".to_string(),
            uptime_seconds: 42,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains(r#""status":"healthy""#));
        assert!(json.contains(r#""version":"0.1.0""#));
        assert!(json.contains(r#""uptime_seconds":42"#));
    }

    #[test]
    fn test_health_status_deserialization() {
        let json = r#"{"status":"healthy","version":"0.1.0","uptime_seconds":42}"#;
        let status: HealthStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.status, "healthy");
        assert_eq!(status.version, "0.1.0");
        assert_eq!(status.uptime_seconds, 42);
    }

    #[test]
    fn test_health_status_clone() {
        let status = HealthStatus {
            status: "healthy".to_string(),
            version: "0.1.0".to_string(),
            uptime_seconds: 42,
        };
        let cloned = status.clone();
        assert_eq!(status.status, cloned.status);
        assert_eq!(status.version, cloned.version);
        assert_eq!(status.uptime_seconds, cloned.uptime_seconds);
    }

    // Note: start_health_server is tested manually/via integration tests
    // Unit testing it requires complex async server mocking which is not practical
}
