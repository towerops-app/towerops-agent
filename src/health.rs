use anyhow::Result;
use log::info;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tiny_http::{Response, Server};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
}

/// Start a simple health check HTTP server
pub async fn start_health_server(port: u16) -> Result<()> {
    let start_time = Arc::new(Instant::now());

    tokio::task::spawn_blocking(move || {
        let addr = format!("0.0.0.0:{}", port);
        info!("Starting health endpoint on {}", addr);

        let server = Server::http(&addr)
            .map_err(|e| anyhow::anyhow!("Failed to start health server: {}", e))?;

        for request in server.incoming_requests() {
            let path = request.url();

            if path == "/health" {
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

                let response = Response::from_string(json)
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Type"[..],
                            &b"application/json"[..],
                        )
                        .unwrap(),
                    )
                    .with_status_code(200);

                let _ = request.respond(response);
            } else {
                let _ = request.respond(Response::from_string("Not found").with_status_code(404));
            }
        }

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    Ok(())
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
