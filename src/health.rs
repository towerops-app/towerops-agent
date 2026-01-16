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
