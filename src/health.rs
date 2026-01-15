use crate::buffer::Storage;
use crate::metrics::Timestamp;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::thread;
use tiny_http::{Response, Server};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub config_last_fetch: Option<String>,
    pub metrics_pending: usize,
    pub last_error: Option<String>,
}

pub struct HealthServer {
    start_time: Timestamp,
    storage: Storage,
    last_error: Arc<Mutex<Option<String>>>,
    config_last_fetch: Arc<Mutex<Option<Timestamp>>>,
}

impl HealthServer {
    pub fn new(storage: Storage) -> Self {
        Self {
            start_time: Timestamp::now(),
            storage,
            last_error: Arc::new(Mutex::new(None)),
            config_last_fetch: Arc::new(Mutex::new(None)),
        }
    }

    pub fn update_config_fetch_time(&self) {
        if let Ok(mut last_fetch) = self.config_last_fetch.lock() {
            *last_fetch = Some(Timestamp::now());
        }
    }

    pub fn record_error(&self, error: String) {
        if let Ok(mut last_error) = self.last_error.lock() {
            *last_error = Some(error);
        }
    }

    pub fn start(self, port: u16) {
        thread::spawn(move || {
            let addr = format!("0.0.0.0:{}", port);
            info!("Starting health endpoint on {}", addr);

            let server = match Server::http(&addr) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to start health server: {}", e);
                    return;
                }
            };

            for request in server.incoming_requests() {
                let path = request.url();

                if path == "/health" {
                    let status = self.get_health_status();
                    let json = match serde_json::to_string(&status) {
                        Ok(j) => j,
                        Err(e) => {
                            error!("Failed to serialize health status: {}", e);
                            let _ = request.respond(
                                Response::from_string("Internal error").with_status_code(500),
                            );
                            continue;
                        }
                    };

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
                    let _ =
                        request.respond(Response::from_string("Not found").with_status_code(404));
                }
            }
        });
    }

    fn get_health_status(&self) -> HealthStatus {
        let uptime = self.start_time.elapsed_secs() as u64;

        // Get pending metrics count
        let metrics_pending = self
            .storage
            .get_pending_metrics(1000)
            .map(|m| m.len())
            .unwrap_or(0);

        // Get last config fetch time
        let config_last_fetch = self
            .config_last_fetch
            .lock()
            .ok()
            .and_then(|guard| *guard)
            .map(|ts| ts.to_rfc3339());

        // Get last error
        let last_error = self
            .last_error
            .lock()
            .ok()
            .and_then(|guard| (*guard).clone());

        HealthStatus {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: uptime,
            config_last_fetch,
            metrics_pending,
            last_error,
        }
    }
}
