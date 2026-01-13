use crate::config::{AgentConfig, HeartbeatMetadata};
use crate::metrics::Metric;
use crate::proto::agent;
use prost::Message;
use serde_json::json;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),

    #[error("HTTP status error: {0}")]
    StatusError(u16),

    #[error("JSON parsing error: {0}")]
    JsonError(#[from] std::io::Error),

    #[error("Task join error: {0}")]
    JoinError(String),
}

pub type Result<T> = std::result::Result<T, ApiError>;

/// API client for communicating with the Towerops server
#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    token: String,
}

impl ApiClient {
    /// Create a new API client
    pub fn new(base_url: String, token: String) -> Result<Self> {
        Ok(Self { base_url, token })
    }

    /// Fetch configuration from the API
    pub async fn fetch_config(&self) -> Result<AgentConfig> {
        let url = format!("{}/api/v1/agent/config", self.base_url);
        let token = self.token.clone();

        let config = tokio::task::spawn_blocking(move || {
            let response = ureq::get(&url)
                .set("Authorization", &format!("Bearer {}", token))
                .timeout(Duration::from_secs(30))
                .call()
                .map_err(|e| ApiError::RequestFailed(e.to_string()))?;

            let status = response.status();
            if status != 200 {
                return Err(ApiError::StatusError(status));
            }

            let config: AgentConfig = response
                .into_json()
                .map_err(|e| ApiError::RequestFailed(e.to_string()))?;

            Ok(config)
        })
        .await
        .map_err(|e| ApiError::JoinError(e.to_string()))??;

        Ok(config)
    }

    /// Submit metrics to the API using Protocol Buffers
    pub async fn submit_metrics(&self, metrics: Vec<Metric>) -> Result<()> {
        if metrics.is_empty() {
            return Ok(());
        }

        let url = format!("{}/api/v1/agent/metrics", self.base_url);
        let token = self.token.clone();

        tokio::task::spawn_blocking(move || {
            // Convert metrics to protobuf
            let proto_metrics: Vec<agent::Metric> = metrics
                .into_iter()
                .map(|m| convert_metric_to_proto(&m))
                .collect();

            let batch = agent::MetricBatch {
                metrics: proto_metrics,
            };

            // Encode to bytes
            let mut buf = Vec::new();
            batch
                .encode(&mut buf)
                .map_err(|e| ApiError::RequestFailed(format!("Protobuf encoding error: {}", e)))?;

            // Send as protobuf
            let response = ureq::post(&url)
                .set("Authorization", &format!("Bearer {}", token))
                .set("Content-Type", "application/x-protobuf")
                .timeout(Duration::from_secs(30))
                .send_bytes(&buf)
                .map_err(|e| ApiError::RequestFailed(e.to_string()))?;

            let status = response.status();
            if status != 200 {
                return Err(ApiError::StatusError(status));
            }

            Ok(())
        })
        .await
        .map_err(|e| ApiError::JoinError(e.to_string()))??;

        Ok(())
    }

    /// Send heartbeat to the API
    pub async fn heartbeat(&self, metadata: HeartbeatMetadata) -> Result<()> {
        let url = format!("{}/api/v1/agent/heartbeat", self.base_url);
        let token = self.token.clone();

        tokio::task::spawn_blocking(move || {
            let response = ureq::post(&url)
                .set("Authorization", &format!("Bearer {}", token))
                .timeout(Duration::from_secs(30))
                .send_json(&metadata)
                .map_err(|e| ApiError::RequestFailed(e.to_string()))?;

            let status = response.status();
            if status != 200 {
                return Err(ApiError::StatusError(status));
            }

            Ok(())
        })
        .await
        .map_err(|e| ApiError::JoinError(e.to_string()))??;

        Ok(())
    }
}

/// Convert internal Metric type to protobuf Metric
fn convert_metric_to_proto(metric: &Metric) -> agent::Metric {
    use crate::metrics::Metric as M;

    match metric {
        M::SensorReading(sr) => agent::Metric {
            metric_type: Some(agent::metric::MetricType::SensorReading(
                agent::SensorReading {
                    sensor_id: sr.sensor_id.clone(),
                    value: sr.value,
                    status: sr.status.clone(),
                    timestamp: sr.timestamp.to_unix_timestamp(),
                },
            )),
        },
        M::InterfaceStat(is) => agent::Metric {
            metric_type: Some(agent::metric::MetricType::InterfaceStat(
                agent::InterfaceStat {
                    interface_id: is.interface_id.clone(),
                    if_in_octets: is.if_in_octets,
                    if_out_octets: is.if_out_octets,
                    if_in_errors: is.if_in_errors,
                    if_out_errors: is.if_out_errors,
                    if_in_discards: is.if_in_discards,
                    if_out_discards: is.if_out_discards,
                    timestamp: is.timestamp.to_unix_timestamp(),
                },
            )),
        },
    }
}
