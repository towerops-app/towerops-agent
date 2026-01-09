use crate::config::{AgentConfig, HeartbeatMetadata};
use crate::metrics::Metric;
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

    /// Submit metrics to the API
    pub async fn submit_metrics(&self, metrics: Vec<Metric>) -> Result<()> {
        if metrics.is_empty() {
            return Ok(());
        }

        let url = format!("{}/api/v1/agent/metrics", self.base_url);
        let token = self.token.clone();

        tokio::task::spawn_blocking(move || {
            let response = ureq::post(&url)
                .set("Authorization", &format!("Bearer {}", token))
                .timeout(Duration::from_secs(30))
                .send_json(json!({ "metrics": metrics }))
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
