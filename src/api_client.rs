use crate::config::{AgentConfig, HeartbeatMetadata};
use crate::metrics::Metric;
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

/// API client for communicating with the Towerops server
#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
    token: String,
}

impl ApiClient {
    /// Create a new API client
    pub fn new(base_url: String, token: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url,
            token,
        })
    }

    /// Fetch configuration from the API
    pub async fn fetch_config(&self) -> Result<AgentConfig> {
        let url = format!("{}/api/v1/agent/config", self.base_url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .context("Failed to send config request")?;

        if !response.status().is_success() {
            anyhow::bail!("Config request failed with status: {}", response.status());
        }

        let config: AgentConfig = response
            .json()
            .await
            .context("Failed to parse config response")?;

        Ok(config)
    }

    /// Submit metrics to the API
    pub async fn submit_metrics(&self, metrics: Vec<Metric>) -> Result<()> {
        if metrics.is_empty() {
            return Ok(());
        }

        let url = format!("{}/api/v1/agent/metrics", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&json!({ "metrics": metrics }))
            .send()
            .await
            .context("Failed to send metrics request")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Metrics submission failed with status: {}",
                response.status()
            );
        }

        Ok(())
    }

    /// Send heartbeat to the API
    pub async fn heartbeat(&self, metadata: HeartbeatMetadata) -> Result<()> {
        let url = format!("{}/api/v1/agent/heartbeat", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&metadata)
            .send()
            .await
            .context("Failed to send heartbeat request")?;

        if !response.status().is_success() {
            anyhow::bail!("Heartbeat failed with status: {}", response.status());
        }

        Ok(())
    }
}
