use crate::api_client::ApiClient;
use crate::buffer::StorageError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("API error: {0}")]
    Api(#[from] crate::api_client::ApiError),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("SNMP error: {0}")]
    Snmp(#[from] crate::snmp::SnmpError),
    #[error("Executor error: {0}")]
    Executor(#[from] super::executor::ExecutorError),
}

pub type Result<T> = std::result::Result<T, SchedulerError>;

use crate::buffer::Storage;
use crate::config::{AgentConfig, HeartbeatMetadata};
use crate::poller::Executor;
use crate::snmp::SnmpClient;

use crate::metrics::Timestamp;
use log::{error, info, warn};
use std::time::Duration;
use tokio::time::interval;

/// Main scheduler that orchestrates polling, config refresh, and metrics submission
pub struct Scheduler {
    api_client: ApiClient,
    storage: Storage,
    executor: Executor,
    config_refresh_seconds: u64,
    current_config: Option<AgentConfig>,
    start_time: Timestamp,
}

impl Scheduler {
    pub fn new(
        api_client: ApiClient,
        storage: Storage,
        snmp_client: SnmpClient,
        config_refresh_seconds: u64,
    ) -> Self {
        let executor = Executor::new(snmp_client, storage.clone());

        Self {
            api_client,
            storage,
            executor,
            config_refresh_seconds,
            current_config: None,
            start_time: Timestamp::now(),
        }
    }

    /// Run the main event loop
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting Towerops agent scheduler");

        // Fetch initial configuration
        if let Err(e) = self.refresh_config().await {
            error!("Failed to fetch initial config: {}", e);
        }

        let mut config_ticker = interval(Duration::from_secs(self.config_refresh_seconds));
        let mut metrics_ticker = interval(Duration::from_secs(30));
        let mut heartbeat_ticker = interval(Duration::from_secs(60));
        let mut cleanup_ticker = interval(Duration::from_secs(3600)); // Cleanup every hour
        let mut poll_ticker = interval(Duration::from_secs(5)); // Check if polling needed every 5s

        loop {
            tokio::select! {
                _ = config_ticker.tick() => {
                    if let Err(e) = self.refresh_config().await {
                        error!("Failed to refresh config: {}", e);
                    }
                }

                _ = metrics_ticker.tick() => {
                    if let Err(e) = self.flush_metrics().await {
                        error!("Failed to flush metrics: {}", e);
                    }
                }

                _ = heartbeat_ticker.tick() => {
                    if let Err(e) = self.send_heartbeat().await {
                        warn!("Failed to send heartbeat: {}", e);
                    }
                }

                _ = cleanup_ticker.tick() => {
                    if let Err(e) = self.storage.cleanup_old_metrics() {
                        error!("Failed to cleanup old metrics: {}", e);
                    }
                }

                _ = poll_ticker.tick() => {
                    if let Err(e) = self.poll_equipment().await {
                        error!("Polling error: {}", e);
                    }
                }
            }
        }
    }

    async fn refresh_config(&mut self) -> Result<()> {
        info!("Refreshing configuration from API");

        match self.api_client.fetch_config().await {
            Ok(config) => {
                info!(
                    "Configuration updated: {} equipment items",
                    config.equipment.len()
                );
                self.current_config = Some(config);
                Ok(())
            }
            Err(e) => {
                warn!(
                    "Failed to fetch config, continuing with cached config: {}",
                    e
                );
                Err(e.into())
            }
        }
    }

    async fn flush_metrics(&self) -> Result<()> {
        let pending = self.storage.get_pending_metrics(100)?;

        if pending.is_empty() {
            return Ok(());
        }

        info!("Flushing {} pending metrics to API", pending.len());

        let ids: Vec<i64> = pending.iter().map(|(id, _)| *id).collect();
        let metrics: Vec<_> = pending.into_iter().map(|(_, m)| m).collect();

        match self.api_client.submit_metrics(metrics).await {
            Ok(_) => {
                self.storage.mark_metrics_sent(&ids)?;
                info!("Successfully submitted {} metrics", ids.len());
                Ok(())
            }
            Err(e) => {
                warn!("Failed to submit metrics, will retry later: {}", e);
                Err(e.into())
            }
        }
    }

    async fn send_heartbeat(&self) -> Result<()> {
        let uptime = self.start_time.elapsed_secs() as u64;

        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());

        let metadata = HeartbeatMetadata {
            version: crate::version::current_version().to_string(),
            hostname,
            uptime_seconds: uptime,
        };

        self.api_client.heartbeat(metadata).await?;
        Ok(())
    }

    async fn poll_equipment(&self) -> Result<()> {
        let config = match &self.current_config {
            Some(c) => c,
            None => return Ok(()),
        };

        let poll_times = self.storage.get_all_last_poll_times()?;

        for equipment in &config.equipment {
            if !equipment.snmp.enabled {
                continue;
            }

            // Check if it's time to poll this equipment
            let should_poll = match poll_times.get(&equipment.id) {
                Some(last_poll) => {
                    let elapsed = last_poll.elapsed_secs() as u64;
                    elapsed >= equipment.poll_interval_seconds
                }
                None => true, // Never polled before
            };

            if should_poll {
                info!("Polling equipment: {}", equipment.name);

                // Poll sensors and interfaces in parallel
                let (sensor_result, interface_result) = tokio::join!(
                    self.executor.poll_sensors(equipment),
                    self.executor.poll_interfaces(equipment)
                );

                if let Err(e) = sensor_result {
                    error!("Failed to poll sensors for {}: {}", equipment.name, e);
                }

                if let Err(e) = interface_result {
                    error!("Failed to poll interfaces for {}: {}", equipment.name, e);
                }

                // Update last poll time
                if let Err(e) = self.storage.update_last_poll_time(&equipment.id) {
                    error!("Failed to update last poll time: {}", e);
                }
            }
        }

        Ok(())
    }
}
