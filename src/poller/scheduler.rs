use crate::api_client::ApiClient;
use crate::buffer::StorageError;

#[derive(Debug)]
pub enum SchedulerError {
    Api(crate::api_client::ApiError),
    Storage(StorageError),
    Snmp(crate::snmp::SnmpError),
    Executor(super::executor::ExecutorError),
}

impl std::fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api(err) => write!(f, "API error: {}", err),
            Self::Storage(err) => write!(f, "Storage error: {}", err),
            Self::Snmp(err) => write!(f, "SNMP error: {}", err),
            Self::Executor(err) => write!(f, "Executor error: {}", err),
        }
    }
}

impl std::error::Error for SchedulerError {}

impl From<crate::api_client::ApiError> for SchedulerError {
    fn from(err: crate::api_client::ApiError) -> Self {
        Self::Api(err)
    }
}

impl From<StorageError> for SchedulerError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err)
    }
}

impl From<crate::snmp::SnmpError> for SchedulerError {
    fn from(err: crate::snmp::SnmpError) -> Self {
        Self::Snmp(err)
    }
}

impl From<super::executor::ExecutorError> for SchedulerError {
    fn from(err: super::executor::ExecutorError) -> Self {
        Self::Executor(err)
    }
}

pub type Result<T> = std::result::Result<T, SchedulerError>;

use crate::buffer::Storage;
use crate::config::{AgentConfig, HeartbeatMetadata};
use crate::poller::Executor;
use crate::snmp::SnmpClient;

use crate::metrics::Timestamp;
use log::{error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
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
        let mut update_ticker = interval(Duration::from_secs(3600)); // Check for updates every hour

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

                _ = update_ticker.tick() => {
                    self.check_and_update().await;
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
        // Process metrics in batches until queue is empty or we hit an error
        // This handles high-volume scenarios with 10,000+ equipment
        let mut total_flushed = 0;
        const BATCH_SIZE: usize = 500;
        const MAX_BATCHES: usize = 20; // Limit to 10,000 metrics per flush cycle

        for _ in 0..MAX_BATCHES {
            let pending = self.storage.get_pending_metrics(BATCH_SIZE)?;

            if pending.is_empty() {
                break;
            }

            let batch_size = pending.len();
            let ids: Vec<i64> = pending.iter().map(|(id, _)| *id).collect();
            let metrics: Vec<_> = pending.into_iter().map(|(_, m)| m).collect();

            match self.api_client.submit_metrics(metrics).await {
                Ok(_) => {
                    self.storage.mark_metrics_sent(&ids)?;
                    total_flushed += batch_size;
                }
                Err(e) => {
                    warn!("Failed to submit batch of {} metrics: {}", batch_size, e);
                    // Don't return error, just log and continue with remaining batches
                    break;
                }
            }

            // If we got less than batch size, we've emptied the queue
            if batch_size < BATCH_SIZE {
                break;
            }
        }

        if total_flushed > 0 {
            info!("Successfully flushed {} metrics to API", total_flushed);
        }

        Ok(())
    }

    async fn send_heartbeat(&self) -> Result<()> {
        let uptime = self.start_time.elapsed_secs() as u64;

        // Get hostname from environment or system
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());

        let metadata = HeartbeatMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
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

        // Collect equipment that needs polling
        let equipment_to_poll: Vec<_> = config
            .equipment
            .iter()
            .filter(|eq| eq.snmp.enabled)
            .filter(|eq| {
                match poll_times.get(&eq.id) {
                    Some(last_poll) => {
                        let elapsed = last_poll.elapsed_secs() as u64;
                        elapsed >= eq.poll_interval_seconds
                    }
                    None => true, // Never polled before
                }
            })
            .collect();

        if equipment_to_poll.is_empty() {
            return Ok(());
        }

        info!(
            "Polling {} equipment items in parallel",
            equipment_to_poll.len()
        );

        // Limit concurrent polling to prevent overwhelming the system
        // With 10,000+ equipment, we don't want 10,000 concurrent tasks
        const MAX_CONCURRENT_POLLS: usize = 100;
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_POLLS));

        // Spawn parallel polling tasks with concurrency limit
        let mut tasks = Vec::new();
        for equipment in equipment_to_poll {
            let executor = self.executor.clone();
            let storage = self.storage.clone();
            let equipment = equipment.clone();
            let permit = semaphore.clone();

            let task = tokio::spawn(async move {
                // Acquire permit before polling (limits concurrency)
                let _permit = permit.acquire().await.unwrap();

                info!("Polling equipment: {}", equipment.name);

                // Poll sensors and interfaces in parallel
                let (sensor_result, interface_result) = tokio::join!(
                    executor.poll_sensors(&equipment),
                    executor.poll_interfaces(&equipment)
                );

                if let Err(e) = sensor_result {
                    error!("Failed to poll sensors for {}: {}", equipment.name, e);
                }

                if let Err(e) = interface_result {
                    error!("Failed to poll interfaces for {}: {}", equipment.name, e);
                }

                // Update last poll time
                if let Err(e) = storage.update_last_poll_time(&equipment.id) {
                    error!("Failed to update last poll time: {}", e);
                }
            });

            tasks.push(task);
        }

        // Wait for all polling tasks to complete
        for task in tasks {
            if let Err(e) = task.await {
                error!("Polling task failed: {}", e);
            }
        }

        Ok(())
    }

    async fn check_and_update(&self) {
        info!("Checking for agent updates");

        // Run version check in blocking thread to avoid blocking event loop
        let result = tokio::task::spawn_blocking(crate::version::perform_self_update).await;

        match result {
            Ok(Ok(true)) => {
                info!("Update initiated, container will restart with new version");
                // perform_self_update calls std::process::exit(0), so we won't reach here
            }
            Ok(Ok(false)) => {
                info!("Already running latest version");
            }
            Ok(Err(e)) => {
                warn!("Failed to perform self-update: {}", e);
            }
            Err(e) => {
                error!("Update check task failed: {}", e);
            }
        }
    }
}
