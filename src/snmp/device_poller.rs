use super::client::SnmpClient;
use super::types::{SnmpError, SnmpResult, SnmpValue};
use super::V3Config;
use crate::secret::SecretString;
use tokio::sync::{mpsc, oneshot};

/// Request to perform an SNMP operation
#[derive(Debug)]
pub enum SnmpRequest {
    Get {
        oid: String,
        response_tx: oneshot::Sender<SnmpResult<SnmpValue>>,
    },
    Walk {
        base_oid: String,
        response_tx: oneshot::Sender<SnmpResult<Vec<(String, SnmpValue)>>>,
    },
    Shutdown,
}

/// Configuration for a device poller
#[derive(Clone)]
pub struct DeviceConfig {
    pub ip: String,
    pub port: u16,
    pub version: String,
    pub community: SecretString,
    pub v3_config: Option<V3Config>,
    pub transport: String,
}

impl std::fmt::Debug for DeviceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceConfig")
            .field("ip", &self.ip)
            .field("port", &self.port)
            .field("version", &self.version)
            .field("transport", &self.transport)
            .field("community", &"[REDACTED]")
            .field("v3_config", &self.v3_config)
            .finish()
    }
}

/// Per-device polling thread that uses C FFI to libnetsnmp
pub struct DevicePoller {
    device_id: String,
    config: DeviceConfig,
    request_tx: mpsc::UnboundedSender<SnmpRequest>,
}

impl DevicePoller {
    /// Spawn a new device poller thread
    pub fn spawn(device_id: String, config: DeviceConfig) -> Self {
        let (request_tx, request_rx) = mpsc::unbounded_channel();

        let device_id_clone = device_id.clone();
        let config_clone = config.clone();

        // Spawn the polling thread with 8MB stack for SNMPv3 crypto operations
        tracing::info!(
            "Spawning device poller thread for {} at {}:{}",
            device_id,
            config.ip,
            config.port
        );
        std::thread::Builder::new()
            .name(format!("poller-{}", device_id))
            .stack_size(8 * 1024 * 1024) // 8MB stack (default is 2MB)
            .spawn(move || {
                tracing::info!("Device poller thread starting for {}", device_id_clone);
                if let Err(e) = run_poller_thread(device_id_clone.clone(), config_clone, request_rx)
                {
                    tracing::error!("Device poller thread failed for {}: {}", device_id_clone, e);
                }
                tracing::info!("Device poller thread exited for {}", device_id_clone);
            })
            .expect("Failed to spawn device poller thread");

        tracing::info!(
            "Successfully spawned device poller thread for {}",
            device_id
        );

        Self {
            device_id,
            config,
            request_tx,
        }
    }

    /// Send a GET request to the poller thread
    pub async fn get(&self, oid: String) -> SnmpResult<SnmpValue> {
        let (response_tx, response_rx) = oneshot::channel();

        self.request_tx
            .send(SnmpRequest::Get { oid, response_tx })
            .map_err(|_| SnmpError::RequestFailed("Poller thread died".into()))?;

        response_rx
            .await
            .map_err(|_| SnmpError::RequestFailed("Poller thread didn't respond".into()))?
    }

    /// Send a WALK request to the poller thread
    pub async fn walk(&self, base_oid: String) -> SnmpResult<Vec<(String, SnmpValue)>> {
        let (response_tx, response_rx) = oneshot::channel();

        self.request_tx
            .send(SnmpRequest::Walk {
                base_oid,
                response_tx,
            })
            .map_err(|_| SnmpError::RequestFailed("Poller thread died".into()))?;

        response_rx
            .await
            .map_err(|_| SnmpError::RequestFailed("Poller thread didn't respond".into()))?
    }

    /// Shutdown the poller thread
    pub fn shutdown(&self) {
        let _ = self.request_tx.send(SnmpRequest::Shutdown);
    }

    /// Get the device config
    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    /// Log the status of this poller (for debugging)
    pub fn log_status(&self) {
        tracing::debug!(
            "Poller status: device_id={}, ip={}:{}",
            self.device_id,
            self.config.ip,
            self.config.port
        );
    }
}

/// Run the poller thread using C FFI to libnetsnmp
fn run_poller_thread(
    device_id: String,
    config: DeviceConfig,
    mut request_rx: mpsc::UnboundedReceiver<SnmpRequest>,
) -> Result<(), String> {
    tracing::info!(
        "Device poller thread started for {} at {}:{}",
        device_id,
        config.ip,
        config.port
    );

    // Create a tokio runtime for this thread (SnmpClient uses async)
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create tokio runtime: {}", e))?;

    // Create SNMP client (stateless, uses C FFI)
    let client = SnmpClient::new();

    // Process requests until shutdown
    while let Some(request) = request_rx.blocking_recv() {
        let is_shutdown = matches!(request, SnmpRequest::Shutdown);

        // Log what request we're processing
        match &request {
            SnmpRequest::Get { oid, .. } => {
                tracing::debug!("Poller thread {} processing GET {}", device_id, oid);
            }
            SnmpRequest::Walk { base_oid, .. } => {
                tracing::debug!("Poller thread {} processing WALK {}", device_id, base_oid);
            }
            SnmpRequest::Shutdown => {
                tracing::info!("Poller thread {} received shutdown signal", device_id);
            }
        }

        let panic_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match request {
                SnmpRequest::Get { oid, response_tx } => {
                    tracing::debug!("Poller thread {} executing GET", device_id);
                    let result = perform_get(&runtime, &client, &config, &oid);
                    tracing::debug!(
                        "Poller thread {} GET result: {:?}",
                        device_id,
                        result.is_ok()
                    );
                    let _ = response_tx.send(result);
                }
                SnmpRequest::Walk {
                    base_oid,
                    response_tx,
                } => {
                    tracing::debug!("Poller thread {} executing WALK", device_id);
                    let result = perform_walk(&runtime, &client, &config, &base_oid);
                    tracing::debug!(
                        "Poller thread {} WALK result: {:?}",
                        device_id,
                        result.as_ref().map(|v| v.len())
                    );
                    let _ = response_tx.send(result);
                }
                SnmpRequest::Shutdown => {
                    tracing::info!("Device poller thread shutting down for {}", device_id);
                }
            }));

        if let Err(panic_err) = panic_result {
            let panic_msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            tracing::error!(
                "Panic in device poller thread for {}: {}",
                device_id,
                panic_msg
            );
            // Don't break - keep the thread alive for future requests
        } else {
            tracing::debug!("Poller thread {} completed request successfully", device_id);
        }

        if is_shutdown {
            tracing::info!("Poller thread {} exiting due to shutdown", device_id);
            break;
        }
    }

    tracing::info!("Device poller thread stopped for {}", device_id);
    Ok(())
}

/// Perform SNMP GET using C FFI
fn perform_get(
    runtime: &tokio::runtime::Runtime,
    client: &SnmpClient,
    config: &DeviceConfig,
    oid: &str,
) -> SnmpResult<SnmpValue> {
    // Use the thread-local runtime to execute async C FFI call
    runtime.block_on(async {
        client
            .get(
                &config.ip,
                config.community.expose(),
                &config.version,
                config.port,
                oid,
                config.v3_config.clone(),
            )
            .await
    })
}

/// Perform SNMP WALK using C FFI
fn perform_walk(
    runtime: &tokio::runtime::Runtime,
    client: &SnmpClient,
    config: &DeviceConfig,
    base_oid: &str,
) -> SnmpResult<Vec<(String, SnmpValue)>> {
    // Use the thread-local runtime to execute async C FFI call
    runtime.block_on(async {
        client
            .walk(
                &config.ip,
                config.community.expose(),
                &config.version,
                config.port,
                base_oid,
                config.v3_config.clone(),
            )
            .await
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_config_debug() {
        let config = DeviceConfig {
            ip: "192.168.1.1".to_string(),
            port: 161,
            version: "2c".to_string(),
            community: SecretString::new("public"),
            v3_config: None,
            transport: "udp".to_string(),
        };

        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("public"));
    }
}
