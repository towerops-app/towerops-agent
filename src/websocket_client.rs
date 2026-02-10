/// WebSocket-based agent client for Towerops.
///
/// This replaces the complex REST API + polling architecture with a single
/// persistent WebSocket connection. The server sends SNMP query jobs as protobuf
/// messages, the agent executes raw SNMP queries, and sends results back.
///
/// Connection URL: {url}/socket/agent/websocket
/// Authentication: Token sent in Phoenix channel join payload
use crate::secret::SecretString;
use futures::stream::SplitStream;
use futures::{SinkExt, StreamExt};
use prost::Message;
use std::collections::HashMap;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, timeout, Duration};
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};
use zeroize::Zeroize;

/// Connection timeout for WebSocket establishment (30 seconds)
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

use crate::proto::agent::{
    AgentHeartbeat, AgentJob, AgentJobList, CredentialTestResult, JobType, MikrotikResult,
    MikrotikSentence, MonitoringCheck, QueryType, SnmpResult,
};
use crate::snmp::{DeviceConfig, PollerRegistry, SnmpValue};

/// Phoenix channel message format (JSON wrapper around binary protobuf).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PhoenixMessage {
    topic: String,
    event: String,
    payload: serde_json::Value,
    #[serde(rename = "ref")]
    reference: Option<String>,
}

/// Channel capacity for result backpressure. If the WebSocket write side
/// falls behind, job tasks will slow down rather than consuming unbounded memory.
const RESULT_CHANNEL_CAPACITY: usize = 1000;

/// Channel capacity for outgoing WebSocket messages routed through the writer task.
const WS_WRITE_CHANNEL_CAPACITY: usize = 500;

/// WebSocket client for agent communication.
///
/// The WebSocket stream is split into a read half (owned here) and a write half
/// (owned by a dedicated writer task). All outgoing messages are sent through
/// `ws_write_tx`, allowing reads and writes to proceed concurrently.
pub struct AgentClient {
    ws_read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    ws_write_tx: mpsc::Sender<WsMessage>,
    agent_id: String,
    result_tx: mpsc::Sender<SnmpResult>,
    result_rx: mpsc::Receiver<SnmpResult>,
    mikrotik_result_tx: mpsc::Sender<MikrotikResult>,
    mikrotik_result_rx: mpsc::Receiver<MikrotikResult>,
    credential_test_tx: mpsc::Sender<CredentialTestResult>,
    credential_test_rx: mpsc::Receiver<CredentialTestResult>,
    monitoring_check_tx: mpsc::Sender<MonitoringCheck>,
    monitoring_check_rx: mpsc::Receiver<MonitoringCheck>,
    poller_registry: PollerRegistry,
    /// Counter for Phoenix transport heartbeat refs
    phx_heartbeat_ref: u64,
    /// Cached hostname (computed once at startup, avoids blocking /proc reads)
    cached_hostname: String,
}

impl AgentClient {
    /// Connect to Towerops server via WebSocket.
    ///
    /// # Arguments
    /// * `url` - Server URL (e.g., "wss://towerops.net")
    /// * `token` - Agent authentication token
    pub async fn connect(url: &str, token: &SecretString) -> Result<Self> {
        // Strip trailing slash from base URL to avoid double slashes
        let base_url = url.trim_end_matches('/');
        let ws_url = format!("{}/socket/agent/websocket", base_url);
        tracing::info!(
            "Connecting to WebSocket: {} (timeout: {}s)",
            ws_url,
            CONNECTION_TIMEOUT.as_secs()
        );

        // Wrap connection in timeout to avoid hanging indefinitely on bad network
        let (ws_stream, _) = match timeout(CONNECTION_TIMEOUT, connect_async(&ws_url)).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                tracing::error!("WebSocket connection failed: {}", e);
                return Err(format!("Failed to connect to WebSocket: {}", e).into());
            }
            Err(_) => {
                tracing::error!(
                    "WebSocket connection timed out after {}s",
                    CONNECTION_TIMEOUT.as_secs()
                );
                return Err(format!(
                    "Connection timed out after {}s",
                    CONNECTION_TIMEOUT.as_secs()
                )
                .into());
            }
        };

        tracing::info!("Connected to Towerops server at {}", url);

        let agent_id = generate_agent_id();
        let (result_tx, result_rx) = mpsc::channel(RESULT_CHANNEL_CAPACITY);
        let (mikrotik_result_tx, mikrotik_result_rx) = mpsc::channel(RESULT_CHANNEL_CAPACITY);
        let (credential_test_tx, credential_test_rx) = mpsc::channel(RESULT_CHANNEL_CAPACITY);
        let (monitoring_check_tx, monitoring_check_rx) = mpsc::channel(RESULT_CHANNEL_CAPACITY);

        // Split the WebSocket stream so reads and writes can proceed concurrently.
        // The write half is owned by a dedicated writer task.
        let (ws_write, ws_read) = ws_stream.split();
        let (ws_write_tx, ws_write_rx) = mpsc::channel::<WsMessage>(WS_WRITE_CHANNEL_CAPACITY);

        tokio::spawn(ws_writer_task(ws_write, ws_write_rx));

        // Join Phoenix channel with token in payload
        let join_msg = PhoenixMessage {
            topic: format!("agent:{}", agent_id),
            event: "phx_join".to_string(),
            payload: serde_json::json!({"token": token.expose()}),
            reference: Some("1".to_string()),
        };

        let join_text = serde_json::to_string(&join_msg)?;
        ws_write_tx
            .send(WsMessage::Text(join_text.into()))
            .await
            .map_err(|e| format!("Failed to send join message: {}", e))?;
        tracing::info!(
            "Sent channel join request with token for agent:{}",
            agent_id
        );

        Ok(Self {
            ws_read,
            ws_write_tx,
            agent_id,
            result_tx,
            result_rx,
            mikrotik_result_tx,
            mikrotik_result_rx,
            credential_test_tx,
            credential_test_rx,
            monitoring_check_tx,
            monitoring_check_rx,
            poller_registry: PollerRegistry::new(),
            phx_heartbeat_ref: 0,
            cached_hostname: get_hostname(),
        })
    }

    /// Main event loop for agent operation.
    ///
    /// Handles:
    /// - Receiving jobs from server
    /// - Executing SNMP queries
    /// - Sending results back
    /// - Periodic heartbeats
    /// - Graceful shutdown on SIGTERM
    pub async fn run(&mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let mut heartbeat_interval = interval(Duration::from_secs(60));
        let mut phx_heartbeat_interval = interval(Duration::from_secs(25));

        loop {
            tokio::select! {
                // Check for shutdown signal (highest priority)
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Shutdown signal received, closing WebSocket connection gracefully");
                        // Send close frame through the writer task
                        let _ = self.ws_write_tx.send(WsMessage::Close(None)).await;
                        break Ok(());
                    }
                }

                // Receive messages from server
                msg = self.ws_read.next() => {
                    match msg {
                        Some(Ok(WsMessage::Binary(data))) => {
                            if let Err(e) = self.handle_message(&data).await {
                                tracing::error!("Error handling binary message: {}", e);
                            }
                        }
                        Some(Ok(WsMessage::Text(text))) => {
                            if let Err(e) = self.handle_text_message(&text).await {
                                tracing::error!("Error handling text message: {}", e);
                            }
                        }
                        Some(Ok(WsMessage::Close(_))) => {
                            tracing::info!("Server closed connection");
                            self.poller_registry.shutdown_all();
                            break Ok(());
                        }
                        Some(Err(e)) => {
                            tracing::error!("WebSocket error: {}", e);
                            self.poller_registry.shutdown_all();
                            break Err(e.into());
                        }
                        None => {
                            tracing::info!("Connection closed");
                            self.poller_registry.shutdown_all();
                            break Ok(());
                        }
                        _ => {}
                    }
                }

                // Receive SNMP results from job tasks
                Some(snmp_result) = self.result_rx.recv() => {
                    if let Err(e) = self.send_snmp_result(snmp_result).await {
                        tracing::error!("Error sending SNMP result: {}", e);
                    }
                }

                // Receive MikroTik results from job tasks
                Some(mikrotik_result) = self.mikrotik_result_rx.recv() => {
                    if let Err(e) = self.send_mikrotik_result(mikrotik_result).await {
                        tracing::error!("Error sending MikroTik result: {}", e);
                    }
                }

                // Receive credential test results from job tasks
                Some(credential_test_result) = self.credential_test_rx.recv() => {
                    if let Err(e) = self.send_credential_test_result(credential_test_result).await {
                        tracing::error!("Error sending credential test result: {}", e);
                    }
                }

                // Receive monitoring check results from job tasks
                Some(monitoring_check) = self.monitoring_check_rx.recv() => {
                    if let Err(e) = self.send_monitoring_check(monitoring_check).await {
                        tracing::error!("Error sending monitoring check: {}", e);
                    }
                }

                // Send periodic heartbeats
                _ = heartbeat_interval.tick() => {
                    if let Err(e) = self.send_heartbeat().await {
                        tracing::error!("Error sending heartbeat: {}", e);
                    }
                    // Log active poller count
                    let count = self.poller_registry.count();
                    if count > 0 {
                        tracing::debug!("Active device pollers: {}", count);
                    }
                }

                // Send Phoenix transport heartbeats to keep connection alive
                _ = phx_heartbeat_interval.tick() => {
                    if let Err(e) = self.send_phx_heartbeat().await {
                        tracing::error!("Error sending Phoenix heartbeat: {}", e);
                    }
                }
            }
        }
    }

    /// Handle Phoenix channel message (JSON-wrapped).
    async fn handle_text_message(&mut self, text: &str) -> Result<()> {
        let phoenix_msg: PhoenixMessage = serde_json::from_str(text)?;

        match phoenix_msg.event.as_str() {
            "phx_reply" => {
                tracing::info!("Channel join reply: {:?}", phoenix_msg.payload);
            }
            // Handle all job events the same way - agent doesn't care about the context
            "jobs" | "discovery_job" | "backup_job" => {
                // Extract binary protobuf from payload
                if let serde_json::Value::Object(map) = phoenix_msg.payload {
                    if let Some(serde_json::Value::String(binary_b64)) = map.get("binary") {
                        let binary = base64_decode(binary_b64)?;
                        let job_list = AgentJobList::decode(&binary[..])?;
                        self.handle_jobs(job_list).await?;
                    }
                }
            }
            _ => {
                tracing::debug!("Ignoring unknown event: {}", phoenix_msg.event);
            }
        }

        Ok(())
    }

    /// Handle binary protobuf message.
    async fn handle_message(&self, data: &[u8]) -> Result<()> {
        // Try to decode as AgentJobList
        if let Ok(job_list) = AgentJobList::decode(data) {
            self.handle_jobs(job_list).await?;
        }

        Ok(())
    }

    /// Process job list from server.
    ///
    /// Each job is executed once in the background and results are sent back.
    /// No long-running tasks are spawned - the agent is stateless.
    /// Server handles all scheduling and retries via Oban.
    async fn handle_jobs(&self, job_list: AgentJobList) -> Result<()> {
        tracing::info!("Received {} jobs from server", job_list.jobs.len());

        // Collect device IDs from current jobs
        let mut current_device_ids = std::collections::HashSet::new();
        for job in &job_list.jobs {
            current_device_ids.insert(job.device_id.clone());
        }

        // Clean up pollers for devices no longer in job list
        let active_devices = self.poller_registry.list_devices();
        for device_id in active_devices {
            if !current_device_ids.contains(&device_id) {
                tracing::debug!(
                    "Removing poller for device no longer in job list: {}",
                    device_id
                );
                self.poller_registry.remove(&device_id);
            }
        }

        for job in job_list.jobs {
            let job_type = JobType::try_from(job.job_type).unwrap_or(JobType::Poll);
            tracing::info!("Executing job: {} (type: {:?})", job.job_id, job_type);

            match job_type {
                JobType::Mikrotik => {
                    // Execute MikroTik API job
                    let mikrotik_result_tx = self.mikrotik_result_tx.clone();

                    tokio::spawn(async move {
                        if let Err(e) = execute_mikrotik_job(job, mikrotik_result_tx).await {
                            tracing::error!("MikroTik job execution failed: {}", e);
                        }
                    });
                }
                JobType::TestCredentials => {
                    // Execute credential test
                    let credential_test_tx = self.credential_test_tx.clone();

                    tokio::spawn(async move {
                        if let Err(e) = execute_credential_test(job, credential_test_tx).await {
                            tracing::error!("Credential test execution failed: {}", e);
                        }
                    });
                }
                JobType::Ping => {
                    // Execute ICMP ping health check
                    let monitoring_check_tx = self.monitoring_check_tx.clone();

                    tokio::spawn(async move {
                        if let Err(e) = execute_ping_job(job, monitoring_check_tx).await {
                            tracing::error!("Ping job execution failed: {}", e);
                        }
                    });
                }
                _ => {
                    // Execute SNMP job (discovery or polling)
                    let result_tx = self.result_tx.clone();
                    let poller_registry = self.poller_registry.clone();

                    tokio::spawn(async move {
                        if let Err(e) = execute_snmp_job(job, result_tx, poller_registry).await {
                            tracing::error!("SNMP job execution failed: {}", e);
                        }
                    });
                }
            }
        }

        Ok(())
    }

    /// Send heartbeat to server.
    async fn send_heartbeat(&mut self) -> Result<()> {
        let heartbeat = AgentHeartbeat {
            version: crate::version::current_version().to_string(),
            hostname: self.cached_hostname.clone(),
            uptime_seconds: get_uptime_seconds(),
            ip_address: get_local_ip().unwrap_or_default(),
        };

        let binary = heartbeat.encode_to_vec();

        // Phoenix channel format
        let msg = PhoenixMessage {
            topic: format!("agent:{}", self.agent_id),
            event: "heartbeat".to_string(),
            payload: serde_json::json!({"binary": base64_encode(&binary)}),
            reference: None,
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_write_tx
            .send(WsMessage::Text(text.into()))
            .await
            .map_err(|e| format!("Writer task closed: {}", e))?;

        tracing::debug!("Sent heartbeat");
        Ok(())
    }

    /// Send Phoenix transport heartbeat to keep the WebSocket connection alive.
    ///
    /// This is separate from the application heartbeat. Phoenix's transport layer
    /// expects periodic messages on the "phoenix" topic to detect dead connections.
    async fn send_phx_heartbeat(&mut self) -> Result<()> {
        self.phx_heartbeat_ref += 1;

        let msg = PhoenixMessage {
            topic: "phoenix".to_string(),
            event: "heartbeat".to_string(),
            payload: serde_json::json!({}),
            reference: Some(self.phx_heartbeat_ref.to_string()),
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_write_tx
            .send(WsMessage::Text(text.into()))
            .await
            .map_err(|e| format!("Writer task closed: {}", e))?;

        tracing::debug!(
            "Sent Phoenix transport heartbeat (ref: {})",
            self.phx_heartbeat_ref
        );
        Ok(())
    }

    /// Send SNMP results to server.
    async fn send_snmp_result(&mut self, result: SnmpResult) -> Result<()> {
        let binary = result.encode_to_vec();

        let msg = PhoenixMessage {
            topic: format!("agent:{}", self.agent_id),
            event: "result".to_string(),
            payload: serde_json::json!({"binary": base64_encode(&binary)}),
            reference: None,
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_write_tx
            .send(WsMessage::Text(text.into()))
            .await
            .map_err(|e| format!("Writer task closed: {}", e))?;

        tracing::debug!("Sent SNMP result for device {}", result.device_id);
        Ok(())
    }

    /// Send MikroTik results to server.
    async fn send_mikrotik_result(&mut self, result: MikrotikResult) -> Result<()> {
        let binary = result.encode_to_vec();

        let msg = PhoenixMessage {
            topic: format!("agent:{}", self.agent_id),
            event: "mikrotik_result".to_string(),
            payload: serde_json::json!({"binary": base64_encode(&binary)}),
            reference: None,
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_write_tx
            .send(WsMessage::Text(text.into()))
            .await
            .map_err(|e| format!("Writer task closed: {}", e))?;

        tracing::debug!(
            "Sent MikroTik result for device {} (job: {})",
            result.device_id,
            result.job_id
        );
        Ok(())
    }

    /// Send credential test result to server.
    async fn send_credential_test_result(&mut self, result: CredentialTestResult) -> Result<()> {
        let binary = result.encode_to_vec();

        let msg = PhoenixMessage {
            topic: format!("agent:{}", self.agent_id),
            event: "credential_test_result".to_string(),
            payload: serde_json::json!({"binary": base64_encode(&binary)}),
            reference: None,
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_write_tx
            .send(WsMessage::Text(text.into()))
            .await
            .map_err(|e| format!("Writer task closed: {}", e))?;

        tracing::info!(
            "Sent credential test result (test_id: {}, success: {})",
            result.test_id,
            result.success
        );
        Ok(())
    }

    /// Send monitoring check result to server.
    async fn send_monitoring_check(&mut self, result: MonitoringCheck) -> Result<()> {
        let binary = result.encode_to_vec();

        let msg = PhoenixMessage {
            topic: format!("agent:{}", self.agent_id),
            event: "monitoring_check".to_string(),
            payload: serde_json::json!({"binary": base64_encode(&binary)}),
            reference: None,
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_write_tx
            .send(WsMessage::Text(text.into()))
            .await
            .map_err(|e| format!("Writer task closed: {}", e))?;

        tracing::debug!(
            "Sent monitoring check for device {} (status: {})",
            result.device_id,
            result.status
        );
        Ok(())
    }
}

/// Dedicated writer task that owns the WebSocket write half.
///
/// All outgoing messages are funnelled through an mpsc channel, allowing the
/// main event loop to continue reading while writes are in progress.
async fn ws_writer_task(
    mut ws_sink: futures::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>,
    mut rx: mpsc::Receiver<WsMessage>,
) {
    while let Some(msg) = rx.recv().await {
        let is_close = matches!(msg, WsMessage::Close(_));
        if let Err(e) = ws_sink.send(msg).await {
            tracing::error!("WebSocket write error: {}", e);
            break;
        }
        if is_close {
            break;
        }
    }
    tracing::debug!("WebSocket writer task stopped");
}

/// Redact SNMP community string for logging.
fn redact_community(community: &str) -> &'static str {
    if community.is_empty() {
        "(empty)"
    } else {
        "***"
    }
}

/// Execute an SNMP job and collect results.
async fn execute_snmp_job(
    job: AgentJob,
    result_tx: mpsc::Sender<SnmpResult>,
    poller_registry: PollerRegistry,
) -> Result<()> {
    let mut snmp_device = job.snmp_device.ok_or("Job missing SNMP device info")?;

    // Build v3 config if version is "3"
    let v3_config = if snmp_device.version == "3" {
        let config = crate::snmp::V3Config {
            username: snmp_device.v3_username.clone(),
            auth_password: if !snmp_device.v3_auth_password.is_empty() {
                Some(zeroize::Zeroizing::new(
                    snmp_device.v3_auth_password.clone(),
                ))
            } else {
                None
            },
            priv_password: if !snmp_device.v3_priv_password.is_empty() {
                Some(zeroize::Zeroizing::new(
                    snmp_device.v3_priv_password.clone(),
                ))
            } else {
                None
            },
            auth_protocol: if !snmp_device.v3_auth_protocol.is_empty() {
                Some(snmp_device.v3_auth_protocol.clone())
            } else {
                None
            },
            priv_protocol: if !snmp_device.v3_priv_protocol.is_empty() {
                Some(snmp_device.v3_priv_protocol.clone())
            } else {
                None
            },
            security_level: snmp_device.v3_security_level.clone(),
        };

        Some(config)
    } else {
        None
    };

    // Log SNMP connection parameters for debugging (mask community for security)
    let community_masked = redact_community(&snmp_device.community);

    tracing::info!(
        "Executing SNMP job for device {} at {}:{} (community: {}, version: {})",
        job.device_id,
        snmp_device.ip,
        snmp_device.port,
        community_masked,
        snmp_device.version
    );

    // Build device config and get or create persistent poller
    let device_config = DeviceConfig {
        ip: snmp_device.ip.clone(),
        port: snmp_device.port as u16,
        version: snmp_device.version.clone(),
        community: SecretString::new(snmp_device.community.clone()),
        v3_config,
        transport: if snmp_device.transport.is_empty() {
            "udp".to_string()
        } else {
            snmp_device.transport.clone()
        },
    };

    // Zeroize credentials in protobuf message after extraction
    snmp_device.community.zeroize();
    snmp_device.v3_auth_password.zeroize();
    snmp_device.v3_priv_password.zeroize();

    let poller = poller_registry.get_or_create(job.device_id.clone(), device_config);

    let mut oid_values: HashMap<String, String> = HashMap::new();

    for query in job.queries {
        let query_type = QueryType::try_from(query.query_type).unwrap_or(QueryType::Get);

        match query_type {
            QueryType::Get => {
                // Execute SNMP GET for each OID
                for oid in &query.oids {
                    match poller.get(oid.clone()).await {
                        Ok(value) => {
                            oid_values.insert(oid.clone(), value_to_string(value));
                        }
                        Err(e) => {
                            tracing::warn!(
                                "SNMP GET failed for device {} at {}:{} (version: {}, community: {}), OID {}: {}",
                                job.device_id,
                                snmp_device.ip,
                                snmp_device.port,
                                snmp_device.version,
                                community_masked,
                                oid,
                                e
                            );
                        }
                    }
                }
            }
            QueryType::Walk => {
                // Execute SNMP WALK for each base OID
                for base_oid in &query.oids {
                    match poller.walk(base_oid.clone()).await {
                        Ok(results) => {
                            for (oid, value) in results {
                                oid_values.insert(oid, value_to_string(value));
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "SNMP WALK failed for device {} at {}:{} (version: {}, community: {}), OID {}: {}",
                                job.device_id,
                                snmp_device.ip,
                                snmp_device.port,
                                snmp_device.version,
                                community_masked,
                                base_oid,
                                e
                            );
                        }
                    }
                }
            }
        }
    }

    // Build result
    let result = SnmpResult {
        device_id: job.device_id.clone(),
        job_type: job.job_type,
        job_id: job.job_id.clone(),
        oid_values,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64,
    };

    tracing::info!(
        "Collected {} OID values for job {}",
        result.oid_values.len(),
        job.job_id
    );

    // Send result back to main client task
    if let Err(e) = result_tx.send(result).await {
        tracing::warn!(
            "Failed to send SNMP result for job {}: channel closed (connection may have dropped)",
            job.job_id
        );
        return Err(format!("Result channel closed: {}", e).into());
    }

    Ok(())
}

/// Execute a credential test job.
///
/// Tests SNMP credentials by performing a simple GET on sysDescr.0.
/// Returns success with system description or failure with error message.
async fn execute_credential_test(
    job: AgentJob,
    result_tx: mpsc::Sender<CredentialTestResult>,
) -> Result<()> {
    let mut snmp_device = job.snmp_device.ok_or("Job missing SNMP device info")?;

    tracing::info!(
        "Testing SNMP credentials for {}:{} (version: {})",
        snmp_device.ip,
        snmp_device.port,
        snmp_device.version
    );

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    // Build v3 config if version is "3"
    let v3_config = if snmp_device.version == "3" {
        Some(crate::snmp::V3Config {
            username: snmp_device.v3_username.clone(),
            auth_password: if !snmp_device.v3_auth_password.is_empty() {
                Some(zeroize::Zeroizing::new(
                    snmp_device.v3_auth_password.clone(),
                ))
            } else {
                None
            },
            priv_password: if !snmp_device.v3_priv_password.is_empty() {
                Some(zeroize::Zeroizing::new(
                    snmp_device.v3_priv_password.clone(),
                ))
            } else {
                None
            },
            auth_protocol: if !snmp_device.v3_auth_protocol.is_empty() {
                Some(snmp_device.v3_auth_protocol.clone())
            } else {
                None
            },
            priv_protocol: if !snmp_device.v3_priv_protocol.is_empty() {
                Some(snmp_device.v3_priv_protocol.clone())
            } else {
                None
            },
            security_level: snmp_device.v3_security_level.clone(),
        })
    } else {
        None
    };

    // Zeroize credentials in protobuf message after extraction
    snmp_device.community.zeroize();
    snmp_device.v3_auth_password.zeroize();
    snmp_device.v3_priv_password.zeroize();

    // Create a temporary SNMP client for testing (don't use persistent poller)
    let snmp_client = crate::snmp::SnmpClient::new();

    // Test with sysDescr.0 (standard system description OID)
    let test_oid = "1.3.6.1.2.1.1.1.0".to_string();

    let result = match snmp_client
        .get(
            &snmp_device.ip,
            &snmp_device.community,
            &snmp_device.version,
            snmp_device.port as u16,
            &test_oid,
            v3_config,
        )
        .await
    {
        Ok(value) => {
            let sys_descr = value_to_string(value);
            tracing::info!("✓ Credential test succeeded: {}", sys_descr);

            CredentialTestResult {
                test_id: job.job_id.clone(),
                success: true,
                error_message: String::new(),
                system_description: sys_descr,
                timestamp,
            }
        }
        Err(e) => {
            let error_msg = format!("SNMP test failed: {}", e);
            tracing::warn!("✗ Credential test failed: {}", error_msg);

            CredentialTestResult {
                test_id: job.job_id.clone(),
                success: false,
                error_message: error_msg,
                system_description: String::new(),
                timestamp,
            }
        }
    };

    // Send result back to main client task
    if let Err(e) = result_tx.send(result).await {
        tracing::warn!(
            "Failed to send credential test result for job {}: channel closed",
            job.job_id
        );
        return Err(format!("Result channel closed: {}", e).into());
    }

    Ok(())
}

/// Execute a ping job using ICMP ping to check device health.
async fn execute_ping_job(job: AgentJob, result_tx: mpsc::Sender<MonitoringCheck>) -> Result<()> {
    let device_id = job.device_id.clone();
    let snmp_device = job.snmp_device.ok_or("Job missing SNMP device info")?;
    let ip_address = &snmp_device.ip;

    // Use 5-second timeout for pings (same as Phoenix DeviceMonitorWorker)
    let timeout_ms = 5000;

    tracing::debug!(
        "Executing health check for device {} at {}",
        device_id,
        ip_address
    );

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    // Execute ping
    let result = match crate::ping::ping_device(ip_address, timeout_ms).await {
        Ok(response_time_ms) => {
            tracing::info!(
                "✓ Device {} is up (response time: {:.1}ms)",
                device_id,
                response_time_ms
            );

            MonitoringCheck {
                device_id: device_id.clone(),
                status: "success".to_string(),
                response_time_ms,
                timestamp,
            }
        }
        Err(e) => {
            tracing::warn!("✗ Device {} is down: {}", device_id, e);

            MonitoringCheck {
                device_id: device_id.clone(),
                status: "failure".to_string(),
                response_time_ms: 0.0,
                timestamp,
            }
        }
    };

    // Send result back to main client task
    if let Err(e) = result_tx.send(result).await {
        tracing::warn!(
            "Failed to send monitoring check for device {}: channel closed",
            device_id
        );
        return Err(format!("Result channel closed: {}", e).into());
    }

    Ok(())
}

/// Execute a MikroTik API job and collect results.
async fn execute_mikrotik_job(
    job: AgentJob,
    result_tx: mpsc::Sender<MikrotikResult>,
) -> Result<()> {
    use crate::mikrotik::MikrotikClient;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    // Check if this is a backup job (job_id starts with "backup:")
    // Backup jobs use SSH instead of API because /export doesn't work via API
    if job.job_id.starts_with("backup:") {
        let mikrotik_device = job
            .mikrotik_device
            .clone()
            .ok_or("Job missing MikroTik device info")?;
        return execute_mikrotik_backup_via_ssh(job, mikrotik_device, result_tx, timestamp).await;
    }

    let mut mikrotik_device = job
        .mikrotik_device
        .ok_or("Job missing MikroTik device info")?;

    tracing::info!(
        "Executing MikroTik job {} for device {} at {}:{} (ssl: {})",
        job.job_id,
        job.device_id,
        mikrotik_device.ip,
        mikrotik_device.port,
        mikrotik_device.use_ssl
    );

    let password = SecretString::new(&mikrotik_device.password);

    // Connect and authenticate to MikroTik RouterOS API
    let mut client = if mikrotik_device.use_ssl {
        match MikrotikClient::connect(
            &mikrotik_device.ip,
            mikrotik_device.port as u16,
            &mikrotik_device.username,
            &password,
        )
        .await
        {
            Ok(client) => client,
            Err(e) => {
                let result = MikrotikResult {
                    device_id: job.device_id,
                    job_id: job.job_id,
                    sentences: vec![],
                    error: format!("Connection failed: {}", e),
                    timestamp,
                };
                let _ = result_tx.send(result).await;
                return Err(format!("MikroTik connection failed: {}", e).into());
            }
        }
    } else {
        match MikrotikClient::connect_plain(
            &mikrotik_device.ip,
            mikrotik_device.port as u16,
            &mikrotik_device.username,
            &password,
        )
        .await
        {
            Ok(client) => client,
            Err(e) => {
                let result = MikrotikResult {
                    device_id: job.device_id,
                    job_id: job.job_id,
                    sentences: vec![],
                    error: format!("Connection failed: {}", e),
                    timestamp,
                };
                let _ = result_tx.send(result).await;
                return Err(format!("MikroTik connection failed: {}", e).into());
            }
        }
    };

    // Zeroize credentials in protobuf message after extraction
    mikrotik_device.password.zeroize();

    // Execute each command and collect results
    let mut all_sentences = Vec::new();
    let mut error_message = String::new();

    for cmd in &job.mikrotik_commands {
        // Convert HashMap<String, String> to Vec<(&str, &str)> for the client API
        let args: Vec<(&str, &str)> = cmd
            .args
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        tracing::debug!(
            "Executing MikroTik command '{}' with {} args: {:?}",
            cmd.command,
            args.len(),
            args
        );

        match client.execute(&cmd.command, &args).await {
            Ok(response) => {
                // Check for error in response
                if let Some(err) = response.error {
                    error_message = format!("Command '{}' error: {}", cmd.command, err);
                    tracing::error!(
                        "MikroTik command error for device {}: {}",
                        job.device_id,
                        error_message
                    );
                    break;
                }

                tracing::debug!(
                    "Command '{}' returned {} sentences",
                    cmd.command,
                    response.sentences.len()
                );

                // Convert sentences to protobuf format and log attribute keys
                for (idx, sentence) in response.sentences.iter().enumerate() {
                    let attr_keys: Vec<&String> = sentence.attributes.keys().collect();
                    let total_size: usize = sentence.attributes.values().map(|v| v.len()).sum();

                    tracing::debug!(
                        "Sentence {}: {} attributes ({} bytes total): {:?}",
                        idx,
                        sentence.attributes.len(),
                        total_size,
                        attr_keys
                    );

                    // Log when we hit EOF during /file/read
                    if cmd.command == "/file/read" {
                        if let Some(data) = sentence.attributes.get("data") {
                            if data.is_empty() {
                                tracing::debug!("Reached end of file (empty chunk)");
                            }
                        }
                    }

                    all_sentences.push(MikrotikSentence {
                        attributes: sentence.attributes.clone(),
                    });
                }
            }
            Err(e) => {
                error_message = format!("Command '{}' failed: {}", cmd.command, e);
                tracing::error!(
                    "MikroTik command failed for device {}: {}",
                    job.device_id,
                    error_message
                );
                break;
            }
        }
    }

    // Build and send result
    let result = MikrotikResult {
        device_id: job.device_id,
        job_id: job.job_id,
        sentences: all_sentences,
        error: error_message,
        timestamp,
    };

    tracing::info!(
        "MikroTik job {} completed with {} sentences",
        result.job_id,
        result.sentences.len()
    );

    let job_id_for_error = result.job_id.clone();
    if let Err(e) = result_tx.send(result).await {
        tracing::warn!(
            "Failed to send MikroTik result for job {}: channel closed",
            job_id_for_error
        );
        return Err(format!("Result channel closed: {}", e).into());
    }

    Ok(())
}

/// Execute a MikroTik backup job via SSH (because /export doesn't work via API).
async fn execute_mikrotik_backup_via_ssh(
    job: AgentJob,
    mut mikrotik_device: crate::proto::agent::MikrotikDevice,
    result_tx: mpsc::Sender<MikrotikResult>,
    timestamp: i64,
) -> Result<()> {
    use crate::ssh::SshClient;

    tracing::info!(
        "Executing backup via SSH for device {} at {}:{} (job: {})",
        job.device_id,
        mikrotik_device.ip,
        mikrotik_device.ssh_port,
        job.job_id
    );

    let password = SecretString::new(mikrotik_device.password.clone());

    // Connect via SSH
    let mut ssh_client = match SshClient::connect(
        &mikrotik_device.ip,
        mikrotik_device.ssh_port,
        &mikrotik_device.username,
        &password,
    )
    .await
    {
        Ok(client) => client,
        Err(e) => {
            let error_msg = format!("SSH connection failed: {}", e);
            tracing::error!("{}", error_msg);
            let result = MikrotikResult {
                device_id: job.device_id,
                job_id: job.job_id,
                sentences: vec![],
                error: error_msg,
                timestamp,
            };
            let _ = result_tx.send(result).await;
            return Err(format!("SSH connection failed: {}", e).into());
        }
    };

    // Execute /export compact command
    let config = match ssh_client.execute_command("/export compact").await {
        Ok(output) => output,
        Err(e) => {
            let error_msg = format!("SSH command failed: {}", e);
            tracing::error!("{}", error_msg);
            let result = MikrotikResult {
                device_id: job.device_id,
                job_id: job.job_id,
                sentences: vec![],
                error: error_msg,
                timestamp,
            };
            let _ = result_tx.send(result).await;
            let _ = ssh_client.close().await;
            return Err(format!("SSH command failed: {}", e).into());
        }
    };

    // Close SSH connection
    let _ = ssh_client.close().await;

    // Zeroize credentials in protobuf message after use
    mikrotik_device.password.zeroize();

    tracing::info!(
        "Backup completed: {} bytes, {} lines",
        config.len(),
        config.lines().count()
    );

    // Return the config as a single sentence with "config" attribute
    let mut attributes = std::collections::HashMap::new();
    attributes.insert("config".to_string(), config);

    let job_id_for_log = job.job_id.clone();

    let result = MikrotikResult {
        device_id: job.device_id,
        job_id: job.job_id,
        sentences: vec![MikrotikSentence { attributes }],
        error: String::new(),
        timestamp,
    };

    tracing::info!(
        "MikroTik backup job {} completed successfully",
        result.job_id
    );

    if let Err(e) = result_tx.send(result).await {
        tracing::warn!(
            "Failed to send MikroTik backup result for job {}: channel closed",
            job_id_for_log
        );
        return Err(format!("Result channel closed: {}", e).into());
    }

    Ok(())
}

/// Convert SnmpValue to String for protobuf transmission.
fn value_to_string(value: SnmpValue) -> String {
    match value {
        SnmpValue::Integer(i) => i.to_string(),
        SnmpValue::String(s) => s,
        SnmpValue::OctetString(bytes) => {
            // Convert to hex string for non-printable data
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":")
        }
        SnmpValue::Oid(oid) => oid,
        SnmpValue::Counter32(c) => c.to_string(),
        SnmpValue::Counter64(c) => c.to_string(),
        SnmpValue::Gauge32(g) => g.to_string(),
        SnmpValue::TimeTicks(t) => t.to_string(),
        SnmpValue::IpAddress(ip) => ip,
        SnmpValue::Null => "null".to_string(),
        SnmpValue::Unsupported(s) => s,
    }
}

/// Base64 encode bytes to string.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let mut buf = [0u8; 3];
        for (i, &byte) in chunk.iter().enumerate() {
            buf[i] = byte;
        }

        result.push(ALPHABET[((buf[0] >> 2) & 0x3F) as usize]);
        result.push(ALPHABET[(((buf[0] << 4) | (buf[1] >> 4)) & 0x3F) as usize]);
        result.push(if chunk.len() > 1 {
            ALPHABET[(((buf[1] << 2) | (buf[2] >> 6)) & 0x3F) as usize]
        } else {
            b'='
        });
        result.push(if chunk.len() > 2 {
            ALPHABET[(buf[2] & 0x3F) as usize]
        } else {
            b'='
        });
    }

    String::from_utf8(result).unwrap()
}

/// Base64 decode string to bytes.
fn base64_decode(encoded: &str) -> Result<Vec<u8>> {
    let mut decode_map = [0xFF; 256];
    for (i, &byte) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        decode_map[byte as usize] = i as u8;
    }

    let input = encoded.as_bytes();
    let mut result = Vec::with_capacity((input.len() / 4) * 3);

    for chunk in input.chunks(4) {
        if chunk.len() < 4 {
            break;
        }

        let mut buf = [0u8; 4];
        for (i, &byte) in chunk.iter().enumerate() {
            if byte == b'=' {
                buf[i] = 0;
            } else {
                let val = decode_map[byte as usize];
                if val == 0xFF {
                    return Err("Invalid base64 character".into());
                }
                buf[i] = val;
            }
        }

        result.push((buf[0] << 2) | (buf[1] >> 4));
        if chunk[2] != b'=' {
            result.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if chunk[3] != b'=' {
            result.push((buf[2] << 6) | buf[3]);
        }
    }

    Ok(result)
}

/// Generate a unique agent ID.
fn generate_agent_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    format!("agent-{}", timestamp)
}

/// Get system hostname.
fn get_hostname() -> String {
    // Try reading from /proc on Linux
    if let Ok(hostname) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        return hostname.trim().to_string();
    }

    // Fallback to "unknown"
    "unknown".to_string()
}

/// Get system uptime in seconds.
fn get_uptime_seconds() -> u64 {
    // Linux: read /proc/uptime (format: "uptime idle")
    if let Ok(uptime_str) = std::fs::read_to_string("/proc/uptime") {
        if let Some(uptime) = uptime_str.split_whitespace().next() {
            if let Ok(secs) = uptime.parse::<f64>() {
                return secs as u64;
            }
        }
    }

    // Fallback
    0
}

/// Get local IP address by connecting a UDP socket to a public address.
/// No data is sent; the OS resolves which local interface would be used.
fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_to_string_integer() {
        let value = SnmpValue::Integer(42);
        assert_eq!(value_to_string(value), "42");
    }

    #[test]
    fn test_value_to_string_string() {
        let value = SnmpValue::String("test".to_string());
        assert_eq!(value_to_string(value), "test");
    }

    #[test]
    fn test_value_to_string_counter32() {
        let value = SnmpValue::Counter32(12345);
        assert_eq!(value_to_string(value), "12345");
    }

    #[test]
    fn test_value_to_string_counter64() {
        let value = SnmpValue::Counter64(9876543210);
        assert_eq!(value_to_string(value), "9876543210");
    }

    #[test]
    fn test_value_to_string_gauge32() {
        let value = SnmpValue::Gauge32(999);
        assert_eq!(value_to_string(value), "999");
    }

    #[test]
    fn test_value_to_string_timeticks() {
        let value = SnmpValue::TimeTicks(12345678);
        assert_eq!(value_to_string(value), "12345678");
    }

    #[test]
    fn test_value_to_string_ip_address() {
        let value = SnmpValue::IpAddress("192.168.1.1".to_string());
        assert_eq!(value_to_string(value), "192.168.1.1");
    }

    #[test]
    fn test_generate_agent_id() {
        let id = generate_agent_id();
        assert!(id.starts_with("agent-"));

        // Verify the timestamp part is a number
        let timestamp_str = id.strip_prefix("agent-").unwrap();
        let timestamp: u64 = timestamp_str.parse().expect("Timestamp should be a number");
        assert!(timestamp > 0);
    }

    #[test]
    fn test_get_uptime_seconds() {
        let uptime = get_uptime_seconds();
        // On Linux with /proc/uptime, should return non-zero
        // On other platforms or if file doesn't exist, returns 0
        // uptime is u64, so always >= 0 - just verify it's callable
        let _ = uptime;
    }

    #[test]
    fn test_get_hostname() {
        let hostname = get_hostname();
        // Should return either the system hostname or "unknown"
        assert!(!hostname.is_empty());
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(base64_decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_get_local_ip() {
        let ip = get_local_ip();
        // Should resolve to a valid local IP via UDP socket trick
        assert!(ip.is_some(), "Expected a local IP address");
        let ip_str = ip.unwrap();
        assert!(!ip_str.is_empty());
        assert_ne!(ip_str, "0.0.0.0");
    }

    #[test]
    fn test_phoenix_message_serialization() {
        let msg = PhoenixMessage {
            topic: "agent:123".to_string(),
            event: "phx_join".to_string(),
            payload: serde_json::json!({"token": "test"}),
            reference: Some("1".to_string()),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("agent:123"));
        assert!(json.contains("phx_join"));
        assert!(json.contains("token"));
        assert!(json.contains("test"));
    }

    #[test]
    fn test_phoenix_message_deserialization() {
        let json =
            r#"{"topic":"agent:123","event":"phx_reply","payload":{"status":"ok"},"ref":"1"}"#;
        let msg: PhoenixMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.topic, "agent:123");
        assert_eq!(msg.event, "phx_reply");
        assert_eq!(msg.reference, Some("1".to_string()));
    }

    #[test]
    fn test_phoenix_message_no_reference() {
        let json = r#"{"topic":"agent:123","event":"job","payload":{},"ref":null}"#;
        let msg: PhoenixMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.topic, "agent:123");
        assert_eq!(msg.event, "job");
        assert!(msg.reference.is_none());
    }

    // Note: AgentClient methods require WebSocket connection and are tested via integration tests

    #[test]
    fn test_redact_community_normal() {
        assert_eq!(redact_community("public"), "***");
    }

    #[test]
    fn test_redact_community_short() {
        assert_eq!(redact_community("ab"), "***");
        assert_eq!(redact_community("a"), "***");
    }

    #[test]
    fn test_redact_community_empty() {
        assert_eq!(redact_community(""), "(empty)");
    }

    #[test]
    fn test_redact_community_three_chars() {
        assert_eq!(redact_community("abc"), "***");
    }

    #[test]
    fn test_redact_community_long() {
        assert_eq!(redact_community("mysecretcommunity"), "***");
    }
}
