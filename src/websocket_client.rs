/// WebSocket-based agent client for Towerops.
///
/// This replaces the complex REST API + polling architecture with a single
/// persistent WebSocket connection. The server sends SNMP query jobs as protobuf
/// messages, the agent executes raw SNMP queries, and sends results back.
///
/// Connection URL: {url}/socket/agent/websocket
/// Authentication: Token sent in Phoenix channel join payload
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use futures::{SinkExt, StreamExt};
use prost::Message;
use std::collections::HashMap;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};

use crate::ping::ping;
use crate::proto::agent::{
    AgentHeartbeat, AgentJob, AgentJobList, JobType, MonitoringCheck, QueryType, SnmpResult,
};
use crate::snmp::{SnmpClient, SnmpValue};

/// Phoenix channel message format (JSON wrapper around binary protobuf).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PhoenixMessage {
    topic: String,
    event: String,
    payload: serde_json::Value,
    #[serde(rename = "ref")]
    reference: Option<String>,
}

/// WebSocket client for agent communication.
pub struct AgentClient {
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    agent_id: String,
    result_tx: mpsc::UnboundedSender<SnmpResult>,
    result_rx: mpsc::UnboundedReceiver<SnmpResult>,
    monitoring_check_tx: mpsc::UnboundedSender<MonitoringCheck>,
    monitoring_check_rx: mpsc::UnboundedReceiver<MonitoringCheck>,
}

impl AgentClient {
    /// Connect to Towerops server via WebSocket.
    ///
    /// # Arguments
    /// * `url` - Server URL (e.g., "wss://towerops.net")
    /// * `token` - Agent authentication token
    ///
    /// # Example
    /// ```no_run
    /// let client = AgentClient::connect("wss://towerops.net", "token123").await?;
    /// ```
    pub async fn connect(url: &str, token: &str) -> Result<Self> {
        // Strip trailing slash from base URL to avoid double slashes
        let base_url = url.trim_end_matches('/');
        let ws_url = format!("{}/socket/agent/websocket", base_url);
        log::info!("Connecting to WebSocket: {}", ws_url);

        let (mut ws_stream, _) = connect_async(&ws_url)
            .await
            .map_err(|e| {
                log::error!("WebSocket connection failed: {}", e);
                e
            })
            .context("Failed to connect to WebSocket")?;

        log::info!("Connected to Towerops server at {}", url);

        let agent_id = generate_agent_id();
        let (result_tx, result_rx) = mpsc::unbounded_channel();
        let (monitoring_check_tx, monitoring_check_rx) = mpsc::unbounded_channel();

        // Join Phoenix channel with token in payload
        let join_msg = PhoenixMessage {
            topic: format!("agent:{}", agent_id),
            event: "phx_join".to_string(),
            payload: serde_json::json!({"token": token}),
            reference: Some("1".to_string()),
        };

        let join_text = serde_json::to_string(&join_msg)?;
        ws_stream.send(WsMessage::Text(join_text)).await?;
        log::info!(
            "Sent channel join request with token for agent:{}",
            agent_id
        );

        Ok(Self {
            ws_stream,
            agent_id,
            result_tx,
            result_rx,
            monitoring_check_tx,
            monitoring_check_rx,
        })
    }

    /// Main event loop for agent operation.
    ///
    /// Handles:
    /// - Receiving jobs from server
    /// - Executing SNMP queries
    /// - Sending results back
    /// - Periodic heartbeats
    pub async fn run(&mut self) -> Result<()> {
        let mut heartbeat_interval = interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                // Receive messages from server
                msg = self.ws_stream.next() => {
                    match msg {
                        Some(Ok(WsMessage::Binary(data))) => {
                            self.handle_message(&data).await?;
                        }
                        Some(Ok(WsMessage::Text(text))) => {
                            self.handle_text_message(&text).await?;
                        }
                        Some(Ok(WsMessage::Close(_))) => {
                            log::info!("Server closed connection");
                            break;
                        }
                        Some(Err(e)) => {
                            log::error!("WebSocket error: {}", e);
                            return Err(e.into());
                        }
                        None => {
                            log::info!("Connection closed");
                            break;
                        }
                        _ => {}
                    }
                }

                // Receive SNMP results from job tasks
                Some(result) = self.result_rx.recv() => {
                    self.send_result(result).await?;
                }

                // Receive monitoring checks from ping tasks
                Some(check) = self.monitoring_check_rx.recv() => {
                    self.send_monitoring_check(check).await?;
                }

                // Send periodic heartbeats
                _ = heartbeat_interval.tick() => {
                    self.send_heartbeat().await?;
                }
            }
        }

        Ok(())
    }

    /// Handle Phoenix channel message (JSON-wrapped).
    async fn handle_text_message(&mut self, text: &str) -> Result<()> {
        let phoenix_msg: PhoenixMessage = serde_json::from_str(text)?;

        match phoenix_msg.event.as_str() {
            "phx_reply" => {
                log::info!("Channel join reply: {:?}", phoenix_msg.payload);
            }
            "jobs" => {
                // Extract binary protobuf from payload
                if let serde_json::Value::Object(map) = phoenix_msg.payload {
                    if let Some(serde_json::Value::String(binary_b64)) = map.get("binary") {
                        let binary = BASE64.decode(binary_b64)?;
                        let job_list = AgentJobList::decode(&binary[..])?;
                        self.handle_jobs(job_list).await?;
                    }
                }
            }
            _ => {
                log::debug!("Ignoring unknown event: {}", phoenix_msg.event);
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
    async fn handle_jobs(&self, job_list: AgentJobList) -> Result<()> {
        log::info!("Received {} jobs from server", job_list.jobs.len());

        for job in job_list.jobs {
            let job_type = JobType::try_from(job.job_type).unwrap_or(JobType::Poll);
            log::info!("Executing job: {} (type: {:?})", job.job_id, job_type);

            // Extract monitoring configuration before moving job
            let monitoring_info = job.snmp_device.as_ref().and_then(|snmp_device| {
                if snmp_device.monitoring_enabled {
                    Some((
                        snmp_device.ip.clone(),
                        if snmp_device.check_interval_seconds > 0 {
                            snmp_device.check_interval_seconds as u64
                        } else {
                            60
                        },
                    ))
                } else {
                    None
                }
            });

            // Spawn task to execute SNMP job
            let result_tx = self.result_tx.clone();
            let monitoring_check_tx = self.monitoring_check_tx.clone();
            let device_id = job.device_id.clone();

            tokio::spawn(async move {
                if let Err(e) = execute_job(job, result_tx).await {
                    log::error!("Job execution failed: {}", e);
                }
            });

            // Start monitoring task if enabled
            if let Some((ip, interval_seconds)) = monitoring_info {
                log::info!(
                    "Starting ICMP monitoring for device {} every {} seconds",
                    device_id,
                    interval_seconds
                );

                let device_id_clone = device_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_monitoring_task(
                        device_id_clone,
                        ip,
                        interval_seconds,
                        monitoring_check_tx,
                    )
                    .await
                    {
                        log::error!("Monitoring task failed: {}", e);
                    }
                });
            }
        }

        Ok(())
    }

    /// Send heartbeat to server.
    async fn send_heartbeat(&mut self) -> Result<()> {
        let heartbeat = AgentHeartbeat {
            version: env!("CARGO_PKG_VERSION").to_string(),
            hostname: hostname::get()?.to_string_lossy().to_string(),
            uptime_seconds: get_uptime_seconds(),
            ip_address: get_local_ip().unwrap_or_else(|| "unknown".to_string()),
        };

        let binary = heartbeat.encode_to_vec();

        // Phoenix channel format
        let msg = PhoenixMessage {
            topic: format!("agent:{}", self.agent_id),
            event: "heartbeat".to_string(),
            payload: serde_json::json!({"binary": BASE64.encode(&binary)}),
            reference: None,
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_stream.send(WsMessage::Text(text)).await?;

        log::debug!("Sent heartbeat");
        Ok(())
    }

    /// Send SNMP results to server.
    async fn send_result(&mut self, result: SnmpResult) -> Result<()> {
        let binary = result.encode_to_vec();

        let msg = PhoenixMessage {
            topic: format!("agent:{}", self.agent_id),
            event: "result".to_string(),
            payload: serde_json::json!({"binary": BASE64.encode(&binary)}),
            reference: None,
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_stream.send(WsMessage::Text(text)).await?;

        log::debug!("Sent SNMP result for device {}", result.device_id);
        Ok(())
    }

    /// Send monitoring check result to server.
    async fn send_monitoring_check(&mut self, check: MonitoringCheck) -> Result<()> {
        let binary = check.encode_to_vec();

        let msg = PhoenixMessage {
            topic: format!("agent:{}", self.agent_id),
            event: "monitoring_check".to_string(),
            payload: serde_json::json!({"binary": BASE64.encode(&binary)}),
            reference: None,
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_stream.send(WsMessage::Text(text)).await?;

        log::debug!(
            "Sent monitoring check for device {}: {}",
            check.device_id,
            check.status
        );
        Ok(())
    }

    /// Get the monitoring check sender for spawning ping tasks.
    pub fn monitoring_check_sender(&self) -> mpsc::UnboundedSender<MonitoringCheck> {
        self.monitoring_check_tx.clone()
    }
}

/// Execute an SNMP job and collect results.
async fn execute_job(job: AgentJob, result_tx: mpsc::UnboundedSender<SnmpResult>) -> Result<()> {
    let snmp_device = job.snmp_device.context("Job missing SNMP device info")?;
    let mut oid_values: HashMap<String, String> = HashMap::new();
    let snmp_client = SnmpClient::new();

    for query in job.queries {
        let query_type = QueryType::try_from(query.query_type).unwrap_or(QueryType::Get);

        match query_type {
            QueryType::Get => {
                // Execute SNMP GET for each OID
                for oid in &query.oids {
                    match snmp_client
                        .get(
                            &snmp_device.ip,
                            &snmp_device.community,
                            &snmp_device.version,
                            snmp_device.port as u16,
                            oid,
                        )
                        .await
                    {
                        Ok(value) => {
                            oid_values.insert(oid.clone(), value_to_string(value));
                        }
                        Err(e) => {
                            log::warn!("SNMP GET failed for OID {}: {}", oid, e);
                        }
                    }
                }
            }
            QueryType::Walk => {
                // Execute SNMP WALK for each base OID
                for base_oid in &query.oids {
                    match snmp_client
                        .walk(
                            &snmp_device.ip,
                            &snmp_device.community,
                            &snmp_device.version,
                            snmp_device.port as u16,
                            base_oid,
                        )
                        .await
                    {
                        Ok(results) => {
                            for (oid, value) in results {
                                oid_values.insert(oid, value_to_string(value));
                            }
                        }
                        Err(e) => {
                            log::warn!("SNMP WALK failed for OID {}: {}", base_oid, e);
                        }
                    }
                }
            }
        }
    }

    // Build result
    let result = SnmpResult {
        device_id: job.device_id,
        job_type: job.job_type,
        oid_values,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64,
    };

    log::info!(
        "Collected {} OID values for job {}",
        result.oid_values.len(),
        job.job_id
    );

    // Send result back to main client task
    result_tx.send(result).ok();

    Ok(())
}

/// Convert SnmpValue to String for protobuf transmission.
fn value_to_string(value: SnmpValue) -> String {
    match value {
        SnmpValue::Integer(i) => i.to_string(),
        SnmpValue::String(s) => s,
        SnmpValue::Counter32(c) => c.to_string(),
        SnmpValue::Counter64(c) => c.to_string(),
        SnmpValue::Gauge32(g) => g.to_string(),
        SnmpValue::TimeTicks(t) => t.to_string(),
        SnmpValue::IpAddress(ip) => ip,
    }
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

/// Get system uptime in seconds.
fn get_uptime_seconds() -> u64 {
    // TODO: Implement platform-specific uptime
    // Linux: read /proc/uptime
    // macOS: use sysctl
    // Windows: GetTickCount64
    0
}

/// Get local IP address.
fn get_local_ip() -> Option<String> {
    // TODO: Implement IP detection
    // Could use local_ip_address crate or parse network interfaces
    None
}

/// Run continuous ICMP monitoring for a device.
async fn run_monitoring_task(
    device_id: String,
    ip: String,
    interval_seconds: u64,
    check_tx: mpsc::UnboundedSender<MonitoringCheck>,
) -> Result<()> {
    let mut interval_timer = interval(Duration::from_secs(interval_seconds));

    loop {
        interval_timer.tick().await;

        let ip_addr: std::net::IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(e) => {
                log::error!("Invalid IP address for device {}: {}", device_id, e);
                continue;
            }
        };

        let timeout = Duration::from_secs(5);

        match ping(ip_addr, timeout).await {
            Ok(rtt) => {
                let check = MonitoringCheck {
                    device_id: device_id.clone(),
                    status: "success".to_string(),
                    response_time_ms: rtt.as_secs_f64() * 1000.0,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs() as i64,
                };

                if let Err(e) = check_tx.send(check) {
                    log::error!("Failed to send monitoring check: {}", e);
                    break;
                }

                log::debug!(
                    "ICMP ping successful for {}: {:.2}ms",
                    ip,
                    rtt.as_secs_f64() * 1000.0
                );
            }
            Err(e) => {
                let check = MonitoringCheck {
                    device_id: device_id.clone(),
                    status: "failure".to_string(),
                    response_time_ms: 0.0,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs() as i64,
                };

                if let Err(send_err) = check_tx.send(check) {
                    log::error!("Failed to send monitoring check: {}", send_err);
                    break;
                }

                log::warn!("ICMP ping failed for {}: {}", ip, e);
            }
        }
    }

    Ok(())
}
