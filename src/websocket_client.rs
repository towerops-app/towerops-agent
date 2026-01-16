/// WebSocket-based agent client for Towerops.
///
/// This replaces the complex REST API + polling architecture with a single
/// persistent WebSocket connection. The server sends SNMP query jobs as protobuf
/// messages, the agent executes raw SNMP queries, and sends results back.
use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use prost::Message;
use std::collections::HashMap;
use tokio::net::TcpStream;
use tokio::time::{interval, Duration};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage, MaybeTlsStream, WebSocketStream};

use crate::proto::{AgentError, AgentHeartbeat, AgentJob, AgentJobList, JobType, QueryType, SnmpResult};

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
    token: String,
    agent_id: String,
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
        let ws_url = format!("{}/socket/agent?token={}", url, token);
        let (ws_stream, _) = connect_async(&ws_url)
            .await
            .context("Failed to connect to WebSocket")?;

        log::info!("Connected to Towerops server at {}", url);

        Ok(Self {
            ws_stream,
            token: token.to_string(),
            agent_id: generate_agent_id(),
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
            "jobs" => {
                // Extract binary protobuf from payload
                if let serde_json::Value::Object(map) = phoenix_msg.payload {
                    if let Some(serde_json::Value::String(binary_b64)) = map.get("binary") {
                        let binary = base64::decode(binary_b64)?;
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
            let job_type = JobType::from_i32(job.job_type).unwrap_or(JobType::Poll);
            log::info!("Executing job: {} (type: {:?})", job.job_id, job_type);

            // Spawn task to execute job
            tokio::spawn(async move {
                if let Err(e) = execute_job(job).await {
                    log::error!("Job execution failed: {}", e);
                }
            });
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
            payload: serde_json::json!({"binary": base64::encode(&binary)}),
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
            payload: serde_json::json!({"binary": base64::encode(&binary)}),
            reference: None,
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_stream.send(WsMessage::Text(text)).await?;

        log::debug!("Sent SNMP result for equipment {}", result.equipment_id);
        Ok(())
    }

    /// Send error to server.
    async fn send_error(&mut self, error: AgentError) -> Result<()> {
        let binary = error.encode_to_vec();

        let msg = PhoenixMessage {
            topic: format!("agent:{}", self.agent_id),
            event: "error".to_string(),
            payload: serde_json::json!({"binary": base64::encode(&binary)}),
            reference: None,
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_stream.send(WsMessage::Text(text)).await?;

        log::warn!("Sent error for equipment {}", error.equipment_id);
        Ok(())
    }
}

/// Execute an SNMP job and collect results.
async fn execute_job(job: AgentJob) -> Result<()> {
    let device = job.device.context("Job missing device info")?;
    let mut oid_values = HashMap::new();

    for query in job.queries {
        let query_type = QueryType::from_i32(query.query_type).unwrap_or(QueryType::Get);

        match query_type {
            QueryType::Get => {
                // Execute SNMP GET for each OID
                for oid in &query.oids {
                    match snmp_get(&device.ip, &device.community, &device.version, device.port, oid).await {
                        Ok(value) => {
                            oid_values.insert(oid.clone(), value);
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
                    match snmp_walk(&device.ip, &device.community, &device.version, device.port, base_oid).await {
                        Ok(results) => {
                            oid_values.extend(results);
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
        equipment_id: job.equipment_id,
        job_type: job.job_type,
        oid_values,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64,
    };

    // Send result back to server
    // TODO: Get client reference to send result
    log::info!("Collected {} OID values for job {}", result.oid_values.len(), job.job_id);

    Ok(())
}

/// Execute SNMP GET operation.
///
/// Returns the value as a string (already formatted).
async fn snmp_get(
    ip: &str,
    community: &str,
    version: &str,
    port: u32,
    oid: &str,
) -> Result<String> {
    // TODO: Implement raw SNMP GET over UDP
    // 1. Construct SNMP GET PDU (BER encoded)
    // 2. Send UDP packet to ip:port
    // 3. Wait for response with timeout
    // 4. Parse response and extract value
    // 5. Format value as string

    log::debug!("SNMP GET: {} @ {}:{} (community: {}, version: {})", oid, ip, port, community, version);

    // Placeholder
    Err(anyhow::anyhow!("SNMP GET not yet implemented"))
}

/// Execute SNMP WALK operation.
///
/// Returns a map of OID → value (all as strings).
async fn snmp_walk(
    ip: &str,
    community: &str,
    version: &str,
    port: u32,
    base_oid: &str,
) -> Result<HashMap<String, String>> {
    // TODO: Implement raw SNMP WALK over UDP
    // 1. Start with GETNEXT(base_oid)
    // 2. Loop: GETNEXT(last_oid) until OID no longer starts with base_oid
    // 3. Collect all OID/value pairs
    // 4. Return map

    log::debug!("SNMP WALK: {} @ {}:{} (community: {}, version: {})", base_oid, ip, port, community, version);

    // Placeholder
    Err(anyhow::anyhow!("SNMP WALK not yet implemented"))
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
