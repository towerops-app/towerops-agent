/// WebSocket-based agent client for Towerops.
///
/// This replaces the complex REST API + polling architecture with a single
/// persistent WebSocket connection. The server sends SNMP query jobs as protobuf
/// messages, the agent executes raw SNMP queries, and sends results back.
///
/// Connection URL: {url}/socket/agent/websocket
/// Authentication: Token sent in Phoenix channel join payload
use futures::{SinkExt, StreamExt};
use prost::Message;
use std::collections::HashMap;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, timeout, Duration};
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};

/// Connection timeout for WebSocket establishment (30 seconds)
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

use crate::proto::agent::{AgentHeartbeat, AgentJob, AgentJobList, JobType, QueryType, SnmpResult};
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
        crate::log_info!(
            "Connecting to WebSocket: {} (timeout: {}s)",
            ws_url,
            CONNECTION_TIMEOUT.as_secs()
        );

        // Wrap connection in timeout to avoid hanging indefinitely on bad network
        let (mut ws_stream, _) = match timeout(CONNECTION_TIMEOUT, connect_async(&ws_url)).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                crate::log_error!("WebSocket connection failed: {}", e);
                return Err(format!("Failed to connect to WebSocket: {}", e).into());
            }
            Err(_) => {
                crate::log_error!(
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

        crate::log_info!("Connected to Towerops server at {}", url);

        let agent_id = generate_agent_id();
        let (result_tx, result_rx) = mpsc::unbounded_channel();

        // Join Phoenix channel with token in payload
        let join_msg = PhoenixMessage {
            topic: format!("agent:{}", agent_id),
            event: "phx_join".to_string(),
            payload: serde_json::json!({"token": token}),
            reference: Some("1".to_string()),
        };

        let join_text = serde_json::to_string(&join_msg)?;
        ws_stream.send(WsMessage::Text(join_text)).await?;
        crate::log_info!(
            "Sent channel join request with token for agent:{}",
            agent_id
        );

        Ok(Self {
            ws_stream,
            agent_id,
            result_tx,
            result_rx,
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

        let result = loop {
            tokio::select! {
                // Check for shutdown signal (highest priority)
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        crate::log_info!("Shutdown signal received, closing WebSocket connection gracefully");
                        // Send close frame to server
                        if let Err(e) = self.ws_stream.close(None).await {
                            crate::log_warn!("Error sending WebSocket close frame: {}", e);
                        }
                        break Ok(());
                    }
                }

                // Receive messages from server
                msg = self.ws_stream.next() => {
                    match msg {
                        Some(Ok(WsMessage::Binary(data))) => {
                            if let Err(e) = self.handle_message(&data).await {
                                crate::log_error!("Error handling binary message: {}", e);
                            }
                        }
                        Some(Ok(WsMessage::Text(text))) => {
                            if let Err(e) = self.handle_text_message(&text).await {
                                crate::log_error!("Error handling text message: {}", e);
                            }
                        }
                        Some(Ok(WsMessage::Close(_))) => {
                            crate::log_info!("Server closed connection");
                            break Ok(());
                        }
                        Some(Err(e)) => {
                            crate::log_error!("WebSocket error: {}", e);
                            break Err(e.into());
                        }
                        None => {
                            crate::log_info!("Connection closed");
                            break Ok(());
                        }
                        _ => {}
                    }
                }

                // Receive SNMP results from job tasks
                Some(result) = self.result_rx.recv() => {
                    if let Err(e) = self.send_result(result).await {
                        crate::log_error!("Error sending SNMP result: {}", e);
                    }
                }

                // Send periodic heartbeats
                _ = heartbeat_interval.tick() => {
                    if let Err(e) = self.send_heartbeat().await {
                        crate::log_error!("Error sending heartbeat: {}", e);
                    }
                }
            }
        };

        result
    }

    /// Handle Phoenix channel message (JSON-wrapped).
    async fn handle_text_message(&mut self, text: &str) -> Result<()> {
        let phoenix_msg: PhoenixMessage = serde_json::from_str(text)?;

        match phoenix_msg.event.as_str() {
            "phx_reply" => {
                crate::log_info!("Channel join reply: {:?}", phoenix_msg.payload);
            }
            "jobs" => {
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
                crate::log_debug!("Ignoring unknown event: {}", phoenix_msg.event);
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
        crate::log_info!("Received {} jobs from server", job_list.jobs.len());

        for job in job_list.jobs {
            let job_type = JobType::try_from(job.job_type).unwrap_or(JobType::Poll);
            crate::log_info!("Executing job: {} (type: {:?})", job.job_id, job_type);

            // Spawn task to execute SNMP job (one-off execution)
            let result_tx = self.result_tx.clone();

            tokio::spawn(async move {
                if let Err(e) = execute_job(job, result_tx).await {
                    crate::log_error!("Job execution failed: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Send heartbeat to server.
    async fn send_heartbeat(&mut self) -> Result<()> {
        let heartbeat = AgentHeartbeat {
            version: env!("CARGO_PKG_VERSION").to_string(),
            hostname: get_hostname(),
            uptime_seconds: get_uptime_seconds(),
            ip_address: get_local_ip().unwrap_or_else(|| "unknown".to_string()),
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
        self.ws_stream.send(WsMessage::Text(text)).await?;

        crate::log_debug!("Sent heartbeat");
        Ok(())
    }

    /// Send SNMP results to server.
    async fn send_result(&mut self, result: SnmpResult) -> Result<()> {
        let binary = result.encode_to_vec();

        let msg = PhoenixMessage {
            topic: format!("agent:{}", self.agent_id),
            event: "result".to_string(),
            payload: serde_json::json!({"binary": base64_encode(&binary)}),
            reference: None,
        };

        let text = serde_json::to_string(&msg)?;
        self.ws_stream.send(WsMessage::Text(text)).await?;

        crate::log_debug!("Sent SNMP result for device {}", result.device_id);
        Ok(())
    }
}

/// Execute an SNMP job and collect results.
async fn execute_job(job: AgentJob, result_tx: mpsc::UnboundedSender<SnmpResult>) -> Result<()> {
    let snmp_device = job.snmp_device.ok_or("Job missing SNMP device info")?;

    // Log SNMP connection parameters for debugging (mask community for security)
    let community_masked = if snmp_device.community.len() > 4 {
        format!("{}***", &snmp_device.community[..2])
    } else {
        "***".to_string()
    };

    crate::log_info!(
        "Executing SNMP job for device {} at {}:{} (community: {}, version: {})",
        job.device_id,
        snmp_device.ip,
        snmp_device.port,
        community_masked,
        snmp_device.version
    );

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
                            crate::log_warn!(
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
                            crate::log_warn!(
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
        device_id: job.device_id,
        job_type: job.job_type,
        oid_values,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64,
    };

    crate::log_info!(
        "Collected {} OID values for job {}",
        result.oid_values.len(),
        job.job_id
    );

    // Send result back to main client task
    if let Err(e) = result_tx.send(result) {
        crate::log_warn!(
            "Failed to send SNMP result for job {}: channel closed (connection may have dropped)",
            job.job_id
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
        SnmpValue::Counter32(c) => c.to_string(),
        SnmpValue::Counter64(c) => c.to_string(),
        SnmpValue::Gauge32(g) => g.to_string(),
        SnmpValue::TimeTicks(t) => t.to_string(),
        SnmpValue::IpAddress(ip) => ip,
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

/// Get local IP address.
fn get_local_ip() -> Option<String> {
    // TODO: Implement IP detection
    // Could use local_ip_address crate or parse network interfaces
    None
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
        // Currently returns None (not implemented), just verify it's callable
        assert!(ip.is_none());
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
}
