use crate::config::{
    AgentConfig, EquipmentConfig, HeartbeatMetadata, InterfaceConfig, SensorConfig, SnmpConfig,
};
use crate::metrics::Metric;
use crate::proto::agent;
use prost::Message;
use std::io::Read;
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

    /// Fetch configuration from the API using Protocol Buffers
    pub async fn fetch_config(&self) -> Result<AgentConfig> {
        let url = format!("{}/api/v1/agent/config", self.base_url);
        let token = self.token.clone();

        let config = tokio::task::spawn_blocking(move || {
            let response = ureq::get(&url)
                .set("Authorization", &format!("Bearer {}", token))
                .set("Accept", "application/x-protobuf")
                .timeout(Duration::from_secs(30))
                .call()
                .map_err(|e| ApiError::RequestFailed(e.to_string()))?;

            let status = response.status();
            if status != 200 {
                return Err(ApiError::StatusError(status));
            }

            // Read response bytes
            let mut bytes = Vec::new();
            response
                .into_reader()
                .read_to_end(&mut bytes)
                .map_err(|e| ApiError::RequestFailed(e.to_string()))?;

            // Decode protobuf
            let proto_config = agent::AgentConfig::decode(&bytes[..])
                .map_err(|e| ApiError::RequestFailed(format!("Protobuf decode error: {}", e)))?;

            // Convert to internal config type
            let config = convert_proto_to_config(proto_config);

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

    /// Send heartbeat to the API using Protocol Buffers
    pub async fn heartbeat(&self, metadata: HeartbeatMetadata) -> Result<()> {
        let url = format!("{}/api/v1/agent/heartbeat", self.base_url);
        let token = self.token.clone();

        tokio::task::spawn_blocking(move || {
            // Convert to protobuf
            let proto_metadata = agent::HeartbeatMetadata {
                version: metadata.version,
                hostname: metadata.hostname,
                uptime_seconds: metadata.uptime_seconds,
            };

            // Encode to bytes
            let mut buf = Vec::new();
            proto_metadata
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
}

/// Convert protobuf AgentConfig to internal AgentConfig
fn convert_proto_to_config(proto: agent::AgentConfig) -> AgentConfig {
    AgentConfig {
        version: proto.version,
        poll_interval_seconds: proto.poll_interval_seconds as u64,
        equipment: proto
            .equipment
            .into_iter()
            .map(convert_proto_equipment)
            .collect(),
    }
}

/// Convert protobuf Equipment to internal EquipmentConfig
fn convert_proto_equipment(proto: agent::Equipment) -> EquipmentConfig {
    EquipmentConfig {
        id: proto.id,
        name: proto.name,
        ip_address: proto.ip_address,
        snmp: convert_proto_snmp(proto.snmp.unwrap_or_default()),
        poll_interval_seconds: proto.poll_interval_seconds as u64,
        sensors: proto
            .sensors
            .into_iter()
            .map(convert_proto_sensor)
            .collect(),
        interfaces: proto
            .interfaces
            .into_iter()
            .map(convert_proto_interface)
            .collect(),
    }
}

/// Convert protobuf SnmpConfig to internal SnmpConfig
fn convert_proto_snmp(proto: agent::SnmpConfig) -> SnmpConfig {
    SnmpConfig {
        enabled: proto.enabled,
        version: proto.version,
        community: proto.community,
        port: proto.port as u16,
    }
}

/// Convert protobuf Sensor to internal SensorConfig
fn convert_proto_sensor(proto: agent::Sensor) -> SensorConfig {
    SensorConfig {
        id: proto.id,
        sensor_type: proto.r#type,
        oid: proto.oid,
        divisor: if proto.divisor == 0.0 {
            None
        } else {
            Some(proto.divisor as i32)
        },
        unit: if proto.unit.is_empty() {
            None
        } else {
            Some(proto.unit)
        },
        metadata: if proto.metadata.is_empty() {
            None
        } else {
            // Convert metadata map to JSON value
            let json_map: serde_json::Map<String, serde_json::Value> = proto
                .metadata
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            Some(serde_json::Value::Object(json_map))
        },
    }
}

/// Convert protobuf Interface to internal InterfaceConfig
fn convert_proto_interface(proto: agent::Interface) -> InterfaceConfig {
    InterfaceConfig {
        id: proto.id,
        if_index: proto.if_index as i32,
        if_name: proto.if_name,
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
