use serde::{Deserialize, Serialize};

/// Configuration received from the API
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    pub version: String,
    pub poll_interval_seconds: u64,
    pub equipment: Vec<EquipmentConfig>,
}

/// Configuration for a single piece of equipment
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EquipmentConfig {
    pub id: String,
    pub name: String,
    pub ip_address: String,
    pub snmp: SnmpConfig,
    pub poll_interval_seconds: u64,
    pub sensors: Vec<SensorConfig>,
    pub interfaces: Vec<InterfaceConfig>,
}

/// SNMP configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SnmpConfig {
    pub enabled: bool,
    pub version: String,
    pub community: String,
    pub port: u16,
}

/// Sensor configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SensorConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub sensor_type: String,
    pub oid: String,
    pub divisor: Option<i32>,
    pub unit: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Interface configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InterfaceConfig {
    pub id: String,
    pub if_index: i32,
    pub if_name: String,
}

/// Heartbeat metadata sent to the API
#[derive(Debug, Serialize)]
pub struct HeartbeatMetadata {
    pub version: String,
    pub hostname: String,
    pub uptime_seconds: u64,
}
