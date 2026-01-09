use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Metric types that can be submitted to the API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Metric {
    #[serde(rename = "sensor_reading")]
    SensorReading(SensorReading),
    #[serde(rename = "interface_stat")]
    InterfaceStat(InterfaceStat),
}

impl Metric {
    pub fn metric_type(&self) -> &str {
        match self {
            Metric::SensorReading(_) => "sensor_reading",
            Metric::InterfaceStat(_) => "interface_stat",
        }
    }

    pub fn timestamp(&self) -> &DateTime<Utc> {
        match self {
            Metric::SensorReading(sr) => &sr.timestamp,
            Metric::InterfaceStat(is) => &is.timestamp,
        }
    }
}

/// Sensor reading metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorReading {
    pub sensor_id: String,
    pub value: f64,
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

/// Interface statistics metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStat {
    pub interface_id: String,
    pub if_in_octets: i64,
    pub if_out_octets: i64,
    pub if_in_errors: i64,
    pub if_out_errors: i64,
    pub if_in_discards: i64,
    pub if_out_discards: i64,
    pub timestamp: DateTime<Utc>,
}
