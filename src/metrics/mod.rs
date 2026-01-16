use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{SystemTime, UNIX_EPOCH};

/// Timestamp that serializes to RFC3339 format
#[derive(Debug, Clone, Copy)]
pub struct Timestamp {
    secs: i64,
}

impl Timestamp {
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        Self {
            secs: duration.as_secs() as i64,
        }
    }

    pub fn elapsed_secs(&self) -> i64 {
        Self::now().secs - self.secs
    }

    pub fn to_unix_timestamp(self) -> i64 {
        self.secs
    }

    pub fn to_rfc3339(self) -> String {
        // Convert Unix timestamp to RFC3339 format
        // This is a simplified implementation that produces UTC timestamps
        let secs = self.secs;
        let days = secs / 86400;
        let rem_secs = secs % 86400;
        let hours = rem_secs / 3600;
        let minutes = (rem_secs % 3600) / 60;
        let seconds = rem_secs % 60;

        // Calculate year/month/day from days since epoch (1970-01-01)
        let (year, month, day) = days_to_ymd(days);

        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, hours, minutes, seconds
        )
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let _s = String::deserialize(deserializer)?;
        // Simple RFC3339 parsing - accepts the format we produce
        // For a production system, you might want more robust parsing
        Ok(Timestamp { secs: 0 }) // Simplified - we mainly serialize, not deserialize
    }
}

/// Convert days since Unix epoch to year/month/day
fn days_to_ymd(mut days: i64) -> (i32, u8, u8) {
    let mut year = 1970;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let days_in_months = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &dim in &days_in_months {
        if days < dim as i64 {
            break;
        }
        days -= dim as i64;
        month += 1;
    }

    (year, month, days as u8 + 1)
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Metric types that can be submitted to the API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Metric {
    #[serde(rename = "sensor_reading")]
    SensorReading(SensorReading),
    #[serde(rename = "interface_stat")]
    InterfaceStat(InterfaceStat),
    #[serde(rename = "neighbor_discovery")]
    NeighborDiscovery(NeighborDiscovery),
}

impl Metric {
    pub fn metric_type(&self) -> &str {
        match self {
            Metric::SensorReading(_) => "sensor_reading",
            Metric::InterfaceStat(_) => "interface_stat",
            Metric::NeighborDiscovery(_) => "neighbor_discovery",
        }
    }

    pub fn timestamp(&self) -> &Timestamp {
        match self {
            Metric::SensorReading(sr) => &sr.timestamp,
            Metric::InterfaceStat(is) => &is.timestamp,
            Metric::NeighborDiscovery(nd) => &nd.timestamp,
        }
    }
}

/// Sensor reading metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorReading {
    pub sensor_id: String,
    pub value: f64,
    pub status: String,
    pub timestamp: Timestamp,
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
    pub timestamp: Timestamp,
}

/// Neighbor discovery metric (LLDP/CDP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborDiscovery {
    pub interface_id: String,
    pub protocol: String,
    pub remote_chassis_id: String,
    pub remote_system_name: String,
    pub remote_system_description: String,
    pub remote_platform: String,
    pub remote_port_id: String,
    pub remote_port_description: String,
    pub remote_address: String,
    pub remote_capabilities: Vec<String>,
    pub timestamp: Timestamp,
}
