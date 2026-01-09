use thiserror::Error;

#[derive(Debug, Error)]
pub enum SnmpError {
    #[error("SNMP request failed: {0}")]
    RequestFailed(String),

    #[error("Invalid OID: {0}")]
    InvalidOid(String),

    #[error("Timeout")]
    Timeout,

    #[error("Authentication failure")]
    AuthFailure,

    #[error("Network unreachable")]
    NetworkUnreachable,
}

pub type SnmpResult<T> = Result<T, SnmpError>;

/// SNMP value returned from a GET operation
#[allow(dead_code)] // Some variants' data not yet accessed directly
#[derive(Debug, Clone)]
pub enum SnmpValue {
    Integer(i64),
    String(String),
    Counter32(u32),
    Counter64(u64),
    Gauge32(u32),
    TimeTicks(u32),
    IpAddress(String),
}

impl SnmpValue {
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            SnmpValue::Integer(v) => Some(*v),
            SnmpValue::Counter32(v) => Some(*v as i64),
            SnmpValue::Counter64(v) => Some(*v as i64),
            SnmpValue::Gauge32(v) => Some(*v as i64),
            SnmpValue::TimeTicks(v) => Some(*v as i64),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        self.as_i64().map(|v| v as f64)
    }
}
