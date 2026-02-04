#[derive(Debug)]
pub enum SnmpError {
    RequestFailed(String),
    InvalidOid(String),
    Timeout,
    AuthFailure,
    NetworkUnreachable,
}

impl std::fmt::Display for SnmpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestFailed(msg) => write!(f, "SNMP request failed: {}", msg),
            Self::InvalidOid(oid) => write!(f, "Invalid OID: {}", oid),
            Self::Timeout => write!(f, "Timeout"),
            Self::AuthFailure => write!(f, "Authentication failure"),
            Self::NetworkUnreachable => write!(f, "Network unreachable"),
        }
    }
}

impl std::error::Error for SnmpError {}

pub type SnmpResult<T> = Result<T, SnmpError>;

/// SNMP value returned from a GET operation
#[allow(dead_code)] // Some variants' data not yet accessed directly
#[derive(Debug, Clone)]
pub enum SnmpValue {
    Integer(i64),
    String(String),
    OctetString(Vec<u8>),
    Oid(String),
    Counter32(u32),
    Counter64(u64),
    Gauge32(u32),
    TimeTicks(u32),
    IpAddress(String),
    Null,
    Unsupported(String),
}

impl SnmpValue {
    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn as_f64(&self) -> Option<f64> {
        self.as_i64().map(|v| v as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snmp_error_display() {
        assert_eq!(
            format!("{}", SnmpError::RequestFailed("test error".to_string())),
            "SNMP request failed: test error"
        );
        assert_eq!(
            format!("{}", SnmpError::InvalidOid("1.2.3".to_string())),
            "Invalid OID: 1.2.3"
        );
        assert_eq!(format!("{}", SnmpError::Timeout), "Timeout");
        assert_eq!(
            format!("{}", SnmpError::AuthFailure),
            "Authentication failure"
        );
        assert_eq!(
            format!("{}", SnmpError::NetworkUnreachable),
            "Network unreachable"
        );
    }

    #[test]
    fn test_snmp_error_is_error() {
        let error: &dyn std::error::Error = &SnmpError::Timeout;
        assert_eq!(format!("{}", error), "Timeout");
    }

    #[test]
    fn test_snmp_value_as_i64() {
        assert_eq!(SnmpValue::Integer(42).as_i64(), Some(42));
        assert_eq!(SnmpValue::Counter32(100).as_i64(), Some(100));
        assert_eq!(SnmpValue::Counter64(1000).as_i64(), Some(1000));
        assert_eq!(SnmpValue::Gauge32(50).as_i64(), Some(50));
        assert_eq!(SnmpValue::TimeTicks(200).as_i64(), Some(200));
        assert_eq!(SnmpValue::String("test".to_string()).as_i64(), None);
        assert_eq!(SnmpValue::IpAddress("1.2.3.4".to_string()).as_i64(), None);
    }

    #[test]
    fn test_snmp_value_as_f64() {
        assert_eq!(SnmpValue::Integer(42).as_f64(), Some(42.0));
        assert_eq!(SnmpValue::Counter32(100).as_f64(), Some(100.0));
        assert_eq!(SnmpValue::Counter64(1000).as_f64(), Some(1000.0));
        assert_eq!(SnmpValue::Gauge32(50).as_f64(), Some(50.0));
        assert_eq!(SnmpValue::TimeTicks(200).as_f64(), Some(200.0));
        assert_eq!(SnmpValue::String("test".to_string()).as_f64(), None);
        assert_eq!(SnmpValue::IpAddress("1.2.3.4".to_string()).as_f64(), None);
    }
}
