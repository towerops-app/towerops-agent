use super::types::{SnmpError, SnmpResult, SnmpValue};
use snmp::SyncSession;
use std::time::Duration;

/// SNMP client for polling devices
#[derive(Debug, Clone, Copy)]
pub struct SnmpClient;

impl SnmpClient {
    pub fn new() -> Self {
        Self
    }

    /// Perform an SNMP GET operation
    pub async fn get(
        &self,
        ip_address: &str,
        community: &str,
        version: &str,
        port: u16,
        oid: &str,
    ) -> SnmpResult<SnmpValue> {
        // Only SNMPv2c is supported by the snmp crate
        if version != "2c" {
            return Err(SnmpError::RequestFailed(format!(
                "Unsupported SNMP version: {}. Only 2c is supported.",
                version
            )));
        }

        // Parse OID string to Vec<u32>
        let oid_parts = parse_oid(oid)?;

        // Clone data for the blocking task
        let addr = format!("{}:{}", ip_address, port);
        let community = community.as_bytes().to_vec();

        // Run SNMP operation in blocking thread pool
        let result = tokio::task::spawn_blocking(move || {
            // Create session with 5 second timeout
            let mut session =
                SyncSession::new(addr.as_str(), &community, Some(Duration::from_secs(5)), 0)
                    .map_err(|_| SnmpError::NetworkUnreachable)?;

            // Perform GET request
            let mut response = session.get(&oid_parts).map_err(map_snmp_error)?;

            // Check for error status
            if response.error_status != 0 {
                return Err(SnmpError::RequestFailed(format!(
                    "SNMP error status: {}",
                    response.error_status
                )));
            }

            // Extract first varbind
            if let Some((_name, value)) = response.varbinds.next() {
                return convert_value(value);
            }

            Err(SnmpError::RequestFailed("No varbinds in response".into()))
        })
        .await
        .map_err(|e| SnmpError::RequestFailed(format!("Task join error: {}", e)))??;

        Ok(result)
    }

    /// Perform an SNMP WALK operation to get multiple values
    #[allow(dead_code)] // Ready for use but not yet called
    pub async fn walk(
        &self,
        ip_address: &str,
        community: &str,
        version: &str,
        port: u16,
        base_oid: &str,
    ) -> SnmpResult<Vec<(String, SnmpValue)>> {
        // Only SNMPv2c is supported by the snmp crate
        if version != "2c" {
            return Err(SnmpError::RequestFailed(format!(
                "Unsupported SNMP version: {}. Only 2c is supported.",
                version
            )));
        }

        // Parse OID string to Vec<u32>
        let base_oid_parts = parse_oid(base_oid)?;

        // Clone data for the blocking task
        let addr = format!("{}:{}", ip_address, port);
        let community = community.as_bytes().to_vec();

        // Run SNMP walk in blocking thread pool
        let results = tokio::task::spawn_blocking(move || {
            // Create session with 5 second timeout
            let mut session =
                SyncSession::new(addr.as_str(), &community, Some(Duration::from_secs(5)), 0)
                    .map_err(|_| SnmpError::NetworkUnreachable)?;

            let mut results = Vec::new();
            let mut current_oid = base_oid_parts.clone();

            // Perform GETNEXT repeatedly until we leave the base OID tree
            loop {
                let response = session.getnext(&current_oid).map_err(map_snmp_error)?;

                // Check for error status
                if response.error_status != 0 {
                    break;
                }

                // Extract varbind
                for (name, value) in response.varbinds {
                    // Convert ObjectIdentifier to Vec<u32>
                    let mut oid_buf = [0u32; 128];
                    let oid_slice = name
                        .read_name(&mut oid_buf)
                        .map_err(|_| SnmpError::InvalidOid("Failed to read OID".into()))?;

                    // Check if we're still under the base OID
                    if !starts_with(oid_slice, &base_oid_parts) {
                        return Ok(results);
                    }

                    // Convert OID to string
                    let oid_string = format_oid(oid_slice);

                    // Convert value
                    let converted_value = convert_value(value)?;

                    results.push((oid_string, converted_value));

                    // Update current OID for next iteration
                    current_oid = oid_slice.to_vec();
                }

                if results.is_empty() {
                    break;
                }
            }

            Ok(results)
        })
        .await
        .map_err(|e| SnmpError::RequestFailed(format!("Task join error: {}", e)))??;

        Ok(results)
    }
}

impl Default for SnmpClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse OID string like "1.3.6.1.2.1.1.1.0" to Vec<u32>
fn parse_oid(oid: &str) -> SnmpResult<Vec<u32>> {
    oid.split('.')
        .map(|part| {
            part.parse::<u32>()
                .map_err(|_| SnmpError::InvalidOid(format!("Invalid OID part: {}", part)))
        })
        .collect()
}

/// Format OID slice as string like "1.3.6.1.2.1.1.1.0"
#[allow(dead_code)] // Used by walk() which is not yet called
fn format_oid(oid: &[u32]) -> String {
    oid.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Check if OID starts with base OID
#[allow(dead_code)] // Used by walk() which is not yet called
fn starts_with(oid: &[u32], base: &[u32]) -> bool {
    if oid.len() < base.len() {
        return false;
    }
    oid[..base.len()] == *base
}

/// Convert snmp crate's Value to our SnmpValue
fn convert_value(value: snmp::Value) -> SnmpResult<SnmpValue> {
    use snmp::Value as V;

    match value {
        V::Integer(i) => Ok(SnmpValue::Integer(i)),
        V::OctetString(s) => Ok(SnmpValue::String(String::from_utf8_lossy(s).into_owned())),
        V::Counter32(c) => Ok(SnmpValue::Counter32(c)),
        V::Counter64(c) => Ok(SnmpValue::Counter64(c)),
        V::Unsigned32(u) => Ok(SnmpValue::Gauge32(u)),
        V::Timeticks(t) => Ok(SnmpValue::TimeTicks(t)),
        V::IpAddress(ip) => Ok(SnmpValue::IpAddress(format!(
            "{}.{}.{}.{}",
            ip[0], ip[1], ip[2], ip[3]
        ))),
        _ => Err(SnmpError::RequestFailed(format!(
            "Unsupported SNMP value type: {:?}",
            value
        ))),
    }
}

/// Map snmp crate errors to our SnmpError
fn map_snmp_error(err: snmp::SnmpError) -> SnmpError {
    use snmp::SnmpError as SE;

    match err {
        SE::SendError => SnmpError::NetworkUnreachable,
        SE::ReceiveError => SnmpError::Timeout,
        SE::CommunityMismatch => SnmpError::AuthFailure,
        _ => SnmpError::RequestFailed(format!("{:?}", err)),
    }
}
