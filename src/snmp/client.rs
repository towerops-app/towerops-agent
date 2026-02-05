use super::types::{SnmpError, SnmpResult, SnmpValue};
use crate::secret::SecretString;
use snmp2::SyncSession;
use std::time::Duration;

// SNMP timeout in seconds - increased to 60s for SNMPv3 operations
// SNMPv3 has significant encryption/auth overhead, especially for large walks
// MikroTik enterprise tree (1.3.6.1.4.1.14988) can take 16+ seconds with v3
const SNMP_TIMEOUT_SECS: u64 = 60;

/// SNMPv3 configuration bundle
#[derive(Clone)]
pub struct V3Config {
    pub username: String,
    pub auth_password: Option<SecretString>,
    pub priv_password: Option<SecretString>,
    pub auth_protocol: Option<String>,
    pub priv_protocol: Option<String>,
    pub security_level: String,
}

impl std::fmt::Debug for V3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3Config")
            .field("username", &self.username)
            .field(
                "auth_password",
                &self.auth_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "priv_password",
                &self.priv_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("auth_protocol", &self.auth_protocol)
            .field("priv_protocol", &self.priv_protocol)
            .field("security_level", &self.security_level)
            .finish()
    }
}

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
        v3_config: Option<V3Config>,
    ) -> SnmpResult<SnmpValue> {
        use snmp2::Oid;
        use std::str::FromStr;

        // Parse OID string
        let oid_parsed = Oid::from_str(oid)
            .map_err(|_| SnmpError::InvalidOid(format!("Invalid OID: {}", oid)))?;

        // Clone data for the blocking task
        let addr = format!("{}:{}", ip_address, port);
        let community = community.as_bytes().to_vec();
        let version_num = parse_snmp_version(version)?;

        // Run SNMP operation in blocking thread pool
        let result = tokio::task::spawn_blocking(move || {
            // Create session based on version
            let mut session = if version_num == 3 {
                let config = v3_config.ok_or_else(|| {
                    SnmpError::RequestFailed("SNMPv3 config required for version 3".into())
                })?;
                create_v3_session(&addr, &config)?
            } else {
                create_v1v2c_session(&addr, &community, version_num)?
            };

            // Perform GET request (with retry for v3 engine ID discovery)
            let mut response = match session.get(&oid_parsed) {
                Ok(resp) => resp,
                Err(snmp2::Error::AuthUpdated) => {
                    tracing::debug!("SNMPv3 engine ID discovered, retrying request");
                    // Retry after engine ID discovery
                    session.get(&oid_parsed).map_err(map_snmp_error)?
                }
                Err(e) => return Err(map_snmp_error(e)),
            };

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
        v3_config: Option<V3Config>,
    ) -> SnmpResult<Vec<(String, SnmpValue)>> {
        use snmp2::Oid;
        use std::str::FromStr;

        // Parse base OID string and clone it for moving into async block
        let base_oid_parsed = Oid::from_str(base_oid)
            .map_err(|_| SnmpError::InvalidOid(format!("Invalid base OID: {}", base_oid)))?;
        let base_oid_string = base_oid.to_string();

        // Clone data for the blocking task
        let addr = format!("{}:{}", ip_address, port);
        let community = community.as_bytes().to_vec();
        let version_num = parse_snmp_version(version)?;

        // Run SNMP walk in blocking thread pool
        let results = tokio::task::spawn_blocking(move || {
            // Create session based on version
            let mut session = if version_num == 3 {
                let config = v3_config.ok_or_else(|| {
                    SnmpError::RequestFailed("SNMPv3 config required for version 3".into())
                })?;
                create_v3_session(&addr, &config)?
            } else {
                create_v1v2c_session(&addr, &community, version_num)?
            };

            let mut results = Vec::new();
            let mut current_oid = base_oid_parsed;

            // Perform GETNEXT repeatedly until we leave the base OID tree
            loop {
                let oid_to_query = current_oid.clone();

                // Extract data we need from the response immediately
                let (error_status, varbind_data) = {
                    // Perform GETNEXT request (with retry for v3 engine ID discovery)
                    let response = match session.getnext(&oid_to_query) {
                        Ok(resp) => resp,
                        Err(snmp2::Error::AuthUpdated) => {
                            tracing::debug!("SNMPv3 engine ID discovered, retrying getnext");
                            // Retry after engine ID discovery
                            session.getnext(&oid_to_query).map_err(map_snmp_error)?
                        }
                        Err(e) => return Err(map_snmp_error(e)),
                    };
                    let status = response.error_status;

                    // Collect all varbind data as owned strings/values immediately
                    let data: Vec<(String, snmp2::Value)> = response
                        .varbinds
                        .map(|(name, value)| (name.to_string(), value))
                        .collect();

                    (status, data)
                    // response is dropped here, ending the mutable borrow of session
                };

                // Check for error status
                if error_status != 0 {
                    break;
                }

                if varbind_data.is_empty() {
                    break;
                }

                // Process the owned varbind data
                for (name_str, value) in varbind_data {
                    // Check if the returned OID starts with our base OID
                    if !name_str.starts_with(&base_oid_string) {
                        return Ok(results);
                    }

                    // Convert value
                    let converted_value = convert_value(value)?;

                    results.push((name_str.clone(), converted_value));

                    // Update current OID for next iteration (parse from string)
                    current_oid = Oid::from_str(&name_str).map_err(|_| {
                        SnmpError::InvalidOid(format!("Invalid OID from response: {}", name_str))
                    })?;
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

/// Parse SNMP version string to integer for snmp2 crate
/// Returns: 0 for SNMPv1, 1 for SNMPv2c, 3 for SNMPv3
fn parse_snmp_version(version: &str) -> SnmpResult<i32> {
    let normalized = version.trim().to_lowercase();

    match normalized.as_str() {
        "1" | "v1" | "snmpv1" => Ok(0),
        "2c" | "v2c" | "snmpv2c" | "2" | "v2" => Ok(1),
        "3" | "v3" | "snmpv3" => Ok(3),
        _ => Err(SnmpError::RequestFailed(format!(
            "Unsupported SNMP version: '{}'. Supported versions: 1, v1, 2c, v2c, 3, v3",
            version
        ))),
    }
}

/// Parse authentication protocol string to snmp2 AuthProtocol enum
fn parse_auth_protocol(protocol: &str) -> SnmpResult<snmp2::v3::AuthProtocol> {
    use snmp2::v3::AuthProtocol;

    match protocol.trim().to_uppercase().as_str() {
        "MD5" => Ok(AuthProtocol::Md5),
        "SHA" | "SHA1" | "SHA-1" => Ok(AuthProtocol::Sha1),
        "SHA-224" | "SHA224" => Ok(AuthProtocol::Sha224),
        "SHA-256" | "SHA256" => Ok(AuthProtocol::Sha256),
        "SHA-384" | "SHA384" => Ok(AuthProtocol::Sha384),
        "SHA-512" | "SHA512" => Ok(AuthProtocol::Sha512),
        _ => Err(SnmpError::RequestFailed(format!(
            "Unsupported auth protocol: '{}'",
            protocol
        ))),
    }
}

/// Parse privacy protocol string to snmp2 Cipher enum
fn parse_priv_protocol(protocol: &str) -> SnmpResult<snmp2::v3::Cipher> {
    use snmp2::v3::Cipher;

    match protocol.trim().to_uppercase().as_str() {
        "DES" => Ok(Cipher::Des),
        "AES" | "AES-128" | "AES128" => Ok(Cipher::Aes128),
        "AES-192" | "AES192" => Ok(Cipher::Aes192),
        "AES-256" | "AES256" | "AES-256-C" | "AES256C" => Ok(Cipher::Aes256),
        _ => Err(SnmpError::RequestFailed(format!(
            "Unsupported priv protocol: '{}'",
            protocol
        ))),
    }
}

/// Create SNMPv1/v2c session
fn create_v1v2c_session(addr: &str, community: &[u8], version: i32) -> SnmpResult<SyncSession> {
    let timeout = Some(Duration::from_secs(SNMP_TIMEOUT_SECS));
    let req_id = 1;

    if version == 0 {
        SyncSession::new_v1(addr, community, timeout, req_id)
            .map_err(|_| SnmpError::NetworkUnreachable)
    } else {
        SyncSession::new_v2c(addr, community, timeout, req_id)
            .map_err(|_| SnmpError::NetworkUnreachable)
    }
}

/// Create SNMPv3 session with authentication and/or privacy
fn create_v3_session(addr: &str, config: &V3Config) -> SnmpResult<SyncSession> {
    use snmp2::v3::{Auth, Security};

    let username = config.username.as_bytes();
    let security_level = config.security_level.trim().to_lowercase();

    // Build the Auth enum based on security level
    let auth = match security_level.as_str() {
        "noauthnopriv" | "" => Auth::NoAuthNoPriv,

        "authnopriv" => {
            // Requires auth protocol and password
            let _auth_proto =
                parse_auth_protocol(config.auth_protocol.as_deref().ok_or_else(|| {
                    SnmpError::RequestFailed("Auth protocol required for authNoPriv".into())
                })?)?;
            let _auth_pass = config
                .auth_password
                .as_ref()
                .map(|s| s.expose())
                .ok_or_else(|| {
                    SnmpError::RequestFailed("Auth password required for authNoPriv".into())
                })?;
            Auth::AuthNoPriv
        }

        "authpriv" => {
            // Requires auth and priv protocol/passwords
            let _auth_proto =
                parse_auth_protocol(config.auth_protocol.as_deref().ok_or_else(|| {
                    SnmpError::RequestFailed("Auth protocol required for authPriv".into())
                })?)?;
            let _auth_pass = config
                .auth_password
                .as_ref()
                .map(|s| s.expose())
                .ok_or_else(|| {
                    SnmpError::RequestFailed("Auth password required for authPriv".into())
                })?;
            let cipher =
                parse_priv_protocol(config.priv_protocol.as_deref().ok_or_else(|| {
                    SnmpError::RequestFailed("Priv protocol required for authPriv".into())
                })?)?;
            let priv_pass = config
                .priv_password
                .as_ref()
                .map(|s| s.expose())
                .ok_or_else(|| {
                    SnmpError::RequestFailed("Priv password required for authPriv".into())
                })?;

            Auth::AuthPriv {
                cipher,
                privacy_password: priv_pass.as_bytes().to_vec(),
            }
        }

        _ => {
            return Err(SnmpError::RequestFailed(format!(
                "Unsupported security level: '{}'",
                config.security_level
            )))
        }
    };

    // Get auth password (empty for noAuthNoPriv)
    let auth_password = config
        .auth_password
        .as_ref()
        .map(|s| s.expose())
        .unwrap_or("")
        .as_bytes();

    // Determine if we need auth protocol (before auth is moved)
    let needs_auth_protocol = !matches!(auth, Auth::NoAuthNoPriv);

    // Build Security object
    let mut security = Security::new(username, auth_password).with_auth(auth);

    // Set auth protocol if authentication is required
    if needs_auth_protocol {
        let auth_proto = parse_auth_protocol(config.auth_protocol.as_deref().unwrap())?;
        security = security.with_auth_protocol(auth_proto);
    }

    // Create v3 session
    let timeout = Some(Duration::from_secs(SNMP_TIMEOUT_SECS));
    let req_id = 1;

    let mut session = SyncSession::new_v3(addr, timeout, req_id, security).map_err(|e| {
        SnmpError::RequestFailed(format!("SNMPv3 session creation failed: {:?}", e))
    })?;

    // For authPriv/authNoPriv, perform engine ID discovery using session.init()
    if needs_auth_protocol {
        session.init().map_err(|e| {
            SnmpError::RequestFailed(format!("Engine ID discovery failed: {:?}", e))
        })?;
    }

    Ok(session)
}

/// Convert snmp2 crate's Value to our SnmpValue
fn convert_value(value: snmp2::Value) -> SnmpResult<SnmpValue> {
    use snmp2::Value as V;

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

/// Map snmp2 crate errors to our SnmpError
fn map_snmp_error(err: snmp2::Error) -> SnmpError {
    use snmp2::Error;

    match err {
        Error::Send => SnmpError::NetworkUnreachable,
        Error::Receive => SnmpError::Timeout,
        Error::CommunityMismatch => SnmpError::AuthFailure,
        Error::AuthFailure(_) => SnmpError::AuthFailure,
        _ => SnmpError::RequestFailed(format!("{:?}", err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snmp_client_new() {
        let client = SnmpClient::new();
        // Just verify we can create it
        assert!(format!("{:?}", client).contains("SnmpClient"));
    }

    #[test]
    fn test_snmp_client_default() {
        let client = SnmpClient;
        assert!(format!("{:?}", client).contains("SnmpClient"));
    }

    #[test]
    fn test_parse_snmp_version_v1() {
        assert_eq!(parse_snmp_version("1").unwrap(), 0);
        assert_eq!(parse_snmp_version("v1").unwrap(), 0);
        assert_eq!(parse_snmp_version("V1").unwrap(), 0);
        assert_eq!(parse_snmp_version("snmpv1").unwrap(), 0);
    }

    #[test]
    fn test_parse_snmp_version_v2c() {
        assert_eq!(parse_snmp_version("2c").unwrap(), 1);
        assert_eq!(parse_snmp_version("2C").unwrap(), 1);
        assert_eq!(parse_snmp_version("v2c").unwrap(), 1);
        assert_eq!(parse_snmp_version("V2C").unwrap(), 1);
        assert_eq!(parse_snmp_version("2").unwrap(), 1);
        assert_eq!(parse_snmp_version("v2").unwrap(), 1);
    }

    #[test]
    fn test_parse_snmp_version_v3() {
        assert_eq!(parse_snmp_version("3").unwrap(), 3);
        assert_eq!(parse_snmp_version("v3").unwrap(), 3);
        assert_eq!(parse_snmp_version("V3").unwrap(), 3);
        assert_eq!(parse_snmp_version("snmpv3").unwrap(), 3);
    }

    #[test]
    fn test_parse_snmp_version_invalid() {
        let result = parse_snmp_version("invalid");
        assert!(result.is_err());
        match result {
            Err(SnmpError::RequestFailed(msg)) => {
                assert!(msg.contains("Unsupported SNMP version"));
            }
            _ => panic!("Expected RequestFailed error"),
        }
    }

    #[test]
    fn test_parse_auth_protocol() {
        use snmp2::v3::AuthProtocol;
        assert!(matches!(parse_auth_protocol("MD5"), Ok(AuthProtocol::Md5)));
        assert!(matches!(parse_auth_protocol("SHA"), Ok(AuthProtocol::Sha1)));
        assert!(matches!(
            parse_auth_protocol("SHA-256"),
            Ok(AuthProtocol::Sha256)
        ));
        assert!(matches!(
            parse_auth_protocol("SHA-512"),
            Ok(AuthProtocol::Sha512)
        ));
    }

    #[test]
    fn test_parse_priv_protocol() {
        use snmp2::v3::Cipher;
        assert!(matches!(parse_priv_protocol("DES"), Ok(Cipher::Des)));
        assert!(matches!(parse_priv_protocol("AES"), Ok(Cipher::Aes128)));
        assert!(matches!(parse_priv_protocol("AES-256"), Ok(Cipher::Aes256)));
    }

    #[test]
    fn test_convert_value_integer() {
        let value = snmp2::Value::Integer(42);
        let result = convert_value(value).unwrap();
        match result {
            SnmpValue::Integer(v) => assert_eq!(v, 42),
            _ => panic!("Expected Integer"),
        }
    }

    #[test]
    fn test_convert_value_octet_string() {
        let value = snmp2::Value::OctetString(b"test".as_slice());
        let result = convert_value(value).unwrap();
        match result {
            SnmpValue::String(s) => assert_eq!(s, "test"),
            _ => panic!("Expected String"),
        }
    }

    #[test]
    fn test_convert_value_counter32() {
        let value = snmp2::Value::Counter32(12345);
        let result = convert_value(value).unwrap();
        match result {
            SnmpValue::Counter32(v) => assert_eq!(v, 12345),
            _ => panic!("Expected Counter32"),
        }
    }

    #[test]
    fn test_convert_value_counter64() {
        let value = snmp2::Value::Counter64(9876543210);
        let result = convert_value(value).unwrap();
        match result {
            SnmpValue::Counter64(v) => assert_eq!(v, 9876543210),
            _ => panic!("Expected Counter64"),
        }
    }

    #[test]
    fn test_convert_value_unsigned32() {
        let value = snmp2::Value::Unsigned32(999);
        let result = convert_value(value).unwrap();
        match result {
            SnmpValue::Gauge32(v) => assert_eq!(v, 999),
            _ => panic!("Expected Gauge32"),
        }
    }

    #[test]
    fn test_convert_value_timeticks() {
        let value = snmp2::Value::Timeticks(12345678);
        let result = convert_value(value).unwrap();
        match result {
            SnmpValue::TimeTicks(v) => assert_eq!(v, 12345678),
            _ => panic!("Expected TimeTicks"),
        }
    }

    #[test]
    fn test_convert_value_ip_address() {
        let value = snmp2::Value::IpAddress([192, 168, 1, 1]);
        let result = convert_value(value).unwrap();
        match result {
            SnmpValue::IpAddress(ip) => assert_eq!(ip, "192.168.1.1"),
            _ => panic!("Expected IpAddress"),
        }
    }

    #[test]
    fn test_map_snmp_error_send() {
        let err = snmp2::Error::Send;
        let result = map_snmp_error(err);
        match result {
            SnmpError::NetworkUnreachable => {}
            _ => panic!("Expected NetworkUnreachable"),
        }
    }

    #[test]
    fn test_map_snmp_error_receive() {
        let err = snmp2::Error::Receive;
        let result = map_snmp_error(err);
        match result {
            SnmpError::Timeout => {}
            _ => panic!("Expected Timeout"),
        }
    }

    #[test]
    fn test_map_snmp_error_community() {
        let err = snmp2::Error::CommunityMismatch;
        let result = map_snmp_error(err);
        match result {
            SnmpError::AuthFailure => {}
            _ => panic!("Expected AuthFailure"),
        }
    }

    // Note: get() and walk() methods require actual network operations
    // and are tested via integration tests, not unit tests
}
