use super::types::{SnmpError, SnmpResult, SnmpValue};
use super::V3Config;
use crate::secret::SecretString;
use snmp2::{Oid, SyncSession};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const SNMP_TIMEOUT_SECS: u64 = 30;

/// Request to perform an SNMP operation
#[derive(Debug)]
pub enum SnmpRequest {
    Get {
        oid: String,
        response_tx: oneshot::Sender<SnmpResult<SnmpValue>>,
    },
    Walk {
        base_oid: String,
        response_tx: oneshot::Sender<SnmpResult<Vec<(String, SnmpValue)>>>,
    },
    Shutdown,
}

/// Configuration for a device poller
#[derive(Clone)]
pub struct DeviceConfig {
    pub ip: String,
    pub port: u16,
    pub version: String,
    pub community: SecretString,
    pub v3_config: Option<V3Config>,
    pub transport: String,
}

impl std::fmt::Debug for DeviceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceConfig")
            .field("ip", &self.ip)
            .field("port", &self.port)
            .field("version", &self.version)
            .field("transport", &self.transport)
            .field("community", &"[REDACTED]")
            .field("v3_config", &self.v3_config)
            .finish()
    }
}

/// Per-device polling thread that maintains a persistent SNMP session
pub struct DevicePoller {
    device_id: String,
    config: DeviceConfig,
    request_tx: mpsc::UnboundedSender<SnmpRequest>,
}

impl DevicePoller {
    /// Spawn a new device poller thread
    pub fn spawn(device_id: String, config: DeviceConfig) -> Self {
        let (request_tx, request_rx) = mpsc::unbounded_channel();

        let device_id_clone = device_id.clone();
        let config_clone = config.clone();

        // Spawn the polling thread with 8MB stack for SNMPv3 crypto operations
        std::thread::Builder::new()
            .name(format!("poller-{}", device_id))
            .stack_size(8 * 1024 * 1024) // 8MB stack (default is 2MB)
            .spawn(move || {
                if let Err(e) = run_poller_thread(device_id_clone, config_clone, request_rx) {
                    tracing::error!("Device poller thread failed: {}", e);
                }
            })
            .expect("Failed to spawn device poller thread");

        tracing::info!("Spawned device poller thread for {}", device_id);

        Self {
            device_id,
            config,
            request_tx,
        }
    }

    /// Send a GET request to the poller thread
    pub async fn get(&self, oid: String) -> SnmpResult<SnmpValue> {
        let (response_tx, response_rx) = oneshot::channel();

        self.request_tx
            .send(SnmpRequest::Get { oid, response_tx })
            .map_err(|_| SnmpError::RequestFailed("Poller thread died".into()))?;

        response_rx
            .await
            .map_err(|_| SnmpError::RequestFailed("Poller thread didn't respond".into()))?
    }

    /// Send a WALK request to the poller thread
    pub async fn walk(&self, base_oid: String) -> SnmpResult<Vec<(String, SnmpValue)>> {
        let (response_tx, response_rx) = oneshot::channel();

        self.request_tx
            .send(SnmpRequest::Walk {
                base_oid,
                response_tx,
            })
            .map_err(|_| SnmpError::RequestFailed("Poller thread died".into()))?;

        response_rx
            .await
            .map_err(|_| SnmpError::RequestFailed("Poller thread didn't respond".into()))?
    }

    /// Shutdown the poller thread
    pub fn shutdown(&self) {
        let _ = self.request_tx.send(SnmpRequest::Shutdown);
    }

    /// Get the device ID
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Get the device config
    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    /// Log device poller status using accessor methods
    pub fn log_status(&self) {
        let id = self.device_id();
        let cfg = self.config();
        tracing::debug!(
            "Device poller {} at {}:{} (version: {})",
            id,
            cfg.ip,
            cfg.port,
            cfg.version
        );
    }
}

/// Run the device poller thread (blocking)
fn run_poller_thread(
    device_id: String,
    config: DeviceConfig,
    mut request_rx: mpsc::UnboundedReceiver<SnmpRequest>,
) -> Result<(), String> {
    tracing::info!(
        "Device poller thread started for {} at {}:{}",
        device_id,
        config.ip,
        config.port
    );

    // Create persistent session
    let addr = format!("{}:{}", config.ip, config.port);
    let mut session = create_session(&addr, &config)?;

    tracing::info!(
        "Created persistent SNMP session for device {} (version: {})",
        device_id,
        config.version
    );

    // Process requests until shutdown
    while let Some(request) = request_rx.blocking_recv() {
        match request {
            SnmpRequest::Get { oid, response_tx } => {
                let result = perform_get(&mut session, &oid);
                let _ = response_tx.send(result);
            }
            SnmpRequest::Walk {
                base_oid,
                response_tx,
            } => {
                let result = perform_walk(&mut session, &base_oid);
                let _ = response_tx.send(result);
            }
            SnmpRequest::Shutdown => {
                tracing::info!("Device poller thread shutting down for {}", device_id);
                break;
            }
        }
    }

    tracing::info!("Device poller thread stopped for {}", device_id);
    Ok(())
}

/// Create an SNMP session based on version and transport
fn create_session(addr: &str, config: &DeviceConfig) -> Result<SyncSession, String> {
    let timeout = Some(Duration::from_secs(SNMP_TIMEOUT_SECS));
    let version_num = parse_snmp_version(&config.version)?;
    let transport = config.transport.to_lowercase();

    // TCP transport warning - not yet implemented
    // TODO: Implement SNMP-over-TCP (RFC 3430) - requires low-level PDU handling
    // since snmp2 crate doesn't expose internal types needed for TCP framing
    if transport == "tcp" {
        tracing::warn!(
            "TCP transport requested for {} but not yet implemented. \
             Falling back to UDP. TCP support requires custom PDU encoder/decoder \
             since snmp2 crate doesn't expose necessary internal types.",
            addr
        );
    }

    // UDP transport (default, also used as fallback for TCP)
    if config.version == "3" {
        let v3_config = config
            .v3_config
            .as_ref()
            .ok_or("v3_config required for SNMPv3")?;
        create_v3_session(addr, timeout, v3_config)
    } else {
        create_v1v2c_session(
            addr,
            config.community.expose().as_bytes(),
            timeout,
            version_num,
        )
    }
}

/// Create v1/v2c session
fn create_v1v2c_session(
    addr: &str,
    community: &[u8],
    timeout: Option<Duration>,
    version: i32,
) -> Result<SyncSession, String> {
    let req_id = 1;

    let result = match version {
        0 => SyncSession::new_v1(addr, community, timeout, req_id),
        1 => SyncSession::new_v2c(addr, community, timeout, req_id),
        _ => return Err(format!("Unsupported SNMP version: {}", version)),
    };

    result.map_err(|e| format!("Failed to create v1/v2c session: {:?}", e))
}

/// Create v3 session
fn create_v3_session(
    addr: &str,
    timeout: Option<Duration>,
    config: &V3Config,
) -> Result<SyncSession, String> {
    use snmp2::v3::{Auth, Security};

    // Parse security level and build Auth enum
    let auth = match config.security_level.trim().to_lowercase().as_str() {
        "noauthnopriv" | "" => Auth::NoAuthNoPriv,
        "authnopriv" => Auth::AuthNoPriv,
        "authpriv" => {
            let cipher = parse_priv_protocol(
                config
                    .priv_protocol
                    .as_deref()
                    .ok_or("Priv protocol required for authPriv")?,
            )?;
            let priv_pass = config
                .priv_password
                .as_ref()
                .map(|s| s.expose())
                .ok_or("Priv password required for authPriv")?;

            Auth::AuthPriv {
                cipher,
                privacy_password: priv_pass.as_bytes().to_vec(),
            }
        }
        _ => {
            return Err(format!(
                "Unsupported security level: '{}'",
                config.security_level
            ))
        }
    };

    let username = config.username.as_bytes();
    let auth_password = config
        .auth_password
        .as_ref()
        .map(|s| s.expose())
        .unwrap_or("")
        .as_bytes();
    let needs_auth_protocol = !matches!(auth, Auth::NoAuthNoPriv);

    let mut security = Security::new(username, auth_password).with_auth(auth);

    if needs_auth_protocol {
        let auth_proto = parse_auth_protocol(config.auth_protocol.as_deref().unwrap())?;
        security = security.with_auth_protocol(auth_proto);
    }

    let req_id = 1;
    let mut session = SyncSession::new_v3(addr, timeout, req_id, security)
        .map_err(|e| format!("Failed to create v3 session: {:?}", e))?;

    // For authPriv/authNoPriv, perform engine ID discovery using session.init()
    if needs_auth_protocol {
        session
            .init()
            .map_err(|e| format!("Engine ID discovery failed: {:?}", e))?;
    }

    Ok(session)
}

/// Perform SNMP GET on existing session (with retry for v3 engine ID discovery)
fn perform_get(session: &mut SyncSession, oid: &str) -> SnmpResult<SnmpValue> {
    let oid_parsed =
        Oid::from_str(oid).map_err(|_| SnmpError::InvalidOid(format!("Invalid OID: {}", oid)))?;

    // First attempt (may fail with AuthUpdated for v3 engine ID discovery)
    let mut response = match session.get(&oid_parsed) {
        Ok(resp) => resp,
        Err(snmp2::Error::AuthUpdated) => {
            tracing::debug!("SNMPv3 engine ID discovered, retrying request");
            // Retry after engine ID discovery
            session.get(&oid_parsed).map_err(map_snmp_error)?
        }
        Err(e) => return Err(map_snmp_error(e)),
    };

    if response.error_status != 0 {
        return Err(SnmpError::RequestFailed(format!(
            "SNMP error status: {}",
            response.error_status
        )));
    }

    let (_, value) = response
        .varbinds
        .next()
        .ok_or(SnmpError::RequestFailed("No varbinds in response".into()))?;

    convert_value(value)
}

/// Perform SNMP WALK on existing session (with retry for v3 engine ID discovery)
fn perform_walk(session: &mut SyncSession, base_oid: &str) -> SnmpResult<Vec<(String, SnmpValue)>> {
    let base_oid_parsed = Oid::from_str(base_oid)
        .map_err(|_| SnmpError::InvalidOid(format!("Invalid OID: {}", base_oid)))?;
    let base_oid_string = base_oid.to_string();

    let mut results = Vec::new();
    let mut current_oid = base_oid_parsed;
    let mut first_request = true;

    loop {
        let oid_to_query = current_oid.clone();

        let (error_status, varbind_data) = {
            // First request may fail with AuthUpdated for v3 engine ID discovery
            let response = match session.getnext(&oid_to_query) {
                Ok(resp) => resp,
                Err(snmp2::Error::AuthUpdated) if first_request => {
                    tracing::debug!("SNMPv3 engine ID discovered, retrying WALK request");
                    // Retry after engine ID discovery
                    session.getnext(&oid_to_query).map_err(map_snmp_error)?
                }
                Err(e) => return Err(map_snmp_error(e)),
            };

            // After first request, don't retry on AuthUpdated
            first_request = false;
            let status = response.error_status;

            let data: Vec<(String, snmp2::Value)> = response
                .varbinds
                .map(|(name, value)| (name.to_string(), value))
                .collect();

            (status, data)
        };

        if error_status != 0 {
            break;
        }

        if varbind_data.is_empty() {
            break;
        }

        for (name_str, value) in varbind_data {
            if !name_str.starts_with(&base_oid_string) {
                return Ok(results);
            }

            let converted_value = convert_value(value)?;
            results.push((name_str.clone(), converted_value));

            current_oid = Oid::from_str(&name_str).map_err(|_| {
                SnmpError::InvalidOid(format!("Invalid OID from response: {}", name_str))
            })?;
        }
    }

    Ok(results)
}

/// Parse SNMP version string to integer
fn parse_snmp_version(version: &str) -> Result<i32, String> {
    match version.trim().to_lowercase().as_str() {
        "1" | "v1" | "snmpv1" => Ok(0),
        "2c" | "v2c" | "snmpv2c" | "2" | "v2" => Ok(1),
        "3" | "v3" | "snmpv3" => Ok(3),
        _ => Err(format!("Unsupported SNMP version: '{}'", version)),
    }
}

/// Parse authentication protocol
fn parse_auth_protocol(protocol: &str) -> Result<snmp2::v3::AuthProtocol, String> {
    use snmp2::v3::AuthProtocol;

    match protocol.trim().to_uppercase().as_str() {
        "MD5" => Ok(AuthProtocol::Md5),
        "SHA" | "SHA1" | "SHA-1" => Ok(AuthProtocol::Sha1),
        "SHA224" | "SHA-224" => Ok(AuthProtocol::Sha224),
        "SHA256" | "SHA-256" => Ok(AuthProtocol::Sha256),
        "SHA384" | "SHA-384" => Ok(AuthProtocol::Sha384),
        "SHA512" | "SHA-512" => Ok(AuthProtocol::Sha512),
        _ => Err(format!("Unsupported auth protocol: '{}'", protocol)),
    }
}

/// Parse privacy protocol
fn parse_priv_protocol(protocol: &str) -> Result<snmp2::v3::Cipher, String> {
    use snmp2::v3::Cipher;

    match protocol.trim().to_uppercase().as_str() {
        "DES" => Ok(Cipher::Des),
        "AES" | "AES128" | "AES-128" => Ok(Cipher::Aes128),
        "AES192" | "AES-192" => Ok(Cipher::Aes192),
        "AES256" | "AES-256" | "AES-256-C" => Ok(Cipher::Aes256),
        _ => Err(format!("Unsupported priv protocol: '{}'", protocol)),
    }
}

/// Map snmp2 errors to our error type
fn map_snmp_error(err: snmp2::Error) -> SnmpError {
    match &err {
        snmp2::Error::AuthFailure(kind) => {
            tracing::error!("SNMPv3 AuthFailure: {:?}", kind);
            SnmpError::AuthFailure
        }
        snmp2::Error::AuthUpdated => {
            tracing::info!("SNMPv3 engine ID discovered, caller should retry");
            SnmpError::RequestFailed("Authentication context updated, need to retry".into())
        }
        snmp2::Error::CommunityMismatch => SnmpError::AuthFailure,
        _ => {
            tracing::error!("SNMP error: {:?}", err);
            SnmpError::RequestFailed(format!("SNMP request failed: {:?}", err))
        }
    }
}

/// Convert snmp2::Value to our SnmpValue
fn convert_value(value: snmp2::Value) -> SnmpResult<SnmpValue> {
    match value {
        snmp2::Value::Integer(i) => Ok(SnmpValue::Integer(i)),
        snmp2::Value::OctetString(bytes) => Ok(String::from_utf8(bytes.to_vec())
            .map(SnmpValue::String)
            .unwrap_or_else(|_| SnmpValue::OctetString(bytes.to_vec()))),
        snmp2::Value::ObjectIdentifier(oid) => Ok(SnmpValue::Oid(oid.to_string())),
        snmp2::Value::Counter32(c) => Ok(SnmpValue::Counter32(c)),
        snmp2::Value::Counter64(c) => Ok(SnmpValue::Counter64(c)),
        snmp2::Value::Unsigned32(g) => Ok(SnmpValue::Gauge32(g)),
        snmp2::Value::Timeticks(t) => Ok(SnmpValue::TimeTicks(t)),
        snmp2::Value::IpAddress(ip) => Ok(SnmpValue::IpAddress(format!(
            "{}.{}.{}.{}",
            ip[0], ip[1], ip[2], ip[3]
        ))),
        snmp2::Value::Null => Ok(SnmpValue::Null),
        _ => Ok(SnmpValue::Unsupported(format!("{:?}", value))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_auth_protocol_standard() {
        use snmp2::v3::AuthProtocol;
        assert!(matches!(parse_auth_protocol("MD5"), Ok(AuthProtocol::Md5)));
        assert!(matches!(
            parse_auth_protocol("SHA"),
            Ok(AuthProtocol::Sha1)
        ));
        assert!(matches!(
            parse_auth_protocol("SHA1"),
            Ok(AuthProtocol::Sha1)
        ));
        assert!(matches!(
            parse_auth_protocol("SHA256"),
            Ok(AuthProtocol::Sha256)
        ));
        assert!(matches!(
            parse_auth_protocol("SHA384"),
            Ok(AuthProtocol::Sha384)
        ));
        assert!(matches!(
            parse_auth_protocol("SHA512"),
            Ok(AuthProtocol::Sha512)
        ));
    }

    #[test]
    fn test_parse_auth_protocol_hyphenated() {
        use snmp2::v3::AuthProtocol;
        assert!(matches!(
            parse_auth_protocol("SHA-1"),
            Ok(AuthProtocol::Sha1)
        ));
        assert!(matches!(
            parse_auth_protocol("SHA-224"),
            Ok(AuthProtocol::Sha224)
        ));
        assert!(matches!(
            parse_auth_protocol("SHA-256"),
            Ok(AuthProtocol::Sha256)
        ));
        assert!(matches!(
            parse_auth_protocol("SHA-384"),
            Ok(AuthProtocol::Sha384)
        ));
        assert!(matches!(
            parse_auth_protocol("SHA-512"),
            Ok(AuthProtocol::Sha512)
        ));
    }

    #[test]
    fn test_parse_auth_protocol_case_insensitive() {
        use snmp2::v3::AuthProtocol;
        assert!(matches!(
            parse_auth_protocol("sha-256"),
            Ok(AuthProtocol::Sha256)
        ));
        assert!(matches!(
            parse_auth_protocol("md5"),
            Ok(AuthProtocol::Md5)
        ));
    }

    #[test]
    fn test_parse_auth_protocol_invalid() {
        assert!(parse_auth_protocol("INVALID").is_err());
    }

    #[test]
    fn test_parse_priv_protocol_standard() {
        use snmp2::v3::Cipher;
        assert!(matches!(parse_priv_protocol("DES"), Ok(Cipher::Des)));
        assert!(matches!(parse_priv_protocol("AES"), Ok(Cipher::Aes128)));
        assert!(matches!(
            parse_priv_protocol("AES128"),
            Ok(Cipher::Aes128)
        ));
        assert!(matches!(
            parse_priv_protocol("AES192"),
            Ok(Cipher::Aes192)
        ));
        assert!(matches!(
            parse_priv_protocol("AES256"),
            Ok(Cipher::Aes256)
        ));
    }

    #[test]
    fn test_parse_priv_protocol_hyphenated() {
        use snmp2::v3::Cipher;
        assert!(matches!(
            parse_priv_protocol("AES-128"),
            Ok(Cipher::Aes128)
        ));
        assert!(matches!(
            parse_priv_protocol("AES-192"),
            Ok(Cipher::Aes192)
        ));
        assert!(matches!(
            parse_priv_protocol("AES-256"),
            Ok(Cipher::Aes256)
        ));
        assert!(matches!(
            parse_priv_protocol("AES-256-C"),
            Ok(Cipher::Aes256)
        ));
    }

    #[test]
    fn test_parse_priv_protocol_invalid() {
        assert!(parse_priv_protocol("INVALID").is_err());
    }
}
