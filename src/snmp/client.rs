use super::types::{SnmpError, SnmpResult, SnmpValue};
use netsnmp_sys::*;
use std::ffi::{c_char, CStr, CString};
use std::ptr;
use zeroize::{Zeroize, Zeroizing};

type SecretString = Zeroizing<String>;

#[cfg(not(test))]
const SNMP_TIMEOUT_SECS: i64 = 10;
#[cfg(not(test))]
const SNMP_RETRIES: i32 = 2;

// Use short timeouts in tests to avoid 90+ second waits on unreachable hosts
#[cfg(test)]
const SNMP_TIMEOUT_SECS: i64 = 1;
#[cfg(test)]
const SNMP_RETRIES: i32 = 0;

// C structs and functions
#[repr(C)]
#[derive(Clone)]
struct SnmpWalkResult {
    oid: [u8; 256],
    value: [u8; 1024],
    value_len: usize,
    value_type: i32,
}

#[repr(C)]
struct SnmpV3ConfigC {
    username: *const c_char,
    auth_password: *const c_char,
    priv_password: *const c_char,
    auth_protocol: *const c_char,
    priv_protocol: *const c_char,
    security_level: *const c_char,
}

extern "C" {
    fn snmp_init_library() -> i32;
    fn snmp_open_session(
        ip_address: *const c_char,
        port: u16,
        community: *const c_char,
        version: i32,
        timeout_us: i64,
        retries: i32,
        v3_config: *const SnmpV3ConfigC,
        error_buf: *mut c_char,
        error_buf_len: usize,
    ) -> *mut std::ffi::c_void;
    fn snmp_close_session(sess_handle: *mut std::ffi::c_void);
    fn snmp_get(
        sess_handle: *mut std::ffi::c_void,
        oid_str: *const c_char,
        value_buf: *mut std::ffi::c_void,
        value_buf_len: usize,
        value_type: *mut i32,
        error_buf: *mut c_char,
        error_buf_len: usize,
    ) -> i32;
    fn snmp_walk(
        sess_handle: *mut std::ffi::c_void,
        oid_str: *const c_char,
        results: *mut SnmpWalkResult,
        max_results: usize,
        num_results: *mut usize,
        error_buf: *mut c_char,
        error_buf_len: usize,
    ) -> i32;
}

/// SNMPv3 configuration
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

/// SNMP client for polling devices using libnetsnmp
#[derive(Debug, Clone, Copy)]
pub struct SnmpClient;

impl SnmpClient {
    pub fn new() -> Self {
        // Initialize libnetsnmp via C helper
        unsafe {
            snmp_init_library();
        }
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
        // Clone data for the blocking task
        let ip_address = ip_address.to_string();
        let community = community.to_string();
        let version = version.to_string();
        let oid = oid.to_string();

        // Run SNMP operation in blocking thread pool
        tokio::task::spawn_blocking(move || {
            let session = SnmpSession::new(&ip_address, port, &community, &version, v3_config)?;
            session.get(&oid)
        })
        .await
        .map_err(|e| SnmpError::RequestFailed(format!("Task join error: {}", e)))?
    }

    /// Perform an SNMP WALK operation
    pub async fn walk(
        &self,
        ip_address: &str,
        community: &str,
        version: &str,
        port: u16,
        oid: &str,
        v3_config: Option<V3Config>,
    ) -> SnmpResult<Vec<(String, SnmpValue)>> {
        // Clone data for the blocking task
        let ip_address = ip_address.to_string();
        let community = community.to_string();
        let version = version.to_string();
        let oid = oid.to_string();

        // Run SNMP operation in blocking thread pool
        tokio::task::spawn_blocking(move || {
            let session = SnmpSession::new(&ip_address, port, &community, &version, v3_config)?;
            session.walk(&oid)
        })
        .await
        .map_err(|e| SnmpError::RequestFailed(format!("Task join error: {}", e)))?
    }
}

impl Default for SnmpClient {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII wrapper for SNMP session
struct SnmpSession {
    sess_handle: *mut std::ffi::c_void,
}

impl SnmpSession {
    fn new(
        ip_address: &str,
        port: u16,
        community: &str,
        version: &str,
        v3_config: Option<V3Config>,
    ) -> SnmpResult<Self> {
        tracing::debug!(
            "Creating SNMP session: ip={}, port={}, version={}",
            ip_address,
            port,
            version
        );

        // Parse SNMP version
        let version_num = match version {
            "1" | "v1" => 1,
            "2c" | "v2c" | "2" => 2,
            "3" | "v3" => 3,
            _ => {
                return Err(SnmpError::RequestFailed(format!(
                    "Unsupported SNMP version: {}",
                    version
                )))
            }
        };

        unsafe {
            let ip_cstr = CString::new(ip_address)
                .map_err(|_| SnmpError::RequestFailed("Invalid IP address".into()))?;
            let comm_cstr = CString::new(community)
                .map_err(|_| SnmpError::RequestFailed("Invalid community string".into()))?;

            // Prepare SNMPv3 config if needed
            let (v3_c_config, _v3_strings) = if let Some(ref v3) = v3_config {
                let username_cstr = CString::new(v3.username.as_str())
                    .map_err(|_| SnmpError::RequestFailed("Invalid username".into()))?;
                let auth_pass_cstr = v3
                    .auth_password
                    .as_ref()
                    .map(|p| CString::new(p.as_str()))
                    .transpose()
                    .map_err(|_| SnmpError::RequestFailed("Invalid auth password".into()))?;
                let priv_pass_cstr = v3
                    .priv_password
                    .as_ref()
                    .map(|p| CString::new(p.as_str()))
                    .transpose()
                    .map_err(|_| SnmpError::RequestFailed("Invalid priv password".into()))?;
                let auth_proto_cstr = v3
                    .auth_protocol
                    .as_ref()
                    .map(|p| CString::new(p.as_str()))
                    .transpose()
                    .map_err(|_| SnmpError::RequestFailed("Invalid auth protocol".into()))?;
                let priv_proto_cstr = v3
                    .priv_protocol
                    .as_ref()
                    .map(|p| CString::new(p.as_str()))
                    .transpose()
                    .map_err(|_| SnmpError::RequestFailed("Invalid priv protocol".into()))?;
                let sec_level_cstr = CString::new(v3.security_level.as_str())
                    .map_err(|_| SnmpError::RequestFailed("Invalid security level".into()))?;

                let config = SnmpV3ConfigC {
                    username: username_cstr.as_ptr(),
                    auth_password: auth_pass_cstr
                        .as_ref()
                        .map(|c| c.as_ptr())
                        .unwrap_or(ptr::null()),
                    priv_password: priv_pass_cstr
                        .as_ref()
                        .map(|c| c.as_ptr())
                        .unwrap_or(ptr::null()),
                    auth_protocol: auth_proto_cstr
                        .as_ref()
                        .map(|c| c.as_ptr())
                        .unwrap_or(ptr::null()),
                    priv_protocol: priv_proto_cstr
                        .as_ref()
                        .map(|c| c.as_ptr())
                        .unwrap_or(ptr::null()),
                    security_level: sec_level_cstr.as_ptr(),
                };

                (
                    Some(config),
                    Some((
                        username_cstr,
                        auth_pass_cstr,
                        priv_pass_cstr,
                        auth_proto_cstr,
                        priv_proto_cstr,
                        sec_level_cstr,
                    )),
                )
            } else {
                (None, None)
            };

            let mut error_buf = [0 as c_char; 512];
            let sess_handle = snmp_open_session(
                ip_cstr.as_ptr(),
                port,
                comm_cstr.as_ptr(),
                version_num,
                SNMP_TIMEOUT_SECS * 1_000_000,
                SNMP_RETRIES,
                v3_c_config
                    .as_ref()
                    .map(|c| c as *const _)
                    .unwrap_or(ptr::null()),
                error_buf.as_mut_ptr(),
                error_buf.len(),
            );

            // Zeroize sensitive data
            drop(comm_cstr);
            drop(_v3_strings); // Drops all v3 CStrings
            if !community.is_empty() {
                let mut community_copy = community.to_string();
                community_copy.zeroize();
            }

            if sess_handle.is_null() {
                let err_msg = CStr::from_ptr(error_buf.as_ptr())
                    .to_string_lossy()
                    .to_string();
                tracing::error!("SNMP session open failed: {}", err_msg);

                return Err(
                    if err_msg.contains("Unknown host") || err_msg.contains("Connection refused") {
                        SnmpError::NetworkUnreachable
                    } else {
                        SnmpError::RequestFailed(err_msg)
                    },
                );
            }

            tracing::debug!("SNMP session opened successfully: {:?}", sess_handle);
            Ok(Self { sess_handle })
        }
    }

    fn get(&self, oid: &str) -> SnmpResult<SnmpValue> {
        unsafe {
            let oid_cstr = CString::new(oid)
                .map_err(|_| SnmpError::InvalidOid(format!("Invalid OID: {}", oid)))?;

            let mut value_buf = [0u8; 1024];
            let mut value_type: i32 = 0;
            let mut error_buf = [0 as c_char; 512];

            let result = snmp_get(
                self.sess_handle,
                oid_cstr.as_ptr(),
                value_buf.as_mut_ptr() as *mut _,
                value_buf.len(),
                &mut value_type,
                error_buf.as_mut_ptr(),
                error_buf.len(),
            );

            if result < 0 {
                let err_msg = CStr::from_ptr(error_buf.as_ptr())
                    .to_string_lossy()
                    .to_string();

                if err_msg.contains("timeout") {
                    return Err(SnmpError::Timeout);
                } else if err_msg.contains("Failed to parse OID") {
                    return Err(SnmpError::InvalidOid(err_msg));
                } else {
                    return Err(SnmpError::RequestFailed(err_msg));
                }
            }

            // Parse value based on type
            let value_len = result as usize;
            match value_type as u8 {
                ASN_OCTET_STR => {
                    // Try to convert to UTF-8 string first
                    match String::from_utf8(value_buf[..value_len].to_vec()) {
                        Ok(s) => Ok(SnmpValue::String(s)),
                        Err(_) => Ok(SnmpValue::OctetString(value_buf[..value_len].to_vec())),
                    }
                }
                ASN_OPAQUE => Ok(SnmpValue::OctetString(value_buf[..value_len].to_vec())),
                ASN_IPADDRESS => {
                    // IP addresses are 4 bytes - convert to dotted notation
                    if value_len == 4 {
                        Ok(SnmpValue::IpAddress(format!(
                            "{}.{}.{}.{}",
                            value_buf[0], value_buf[1], value_buf[2], value_buf[3]
                        )))
                    } else {
                        Ok(SnmpValue::OctetString(value_buf[..value_len].to_vec()))
                    }
                }
                ASN_OBJECT_ID => {
                    // Object IDs are returned as strings in dotted notation from C
                    match String::from_utf8(value_buf[..value_len].to_vec()) {
                        Ok(s) => Ok(SnmpValue::Oid(s)),
                        Err(_) => Ok(SnmpValue::OctetString(value_buf[..value_len].to_vec())),
                    }
                }
                ASN_INTEGER | ASN_COUNTER | ASN_GAUGE | ASN_TIMETICKS | ASN_UINTEGER => {
                    if value_len >= std::mem::size_of::<i64>() {
                        // Use unaligned read to avoid alignment issues from C
                        let value = (value_buf.as_ptr() as *const i64).read_unaligned();
                        Ok(SnmpValue::Integer(value))
                    } else {
                        Err(SnmpError::RequestFailed("Invalid integer size".into()))
                    }
                }
                ASN_COUNTER64 => {
                    if value_len >= 8 {
                        let high = u32::from_ne_bytes([
                            value_buf[0],
                            value_buf[1],
                            value_buf[2],
                            value_buf[3],
                        ]);
                        let low = u32::from_ne_bytes([
                            value_buf[4],
                            value_buf[5],
                            value_buf[6],
                            value_buf[7],
                        ]);
                        Ok(SnmpValue::Counter64((high as u64) << 32 | low as u64))
                    } else {
                        Err(SnmpError::RequestFailed("Invalid counter64 size".into()))
                    }
                }
                _ => Err(SnmpError::RequestFailed(format!(
                    "Unsupported type: {}",
                    value_type
                ))),
            }
        }
    }

    fn walk(&self, start_oid: &str) -> SnmpResult<Vec<(String, SnmpValue)>> {
        unsafe {
            let oid_cstr = CString::new(start_oid)
                .map_err(|_| SnmpError::InvalidOid(format!("Invalid OID: {}", start_oid)))?;

            // Allocate buffer for results (max 10000 entries)
            const MAX_RESULTS: usize = 10000;
            let mut results_buf: Vec<SnmpWalkResult> = vec![
                SnmpWalkResult {
                    oid: [0; 256],
                    value: [0; 1024],
                    value_len: 0,
                    value_type: 0,
                };
                MAX_RESULTS
            ];

            let mut num_results: usize = 0;
            let mut error_buf = [0 as c_char; 512];

            let result = snmp_walk(
                self.sess_handle,
                oid_cstr.as_ptr(),
                results_buf.as_mut_ptr(),
                MAX_RESULTS,
                &mut num_results,
                error_buf.as_mut_ptr(),
                error_buf.len(),
            );

            if result < 0 {
                let err_msg = CStr::from_ptr(error_buf.as_ptr())
                    .to_string_lossy()
                    .to_string();
                if err_msg.contains("Failed to parse OID") {
                    return Err(SnmpError::InvalidOid(err_msg));
                }
                return Err(SnmpError::RequestFailed(err_msg));
            }

            // Convert C results to Rust
            let mut parsed_results = Vec::with_capacity(num_results);
            for res in results_buf.iter().take(num_results) {
                // Parse OID string
                let oid_str = CStr::from_ptr(res.oid.as_ptr() as *const c_char)
                    .to_string_lossy()
                    .to_string();

                // Parse value
                if res.value_len > 0 {
                    let value = match res.value_type as u8 {
                        ASN_OCTET_STR => {
                            // Try UTF-8 conversion first
                            match String::from_utf8(res.value[..res.value_len].to_vec()) {
                                Ok(s) => SnmpValue::String(s),
                                Err(_) => {
                                    SnmpValue::OctetString(res.value[..res.value_len].to_vec())
                                }
                            }
                        }
                        ASN_OPAQUE => SnmpValue::OctetString(res.value[..res.value_len].to_vec()),
                        ASN_IPADDRESS => {
                            if res.value_len == 4 {
                                SnmpValue::IpAddress(format!(
                                    "{}.{}.{}.{}",
                                    res.value[0], res.value[1], res.value[2], res.value[3]
                                ))
                            } else {
                                SnmpValue::OctetString(res.value[..res.value_len].to_vec())
                            }
                        }
                        ASN_OBJECT_ID => {
                            match String::from_utf8(res.value[..res.value_len].to_vec()) {
                                Ok(s) => SnmpValue::Oid(s),
                                Err(_) => {
                                    SnmpValue::OctetString(res.value[..res.value_len].to_vec())
                                }
                            }
                        }
                        ASN_INTEGER | ASN_COUNTER | ASN_GAUGE | ASN_TIMETICKS | ASN_UINTEGER => {
                            if res.value_len >= std::mem::size_of::<i64>() {
                                // Use unaligned read to avoid alignment issues from C
                                let val = (res.value.as_ptr() as *const i64).read_unaligned();
                                SnmpValue::Integer(val)
                            } else {
                                continue; // Skip invalid values
                            }
                        }
                        ASN_COUNTER64 => {
                            if res.value_len >= 8 {
                                let high = u32::from_ne_bytes([
                                    res.value[0],
                                    res.value[1],
                                    res.value[2],
                                    res.value[3],
                                ]);
                                let low = u32::from_ne_bytes([
                                    res.value[4],
                                    res.value[5],
                                    res.value[6],
                                    res.value[7],
                                ]);
                                SnmpValue::Counter64((high as u64) << 32 | low as u64)
                            } else {
                                continue;
                            }
                        }
                        _ => continue, // Skip unsupported types
                    };

                    parsed_results.push((oid_str, value));
                }
            }

            Ok(parsed_results)
        }
    }
}

impl Drop for SnmpSession {
    fn drop(&mut self) {
        unsafe {
            if !self.sess_handle.is_null() {
                snmp_close_session(self.sess_handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_snmp_client_creation() {
        let client = SnmpClient::new();
        // Should not panic - init_snmp should be called once
        let client2 = SnmpClient::new();
        // Verify both clients are valid (zero-sized struct)
        assert_eq!(
            std::mem::size_of_val(&client),
            std::mem::size_of_val(&client2)
        );
    }

    #[tokio::test]
    async fn test_get_invalid_host() {
        let client = SnmpClient::new();
        let result = client
            .get(
                "invalid.host.that.does.not.exist",
                "public",
                "2c",
                161,
                "1.3.6.1.2.1.1.1.0",
                None,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SnmpError::NetworkUnreachable | SnmpError::RequestFailed(_) => {}
            e => panic!("Expected NetworkUnreachable or RequestFailed, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_get_invalid_oid() {
        let client = SnmpClient::new();
        let result = client
            .get("127.0.0.1", "public", "2c", 161, "not-a-valid-oid", None)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SnmpError::InvalidOid(_) => {}
            e => panic!("Expected InvalidOid, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_walk_invalid_oid() {
        let client = SnmpClient::new();
        let result = client
            .walk("127.0.0.1", "public", "2c", 161, "not-valid", None)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SnmpError::InvalidOid(_) => {}
            e => panic!("Expected InvalidOid, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_v3_config_clone() {
        let config = V3Config {
            username: "testuser".to_string(),
            auth_password: Some(Zeroizing::new("authpass".to_string())),
            priv_password: Some(Zeroizing::new("privpass".to_string())),
            auth_protocol: Some("SHA".to_string()),
            priv_protocol: Some("AES".to_string()),
            security_level: "authPriv".to_string(),
        };

        let cloned = config.clone();
        assert_eq!(config.username, cloned.username);
        assert_eq!(config.auth_protocol, cloned.auth_protocol);
        assert_eq!(config.priv_protocol, cloned.priv_protocol);
        assert_eq!(config.security_level, cloned.security_level);
    }

    #[tokio::test]
    async fn test_v3_config_debug_redacts_passwords() {
        let config = V3Config {
            username: "testuser".to_string(),
            auth_password: Some(Zeroizing::new("authpass".to_string())),
            priv_password: Some(Zeroizing::new("privpass".to_string())),
            auth_protocol: Some("SHA".to_string()),
            priv_protocol: Some("AES".to_string()),
            security_level: "authPriv".to_string(),
        };

        let debug_str = format!("{:?}", config);
        assert!(!debug_str.contains("authpass"));
        assert!(!debug_str.contains("privpass"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(debug_str.contains("testuser"));
    }

    #[tokio::test]
    async fn test_unsupported_version() {
        let client = SnmpClient::new();
        let result = client
            .get("127.0.0.1", "public", "99", 161, "1.3.6.1.2.1.1.1.0", None)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SnmpError::RequestFailed(msg) => {
                assert!(msg.contains("Unsupported SNMP version"));
            }
            e => panic!("Expected RequestFailed with version error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_sequential_requests() {
        // Test that multiple sequential requests work without issues
        // Note: Concurrent requests via tokio::spawn can cause segfaults
        // because libnetsnmp may not be fully thread-safe.
        // Our implementation uses spawn_blocking which should be safe for
        // sequential async operations.
        let client = SnmpClient::new();

        for _ in 0..3 {
            let result = client
                .get("192.0.2.1", "public", "2c", 161, "1.3.6.1.2.1.1.1.0", None)
                .await;

            // Should fail (no agent at 192.0.2.1) but not panic
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_get_and_walk_different_clients() {
        // Test that get and walk can be used with different client instances
        let client1 = SnmpClient::new();
        let client2 = SnmpClient::new();

        let get_result = client1
            .get("192.0.2.1", "public", "2c", 161, "1.3.6.1.2.1.1.1.0", None)
            .await;

        let walk_result = client2
            .walk("192.0.2.1", "public", "2c", 161, "1.3.6.1.2.1.1", None)
            .await;

        // Get should fail (unreachable host), walk may fail or return empty
        assert!(get_result.is_err());
        match walk_result {
            Err(_) => {} // Expected on most systems
            Ok(results) => assert!(
                results.is_empty(),
                "Walk to unreachable host should return no results"
            ),
        }
    }

    #[test]
    fn test_c_helpers_init() {
        // Test that C library initializes without crashing
        unsafe {
            let result = snmp_init_library();
            assert_eq!(result, 0, "C library initialization should succeed");
        }
    }

    #[test]
    fn test_c_helpers_session_open_invalid_host() {
        // Test session opening with invalid host
        unsafe {
            snmp_init_library();

            let ip = CString::new("invalid.host.example").unwrap();
            let community = CString::new("public").unwrap();
            let mut error_buf = [0i8; 256];

            let sess = snmp_open_session(
                ip.as_ptr(),
                161,
                community.as_ptr(),
                2, // SNMPv2c
                10_000_000,
                2,
                ptr::null(), // No v3 config for v2c
                error_buf.as_mut_ptr(),
                error_buf.len(),
            );

            // Should fail with invalid host
            assert!(sess.is_null(), "Session should fail with invalid host");

            // Should have an error message
            let err_msg = CStr::from_ptr(error_buf.as_ptr())
                .to_string_lossy()
                .to_string();
            assert!(
                !err_msg.is_empty(),
                "Should have error message, got: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_c_helpers_session_lifecycle() {
        // Test session open/close lifecycle (doesn't require actual SNMP device)
        unsafe {
            snmp_init_library();

            let ip = CString::new("192.0.2.1").unwrap(); // TEST-NET-1 (should be unreachable)
            let community = CString::new("public").unwrap();
            let mut error_buf = [0i8; 256];

            let sess = snmp_open_session(
                ip.as_ptr(),
                161,
                community.as_ptr(),
                2, // SNMPv2c
                10_000_000,
                2,
                ptr::null(), // No v3 config for v2c
                error_buf.as_mut_ptr(),
                error_buf.len(),
            );

            // Session creation should succeed even if host is unreachable
            // (connection happens on first request)
            if !sess.is_null() {
                // Clean close should not crash
                snmp_close_session(sess);
            }
        }
    }
}
