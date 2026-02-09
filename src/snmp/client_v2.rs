// Temporary new implementation to test compilation - will replace client.rs

use super::types::{SnmpError, SnmpResult, SnmpValue};
use netsnmp_sys::*;
use std::ffi::{CStr, CString};
use std::ptr;

const SNMP_TIMEOUT_SECS: i64 = 10;

/// Test if we can compile a simple SNMP GET using netsnmp-sys
pub fn test_snmp_get(ip: &str, community: &str) -> SnmpResult<String> {
    unsafe {
        // Initialize library
        init_snmp(b"test\0".as_ptr() as *const i8);

        // Create session
        let mut sess: Struct_netsnmp_session = std::mem::zeroed();
        snmp_sess_init(&mut sess as *mut _);

        // Set peername
        let peer = CString::new(format!("{}:161", ip)).unwrap();
        sess.peername = peer.as_ptr() as *mut _;

        // Set version and community
        sess.version = SNMP_VERSION_2c as i32;
        let comm = CString::new(community).unwrap();
        sess.community = comm.as_ptr() as *mut _;
        sess.community_len = community.len();

        // Set timeout
        sess.timeout = SNMP_TIMEOUT_SECS * 1_000_000; // microseconds

        // Open session
        let sess_ptr = snmp_open(&mut sess as *mut _);
        if sess_ptr.is_null() {
            return Err(SnmpError::NetworkUnreachable);
        }

        // Parse OID for sysDescr.0
        let mut oid_buf = [0u32; MAX_OID_LEN];
        let mut oid_len = MAX_OID_LEN;
        let oid_str = CString::new("1.3.6.1.2.1.1.1.0").unwrap();

        if read_objid(oid_str.as_ptr(), oid_buf.as_mut_ptr(), &mut oid_len) == 0 {
            snmp_close(sess_ptr);
            return Err(SnmpError::InvalidOid("Failed to parse OID".into()));
        }

        // Create PDU
        let pdu = snmp_pdu_create(SNMP_MSG_GET as i32);
        if pdu.is_null() {
            snmp_close(sess_ptr);
            return Err(SnmpError::RequestFailed("Failed to create PDU".into()));
        }

        // Add OID to PDU
        snmp_add_null_var(pdu, oid_buf.as_ptr(), oid_len);

        // Send request
        let mut response: *mut Struct_netsnmp_pdu = ptr::null_mut();
        let status = snmp_synch_response(sess_ptr, pdu, &mut response as *mut _);

        let result = if status == STAT_SUCCESS as i32 && !response.is_null() {
            let vars = (*response).variables;
            if !vars.is_null() {
                // Get the type
                let var_type = (*vars)._type;

                // Try to extract string value
                if var_type == ASN_OCTET_STR as u8 {
                    let val_len = (*vars).val_len;
                    // Access union - need mutable pointer
                    let vars_mut = vars as *mut _;
                    let string_ptr = *(*vars_mut).val.string();
                    let slice = std::slice::from_raw_parts(string_ptr, val_len);
                    Ok(String::from_utf8_lossy(slice).to_string())
                } else {
                    Err(SnmpError::RequestFailed(format!("Unexpected type: {}", var_type)))
                }
            } else {
                Err(SnmpError::RequestFailed("No variables in response".into()))
            }
        } else {
            Err(if status == STAT_TIMEOUT as i32 {
                SnmpError::Timeout
            } else {
                SnmpError::RequestFailed("SNMP request failed".into()))
            }
        };

        // Cleanup
        if !response.is_null() {
            snmp_free_pdu(response);
        }
        snmp_close(sess_ptr);

        result
    }
}
