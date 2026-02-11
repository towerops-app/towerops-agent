//! Integration tests for SNMP crash scenarios.
//!
//! These tests use a mock SNMP UDP server that returns crafted BER-encoded
//! responses to exercise all value type handling paths in snmp_helper.c,
//! particularly the `snmp_walk` switch statement where NULL pointer
//! dereferences and unhandled exception types can cause SIGSEGV.

use std::ffi::{c_char, CStr, CString};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

// ─── FFI declarations matching snmp_helper.h ────────────────────────────────

#[repr(C)]
struct SnmpWalkResult {
    oid: [u8; 256],
    value: [u8; 1024],
    value_len: usize,
    value_type: i32,
}

#[repr(C)]
struct SnmpIsolatedWalkHeader {
    status: i32,
    num_results: u32,
    child_signal: i32,
    error_buf: [c_char; 512],
}

#[repr(C)]
struct SnmpIsolatedGetResult {
    status: i32,
    value_type: i32,
    child_signal: i32,
    error_buf: [c_char; 512],
    value_buf: [u8; 1024],
}

extern "C" {
    fn snmp_walk_isolated(
        ip_address: *const c_char,
        port: u16,
        community: *const c_char,
        version: i32,
        timeout_us: i64,
        retries: i32,
        v3_config: *const std::ffi::c_void,
        oid_str: *const c_char,
        header: *mut SnmpIsolatedWalkHeader,
        results: *mut SnmpWalkResult,
        max_results: usize,
    );

    fn snmp_get_isolated(
        ip_address: *const c_char,
        port: u16,
        community: *const c_char,
        version: i32,
        timeout_us: i64,
        retries: i32,
        v3_config: *const std::ffi::c_void,
        oid_str: *const c_char,
        result: *mut SnmpIsolatedGetResult,
    );
}

// ─── BER encoding helpers ───────────────────────────────────────────────────

/// BER ASN.1 type tags
const BER_SEQUENCE: u8 = 0x30;
const BER_INTEGER: u8 = 0x02;
const BER_OCTET_STRING: u8 = 0x04;
const BER_NULL: u8 = 0x05;
const BER_OID: u8 = 0x06;
const BER_IPADDRESS: u8 = 0x40; // Application[0], primitive
const BER_COUNTER32: u8 = 0x41; // Application[1], primitive
const BER_GAUGE32: u8 = 0x42; // Application[2], primitive
const BER_TIMETICKS: u8 = 0x43; // Application[3], primitive
const BER_OPAQUE: u8 = 0x44; // Application[4], primitive
const BER_COUNTER64: u8 = 0x46; // Application[6], primitive

const SNMP_GET_RESPONSE: u8 = 0xA2;
const SNMP_GET_NEXT_REQUEST: u8 = 0xA1;

// SNMP exception types (context-specific, primitive)
const SNMP_NOSUCHOBJECT: u8 = 0x80;
const SNMP_NOSUCHINSTANCE: u8 = 0x81;
const SNMP_ENDOFMIBVIEW: u8 = 0x82;

fn ber_encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn ber_encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    result.extend(ber_encode_length(content.len()));
    result.extend(content);
    result
}

fn ber_encode_integer(value: i64) -> Vec<u8> {
    // Encode integer value in minimum bytes, two's complement
    let mut bytes = Vec::new();
    if value == 0 {
        bytes.push(0);
    } else if value > 0 {
        let mut v = value;
        while v > 0 {
            bytes.push((v & 0xFF) as u8);
            v >>= 8;
        }
        // Add leading zero if high bit set (would be negative)
        if bytes.last().unwrap() & 0x80 != 0 {
            bytes.push(0);
        }
        bytes.reverse();
    } else {
        let mut v = value;
        loop {
            bytes.push((v & 0xFF) as u8);
            v >>= 8;
            if v == -1 && (bytes.last().unwrap() & 0x80) != 0 {
                break;
            }
        }
        bytes.reverse();
    }
    ber_encode_tlv(BER_INTEGER, &bytes)
}

fn ber_encode_unsigned32(tag: u8, value: u32) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    // Remove leading zeros but keep at least one byte
    while bytes.len() > 1 && bytes[0] == 0 && (bytes[1] & 0x80) == 0 {
        bytes.remove(0);
    }
    // Add leading zero if high bit set (ASN.1 unsigned encoding)
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    ber_encode_tlv(tag, &bytes)
}

fn ber_encode_counter64(value: u64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && (bytes[1] & 0x80) == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    ber_encode_tlv(BER_COUNTER64, &bytes)
}

fn ber_encode_oid(components: &[u32]) -> Vec<u8> {
    if components.len() < 2 {
        return ber_encode_tlv(BER_OID, &[]);
    }
    let mut encoded = vec![(40 * components[0] + components[1]) as u8];
    for &c in &components[2..] {
        if c < 128 {
            encoded.push(c as u8);
        } else {
            // Base-128 encoding with continuation bits
            let mut temp = Vec::new();
            let mut v = c;
            temp.push((v & 0x7F) as u8);
            v >>= 7;
            while v > 0 {
                temp.push((v & 0x7F) as u8 | 0x80);
                v >>= 7;
            }
            temp.reverse();
            encoded.extend(temp);
        }
    }
    ber_encode_tlv(BER_OID, &encoded)
}

fn ber_encode_octet_string(value: &[u8]) -> Vec<u8> {
    ber_encode_tlv(BER_OCTET_STRING, value)
}

fn ber_encode_null() -> Vec<u8> {
    vec![BER_NULL, 0x00]
}

/// Build an SNMP GetResponse PDU with one varbind.
fn build_snmp_response(
    request_id: i64,
    community: &[u8],
    oid_components: &[u32],
    value_encoding: &[u8], // Pre-encoded TLV for the value
) -> Vec<u8> {
    // VarBind: SEQUENCE { OID, value }
    let varbind_content = [ber_encode_oid(oid_components).as_slice(), value_encoding].concat();
    let varbind = ber_encode_tlv(BER_SEQUENCE, &varbind_content);

    // VarBindList: SEQUENCE OF VarBind
    let varbind_list = ber_encode_tlv(BER_SEQUENCE, &varbind);

    // GetResponse-PDU: [2] { request-id, error-status(0), error-index(0), varbind-list }
    let pdu_content = [
        ber_encode_integer(request_id).as_slice(),
        &ber_encode_integer(0), // error-status = noError
        &ber_encode_integer(0), // error-index = 0
        &varbind_list,
    ]
    .concat();
    let pdu = ber_encode_tlv(SNMP_GET_RESPONSE, &pdu_content);

    // SNMP Message: SEQUENCE { version, community, pdu }
    let msg_content = [
        ber_encode_integer(1).as_slice(), // version = 1 (SNMPv2c)
        &ber_encode_tlv(BER_OCTET_STRING, community),
        &pdu,
    ]
    .concat();

    ber_encode_tlv(BER_SEQUENCE, &msg_content)
}

// ─── BER decoding helpers (minimal, for parsing incoming requests) ──────────

fn ber_decode_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let tag = data[0];
    let (length, header_len) = if data[1] < 128 {
        (data[1] as usize, 2)
    } else if data[1] == 0x81 && data.len() >= 3 {
        (data[2] as usize, 3)
    } else if data[1] == 0x82 && data.len() >= 4 {
        (((data[2] as usize) << 8) | data[3] as usize, 4)
    } else {
        return None;
    };

    if header_len + length > data.len() {
        return None;
    }

    let content = &data[header_len..header_len + length];
    let rest = &data[header_len + length..];
    Some((tag, content, rest))
}

fn ber_decode_integer(data: &[u8]) -> Option<(i64, &[u8])> {
    let (tag, content, rest) = ber_decode_tlv(data)?;
    if tag != BER_INTEGER || content.is_empty() {
        return None;
    }
    let mut value: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for &byte in content {
        value = (value << 8) | byte as i64;
    }
    Some((value, rest))
}

/// Parse an incoming SNMP request enough to extract request-id and the first OID.
fn parse_snmp_request(data: &[u8]) -> Option<(i64, Vec<u8>)> {
    // Outer SEQUENCE
    let (_tag, msg_content, _) = ber_decode_tlv(data)?;

    // Skip version (INTEGER)
    let (_, rest) = ber_decode_integer(msg_content)?;

    // Skip community (OCTET STRING)
    let (_, community_content, rest) = ber_decode_tlv(rest)?;
    let _ = community_content;

    // PDU (GetNextRequest = 0xA1 or GetRequest = 0xA0)
    let (pdu_tag, pdu_content, _) = ber_decode_tlv(rest)?;
    if pdu_tag != SNMP_GET_NEXT_REQUEST && pdu_tag != 0xA0 {
        return None;
    }

    // Request ID
    let (request_id, rest) = ber_decode_integer(pdu_content)?;

    // Skip error-status, error-index
    let (_, rest) = ber_decode_integer(rest)?;
    let (_, rest) = ber_decode_integer(rest)?;

    // VarBindList SEQUENCE
    let (_, vbl_content, _) = ber_decode_tlv(rest)?;

    // First VarBind SEQUENCE
    let (_, vb_content, _) = ber_decode_tlv(vbl_content)?;

    // OID - return raw bytes for comparison
    let (tag, oid_content, _) = ber_decode_tlv(vb_content)?;
    if tag != BER_OID {
        return None;
    }

    Some((request_id, oid_content.to_vec()))
}

// ─── Mock SNMP server ──────────────────────────────────────────────────────

/// Configuration for a varbind response from the mock server.
#[derive(Clone)]
struct MockVarbind {
    /// OID to return in the response (the "next" OID in the walk)
    response_oid: Vec<u32>,
    /// Pre-encoded TLV for the value
    value_tlv: Vec<u8>,
}

/// A mock SNMP UDP server that returns crafted responses.
struct MockSnmpServer {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockSnmpServer {
    /// Start a mock server that returns the given varbinds in sequence.
    /// After all varbinds are exhausted, returns an OID outside the subtree
    /// (2.0) to terminate the walk.
    fn start(varbinds: Vec<MockVarbind>) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind mock SNMP server");
        let port = socket.local_addr().unwrap().port();
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        let handle = thread::spawn(move || {
            let community = b"public";
            let mut request_count = 0usize;
            let mut buf = [0u8; 4096];

            while !stop_clone.load(Ordering::Relaxed) {
                let (len, src) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                };

                let data = &buf[..len];

                // Parse request to get request-id
                let request_id = match parse_snmp_request(data) {
                    Some((id, _oid)) => id,
                    None => continue,
                };

                // Build response
                let response = if request_count < varbinds.len() {
                    let vb = &varbinds[request_count];
                    build_snmp_response(request_id, community, &vb.response_oid, &vb.value_tlv)
                } else {
                    // Return OID outside subtree to end the walk
                    // Use OID 2.0 which is outside any 1.x subtree
                    build_snmp_response(request_id, community, &[2, 0], &ber_encode_null())
                };

                let _ = socket.send_to(&response, src);
                request_count += 1;
            }
        });

        MockSnmpServer {
            port,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for MockSnmpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ─── Test helpers ──────────────────────────────────────────────────────────

const TEST_TIMEOUT_US: i64 = 2_000_000; // 2 seconds for mock tests
const TEST_RETRIES: i32 = 1;
const MAX_RESULTS: usize = 100;

/// The base OID we walk in all tests: 1.3.6.1.2.1.1 (system subtree)
/// OID within the subtree for test responses: 1.3.6.1.2.1.1.1.0
const RESPONSE_OID_1: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
/// Second OID within the subtree: 1.3.6.1.2.1.1.2.0
const RESPONSE_OID_2: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
/// Third OID: 1.3.6.1.2.1.1.3.0
const RESPONSE_OID_3: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];

fn do_walk_isolated(port: u16, oid: &str) -> (SnmpIsolatedWalkHeader, Vec<SnmpWalkResult>) {
    let ip = CString::new("127.0.0.1").unwrap();
    let community = CString::new("public").unwrap();
    let oid_cstr = CString::new(oid).unwrap();

    let mut header = SnmpIsolatedWalkHeader {
        status: -1,
        num_results: 0,
        child_signal: 0,
        error_buf: [0; 512],
    };

    let mut results: Vec<SnmpWalkResult> = (0..MAX_RESULTS)
        .map(|_| SnmpWalkResult {
            oid: [0; 256],
            value: [0; 1024],
            value_len: 0,
            value_type: 0,
        })
        .collect();

    unsafe {
        snmp_walk_isolated(
            ip.as_ptr(),
            port,
            community.as_ptr(),
            2, // SNMPv2c
            TEST_TIMEOUT_US,
            TEST_RETRIES,
            std::ptr::null(),
            oid_cstr.as_ptr(),
            &mut header,
            results.as_mut_ptr(),
            MAX_RESULTS,
        );
    }

    (header, results)
}

fn do_get_isolated(port: u16, oid: &str) -> SnmpIsolatedGetResult {
    let ip = CString::new("127.0.0.1").unwrap();
    let community = CString::new("public").unwrap();
    let oid_cstr = CString::new(oid).unwrap();

    let mut result = SnmpIsolatedGetResult {
        status: -1,
        value_type: 0,
        child_signal: 0,
        error_buf: [0; 512],
        value_buf: [0; 1024],
    };

    unsafe {
        snmp_get_isolated(
            ip.as_ptr(),
            port,
            community.as_ptr(),
            2, // SNMPv2c
            TEST_TIMEOUT_US,
            TEST_RETRIES,
            std::ptr::null(),
            oid_cstr.as_ptr(),
            &mut result,
        );
    }

    result
}

fn header_error(header: &SnmpIsolatedWalkHeader) -> String {
    unsafe {
        CStr::from_ptr(header.error_buf.as_ptr())
            .to_string_lossy()
            .to_string()
    }
}

fn get_error(result: &SnmpIsolatedGetResult) -> String {
    unsafe {
        CStr::from_ptr(result.error_buf.as_ptr())
            .to_string_lossy()
            .to_string()
    }
}

fn assert_no_crash(header: &SnmpIsolatedWalkHeader, scenario: &str) {
    assert_ne!(
        header.status,
        -2,
        "{}: child process crashed with signal {} ({})",
        scenario,
        header.child_signal,
        header_error(header)
    );
}

fn assert_get_no_crash(result: &SnmpIsolatedGetResult, scenario: &str) {
    assert_ne!(
        result.status,
        -2,
        "{}: child process crashed with signal {} ({})",
        scenario,
        result.child_signal,
        get_error(result)
    );
}

// ─── Walk tests with exception types ───────────────────────────────────────

#[test]
fn test_walk_nosuchobject_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: vec![SNMP_NOSUCHOBJECT, 0x00], // NoSuchObject, length 0
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "NoSuchObject");
}

#[test]
fn test_walk_nosuchinstance_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: vec![SNMP_NOSUCHINSTANCE, 0x00], // NoSuchInstance, length 0
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "NoSuchInstance");
}

#[test]
fn test_walk_endofmibview_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: vec![SNMP_ENDOFMIBVIEW, 0x00], // EndOfMibView, length 0
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "EndOfMibView");
}

// ─── Walk tests with NULL type ─────────────────────────────────────────────

#[test]
fn test_walk_null_value_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_null(),
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "ASN_NULL");
}

// ─── Walk tests with standard types ────────────────────────────────────────

#[test]
fn test_walk_integer_value() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_integer(42),
    }]);

    let (header, results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "Integer");
    assert_eq!(header.status, 0, "walk should succeed");
    assert!(header.num_results >= 1, "should have at least 1 result");
    assert_eq!(results[0].value_type, BER_INTEGER as i32);
}

#[test]
fn test_walk_octet_string_value() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_octet_string(b"Hello SNMP"),
    }]);

    let (header, results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "OctetString");
    assert_eq!(header.status, 0);
    assert!(header.num_results >= 1);
    assert_eq!(results[0].value_type, BER_OCTET_STRING as i32);
    assert_eq!(results[0].value_len, 10);
    assert_eq!(&results[0].value[..10], b"Hello SNMP");
}

#[test]
fn test_walk_empty_octet_string_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_octet_string(b""), // Empty string
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "EmptyOctetString");
    // Empty strings get value_len=0, which means result is skipped
    // This is acceptable behavior
}

#[test]
fn test_walk_binary_octet_string() {
    // Simulate a binary value like a MAC address (common in LLDP)
    let mac = vec![0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_octet_string(&mac),
    }]);

    let (header, results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "BinaryOctetString");
    assert_eq!(header.status, 0);
    assert!(header.num_results >= 1);
    assert_eq!(&results[0].value[..6], &mac[..]);
}

#[test]
fn test_walk_counter32_value() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_unsigned32(BER_COUNTER32, 123456),
    }]);

    let (header, results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "Counter32");
    assert_eq!(header.status, 0);
    assert!(header.num_results >= 1);
    assert_eq!(results[0].value_type, BER_COUNTER32 as i32);
}

#[test]
fn test_walk_gauge32_value() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_unsigned32(BER_GAUGE32, 99999),
    }]);

    let (header, results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "Gauge32");
    assert_eq!(header.status, 0);
    assert!(header.num_results >= 1);
}

#[test]
fn test_walk_timeticks_value() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_unsigned32(BER_TIMETICKS, 500000),
    }]);

    let (header, results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "TimeTicks");
    assert_eq!(header.status, 0);
    assert!(header.num_results >= 1);
}

#[test]
fn test_walk_counter64_value() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_counter64(0x0001_0000_0000_ABCD),
    }]);

    let (header, results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "Counter64");
    assert_eq!(header.status, 0);
    assert!(header.num_results >= 1);
    assert_eq!(results[0].value_type, BER_COUNTER64 as i32);
}

#[test]
fn test_walk_oid_value() {
    // Value is itself an OID (e.g., sysObjectID)
    let oid_value = ber_encode_oid(&[1, 3, 6, 1, 4, 1, 41112, 1, 4]); // Ubiquiti OID
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: oid_value,
    }]);

    let (header, results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "OID value");
    assert_eq!(header.status, 0);
    assert!(header.num_results >= 1);
    assert_eq!(results[0].value_type, BER_OID as i32);
}

#[test]
fn test_walk_ipaddress_value() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_tlv(BER_IPADDRESS, &[10, 0, 0, 1]),
    }]);

    let (header, results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "IpAddress");
    assert_eq!(header.status, 0);
    assert!(header.num_results >= 1);
}

#[test]
fn test_walk_opaque_value() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_tlv(BER_OPAQUE, &[0x9F, 0x78, 0x04, 0x42, 0x8C, 0xCC, 0xCD]),
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "Opaque");
    assert_eq!(header.status, 0);
    // Opaque values may or may not be returned depending on net-snmp's parsing
}

// ─── Walk tests with edge cases ────────────────────────────────────────────

#[test]
fn test_walk_unknown_type_does_not_crash() {
    // Use a type tag not in the switch statement (e.g., BIT STRING = 0x03)
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_tlv(0x03, &[0x00, 0xFF, 0xAA]), // BIT STRING
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "UnknownType(BIT_STRING)");
}

#[test]
fn test_walk_large_octet_string_does_not_crash() {
    // Value larger than the 1024-byte result buffer
    let large_value = vec![0x41; 2000]; // 2000 bytes of 'A'
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_octet_string(&large_value),
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "LargeOctetString");
    // Large values should be skipped (not overflow the buffer)
}

#[test]
fn test_walk_zero_integer_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_integer(0),
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "ZeroInteger");
    assert_eq!(header.status, 0);
    assert!(header.num_results >= 1);
}

#[test]
fn test_walk_negative_integer_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_integer(-1),
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "NegativeInteger");
    assert_eq!(header.status, 0);
    assert!(header.num_results >= 1);
}

#[test]
fn test_walk_max_counter64_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_counter64(u64::MAX),
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "MaxCounter64");
}

// ─── Walk tests with mixed types (simulating real device responses) ────────

#[test]
fn test_walk_mixed_types_like_real_device() {
    // Simulate a realistic SNMP walk returning various system MIB values
    let server = MockSnmpServer::start(vec![
        // sysDescr.0 = OctetString
        MockVarbind {
            response_oid: RESPONSE_OID_1.to_vec(),
            value_tlv: ber_encode_octet_string(b"EdgeSwitch 24-Port 250W"),
        },
        // sysObjectID.0 = OID
        MockVarbind {
            response_oid: RESPONSE_OID_2.to_vec(),
            value_tlv: ber_encode_oid(&[1, 3, 6, 1, 4, 1, 41112, 1, 6]),
        },
        // sysUpTime.0 = TimeTicks
        MockVarbind {
            response_oid: RESPONSE_OID_3.to_vec(),
            value_tlv: ber_encode_unsigned32(BER_TIMETICKS, 123456789),
        },
    ]);

    let (header, results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "MixedTypes");
    assert_eq!(header.status, 0);
    assert_eq!(header.num_results, 3, "should have 3 results");

    // Verify types
    assert_eq!(results[0].value_type, BER_OCTET_STRING as i32);
    assert_eq!(results[1].value_type, BER_OID as i32);
    assert_eq!(results[2].value_type, BER_TIMETICKS as i32);
}

#[test]
fn test_walk_mixed_with_exceptions() {
    // Simulate walk where some OIDs return exceptions (common on Ubiquiti)
    let server = MockSnmpServer::start(vec![
        // First result: normal string
        MockVarbind {
            response_oid: RESPONSE_OID_1.to_vec(),
            value_tlv: ber_encode_octet_string(b"Normal value"),
        },
        // Second result: NoSuchInstance (device doesn't implement this OID)
        MockVarbind {
            response_oid: RESPONSE_OID_2.to_vec(),
            value_tlv: vec![SNMP_NOSUCHINSTANCE, 0x00],
        },
        // Third result: normal integer after the exception
        MockVarbind {
            response_oid: RESPONSE_OID_3.to_vec(),
            value_tlv: ber_encode_integer(100),
        },
    ]);

    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "MixedWithExceptions");
    assert_eq!(header.status, 0);
    // Exception values get value_len=0 so they're skipped
    // We should get at least the normal values
}

// ─── Walk test simulating LLDP responses (Ubiquiti-like) ───────────────────

#[test]
fn test_walk_lldp_binary_chassis_id() {
    // LLDP lldpRemChassisId returns binary MAC address
    // OID: 1.0.8802.1.1.2.1.4.1.1.5.0.1
    let lldp_base: Vec<u32> = vec![1, 0, 8802, 1, 1, 2, 1, 4, 1, 1];
    let mut oid1 = lldp_base.clone();
    oid1.extend(&[5, 0, 1]);

    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: oid1,
        value_tlv: ber_encode_octet_string(&[0x04, 0xF0, 0x21, 0xBE, 0xAC, 0x10]), // MAC address
    }]);

    let (header, _results) = do_walk_isolated(server.port, "1.0.8802.1.1.2.1.4.1.1");
    assert_no_crash(&header, "LLDP binary chassis ID");
}

#[test]
fn test_walk_lldp_with_all_exception_types() {
    // Some Ubiquiti devices return exceptions for LLDP sub-OIDs
    let lldp_base: Vec<u32> = vec![1, 0, 8802, 1, 1, 2, 1, 4, 1, 1];
    let mut oid1 = lldp_base.clone();
    oid1.extend(&[1, 0, 1]);
    let mut oid2 = lldp_base.clone();
    oid2.extend(&[2, 0, 1]);
    let mut oid3 = lldp_base.clone();
    oid3.extend(&[3, 0, 1]);

    let server = MockSnmpServer::start(vec![
        MockVarbind {
            response_oid: oid1,
            value_tlv: vec![SNMP_NOSUCHOBJECT, 0x00],
        },
        MockVarbind {
            response_oid: oid2,
            value_tlv: vec![SNMP_NOSUCHINSTANCE, 0x00],
        },
        MockVarbind {
            response_oid: oid3,
            value_tlv: vec![SNMP_ENDOFMIBVIEW, 0x00],
        },
    ]);

    let (header, _results) = do_walk_isolated(server.port, "1.0.8802.1.1.2.1.4.1.1");
    assert_no_crash(&header, "LLDP all exception types");
}

// ─── GET tests with exception types ────────────────────────────────────────

// Note: GET requests use GetRequest (0xA0), and the mock server responds to
// both 0xA0 and 0xA1. But `snmp_get_isolated` sends a GET PDU (0xA0),
// and the mock needs to handle that. Since we configured the mock to accept
// both tags, this should work. However, GET operations send a GetRequest,
// not GetNextRequest, so we need our mock to handle 0xA0 too.
// The mock's parse_snmp_request already accepts both 0xA0 and 0xA1.

// For GET tests, the mock returns exactly one response (no walk iteration).

#[test]
fn test_get_nosuchobject_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: vec![SNMP_NOSUCHOBJECT, 0x00],
    }]);

    let result = do_get_isolated(server.port, "1.3.6.1.2.1.1.1.0");
    assert_get_no_crash(&result, "GET NoSuchObject");
}

#[test]
fn test_get_nosuchinstance_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: vec![SNMP_NOSUCHINSTANCE, 0x00],
    }]);

    let result = do_get_isolated(server.port, "1.3.6.1.2.1.1.1.0");
    assert_get_no_crash(&result, "GET NoSuchInstance");
}

#[test]
fn test_get_endofmibview_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: vec![SNMP_ENDOFMIBVIEW, 0x00],
    }]);

    let result = do_get_isolated(server.port, "1.3.6.1.2.1.1.1.0");
    assert_get_no_crash(&result, "GET EndOfMibView");
}

#[test]
fn test_get_null_value_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_null(),
    }]);

    let result = do_get_isolated(server.port, "1.3.6.1.2.1.1.1.0");
    assert_get_no_crash(&result, "GET NULL");
}

#[test]
fn test_get_normal_string() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_octet_string(b"test value"),
    }]);

    let result = do_get_isolated(server.port, "1.3.6.1.2.1.1.1.0");
    assert_get_no_crash(&result, "GET string");
    assert!(result.status >= 0, "GET should succeed");
    assert_eq!(result.value_type, BER_OCTET_STRING as i32);
}

#[test]
fn test_get_empty_octet_string_does_not_crash() {
    let server = MockSnmpServer::start(vec![MockVarbind {
        response_oid: RESPONSE_OID_1.to_vec(),
        value_tlv: ber_encode_octet_string(b""),
    }]);

    let result = do_get_isolated(server.port, "1.3.6.1.2.1.1.1.0");
    assert_get_no_crash(&result, "GET empty string");
}

// ─── Stress / concurrent tests ─────────────────────────────────────────────

#[test]
fn test_walk_many_sequential_operations() {
    // Run multiple walks to the same mock to verify no resource leaks
    for i in 0..5 {
        let server = MockSnmpServer::start(vec![MockVarbind {
            response_oid: RESPONSE_OID_1.to_vec(),
            value_tlv: ber_encode_integer(i),
        }]);

        let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
        assert_no_crash(&header, &format!("Sequential walk {}", i));
    }
}

#[test]
fn test_walk_many_results() {
    // Walk that returns many results to test the results buffer handling
    let mut varbinds = Vec::new();
    for i in 0..50 {
        let mut oid = vec![1u32, 3, 6, 1, 2, 1, 1, 1];
        oid.push(i);
        varbinds.push(MockVarbind {
            response_oid: oid,
            value_tlv: ber_encode_integer(i as i64),
        });
    }

    let server = MockSnmpServer::start(varbinds);
    let (header, _results) = do_walk_isolated(server.port, "1.3.6.1.2.1.1");
    assert_no_crash(&header, "ManyResults");
    assert_eq!(header.status, 0);
    assert_eq!(header.num_results, 50);
}
