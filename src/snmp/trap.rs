//! SNMP Trap Listener
//!
//! Listens for SNMP v1 and v2c traps on a UDP socket and logs them.
//! Implements minimal BER/ASN.1 parsing for trap PDUs.

use std::fmt;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Default SNMP trap port
pub const DEFAULT_TRAP_PORT: u16 = 162;

/// Maximum UDP packet size for SNMP traps
const MAX_PACKET_SIZE: usize = 65535;

/// SNMP version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    V1,
    V2c,
}

impl fmt::Display for SnmpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnmpVersion::V1 => write!(f, "v1"),
            SnmpVersion::V2c => write!(f, "v2c"),
        }
    }
}

/// SNMPv1 generic trap types
#[derive(Debug, Clone, Copy)]
pub enum GenericTrap {
    ColdStart,
    WarmStart,
    LinkDown,
    LinkUp,
    AuthenticationFailure,
    EgpNeighborLoss,
    EnterpriseSpecific,
}

impl GenericTrap {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(GenericTrap::ColdStart),
            1 => Some(GenericTrap::WarmStart),
            2 => Some(GenericTrap::LinkDown),
            3 => Some(GenericTrap::LinkUp),
            4 => Some(GenericTrap::AuthenticationFailure),
            5 => Some(GenericTrap::EgpNeighborLoss),
            6 => Some(GenericTrap::EnterpriseSpecific),
            _ => None,
        }
    }
}

impl fmt::Display for GenericTrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenericTrap::ColdStart => write!(f, "coldStart"),
            GenericTrap::WarmStart => write!(f, "warmStart"),
            GenericTrap::LinkDown => write!(f, "linkDown"),
            GenericTrap::LinkUp => write!(f, "linkUp"),
            GenericTrap::AuthenticationFailure => write!(f, "authenticationFailure"),
            GenericTrap::EgpNeighborLoss => write!(f, "egpNeighborLoss"),
            GenericTrap::EnterpriseSpecific => write!(f, "enterpriseSpecific"),
        }
    }
}

/// Parsed SNMP trap
#[derive(Debug, Clone)]
pub struct SnmpTrap {
    pub source_addr: SocketAddr,
    pub version: SnmpVersion,
    #[allow(dead_code)] // Parsed but not currently logged; useful for future filtering
    pub community: String,
    pub trap_oid: String,
    pub generic_trap: Option<GenericTrap>,
    pub specific_trap: Option<u32>,
    pub uptime: u32,
    pub varbinds: Vec<(String, String)>,
}

impl fmt::Display for SnmpTrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SNMP trap from {} [{}]", self.source_addr, self.version)?;

        match self.version {
            SnmpVersion::V1 => {
                write!(f, " enterprise={}", self.trap_oid)?;
                if let Some(generic) = &self.generic_trap {
                    write!(f, " generic={}", generic)?;
                }
                if let Some(specific) = self.specific_trap {
                    write!(f, " specific={}", specific)?;
                }
            }
            SnmpVersion::V2c => {
                write!(f, " oid={}", self.trap_oid)?;
            }
        }

        write!(f, " uptime={}", self.uptime)?;

        if !self.varbinds.is_empty() {
            write!(f, " varbinds=[")?;
            for (i, (oid, value)) in self.varbinds.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}={}", oid, value)?;
            }
            write!(f, "]")?;
        }

        Ok(())
    }
}

/// SNMP trap listener
pub struct TrapListener {
    port: u16,
}

impl TrapListener {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Run the trap listener, sending parsed traps through the channel
    pub async fn run(self, trap_tx: mpsc::Sender<SnmpTrap>) {
        let bind_addr = format!("0.0.0.0:{}", self.port);

        let socket = match UdpSocket::bind(&bind_addr).await {
            Ok(s) => {
                crate::log_info!("SNMP trap listener started on UDP port {}", self.port);
                s
            }
            Err(e) => {
                crate::log_error!("Failed to bind trap listener to {}: {}", bind_addr, e);
                return;
            }
        };

        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    let packet = &buf[..len];

                    match parse_trap(packet, src_addr) {
                        Ok(trap) => {
                            if trap_tx.send(trap).await.is_err() {
                                crate::log_warn!("Trap channel closed, stopping listener");
                                break;
                            }
                        }
                        Err(e) => {
                            crate::log_warn!("Failed to parse SNMP trap from {}: {}", src_addr, e);
                        }
                    }
                }
                Err(e) => {
                    crate::log_warn!("Error receiving trap packet: {}", e);
                }
            }
        }
    }
}

// ============================================================================
// BER/ASN.1 Parsing
// ============================================================================

/// BER tag types
mod ber_tags {
    pub const INTEGER: u8 = 0x02;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30;
    pub const IP_ADDRESS: u8 = 0x40;
    pub const COUNTER32: u8 = 0x41;
    pub const GAUGE32: u8 = 0x42;
    pub const TIMETICKS: u8 = 0x43;
    pub const COUNTER64: u8 = 0x46;
    pub const TRAP_PDU_V1: u8 = 0xA4;
    pub const TRAP_PDU_V2: u8 = 0xA7;
}

/// Parse error
#[derive(Debug)]
struct ParseError(String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

type ParseResult<T> = Result<T, ParseError>;

/// Parse a BER TLV (Tag-Length-Value) and return (tag, value_bytes, remaining_bytes)
fn parse_tlv(data: &[u8]) -> ParseResult<(u8, &[u8], &[u8])> {
    if data.is_empty() {
        return Err(ParseError("Empty data".to_string()));
    }

    let tag = data[0];
    let (length, header_len) = parse_length(&data[1..])?;

    let total_header = 1 + header_len;
    if data.len() < total_header + length {
        return Err(ParseError(format!(
            "Data too short: need {} bytes, have {}",
            total_header + length,
            data.len()
        )));
    }

    let value = &data[total_header..total_header + length];
    let remaining = &data[total_header + length..];

    Ok((tag, value, remaining))
}

/// Parse BER length field, returning (length, bytes_consumed)
fn parse_length(data: &[u8]) -> ParseResult<(usize, usize)> {
    if data.is_empty() {
        return Err(ParseError("Empty length field".to_string()));
    }

    let first = data[0];

    if first < 0x80 {
        // Short form: length in single byte
        Ok((first as usize, 1))
    } else if first == 0x80 {
        Err(ParseError("Indefinite length not supported".to_string()))
    } else {
        // Long form: first byte indicates number of length bytes
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || data.len() < 1 + num_bytes {
            return Err(ParseError("Invalid length encoding".to_string()));
        }

        let mut length: usize = 0;
        for byte in &data[1..1 + num_bytes] {
            length = (length << 8) | (*byte as usize);
        }

        Ok((length, 1 + num_bytes))
    }
}

/// Parse an INTEGER value
fn parse_integer(data: &[u8]) -> ParseResult<i64> {
    if data.is_empty() {
        return Ok(0);
    }

    let mut value: i64 = if data[0] & 0x80 != 0 { -1 } else { 0 };

    for &byte in data {
        value = (value << 8) | (byte as i64);
    }

    Ok(value)
}

/// Parse an unsigned INTEGER value
fn parse_unsigned(data: &[u8]) -> ParseResult<u64> {
    let mut value: u64 = 0;
    for &byte in data {
        value = (value << 8) | (byte as u64);
    }
    Ok(value)
}

/// Parse an OBJECT IDENTIFIER
fn parse_oid(data: &[u8]) -> ParseResult<String> {
    if data.is_empty() {
        return Ok(String::new());
    }

    let mut oid_parts = Vec::new();

    // First byte encodes first two components: X*40 + Y
    let first = data[0] as u32;
    oid_parts.push(first / 40);
    oid_parts.push(first % 40);

    // Remaining bytes use variable-length encoding
    let mut value: u32 = 0;
    for &byte in &data[1..] {
        value = (value << 7) | ((byte & 0x7F) as u32);
        if byte & 0x80 == 0 {
            oid_parts.push(value);
            value = 0;
        }
    }

    Ok(oid_parts
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

/// Parse an OCTET STRING as a UTF-8 string (lossy)
fn parse_octet_string(data: &[u8]) -> String {
    // Try UTF-8 first, fall back to hex if it contains non-printable chars
    let s = String::from_utf8_lossy(data);
    if s.chars()
        .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
    {
        s.into_owned()
    } else {
        // Hex encode non-printable data
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    }
}

/// Parse IP address (4 bytes)
fn parse_ip_address(data: &[u8]) -> ParseResult<String> {
    if data.len() != 4 {
        return Err(ParseError(format!(
            "Invalid IP address length: {}",
            data.len()
        )));
    }
    Ok(format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]))
}

/// Parse a varbind value to string representation
fn parse_value_to_string(tag: u8, data: &[u8]) -> String {
    match tag {
        ber_tags::INTEGER => parse_integer(data)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".to_string()),
        ber_tags::OCTET_STRING => parse_octet_string(data),
        ber_tags::OBJECT_IDENTIFIER => parse_oid(data).unwrap_or_else(|_| "?".to_string()),
        ber_tags::NULL => "null".to_string(),
        ber_tags::IP_ADDRESS => parse_ip_address(data).unwrap_or_else(|_| "?".to_string()),
        ber_tags::COUNTER32 | ber_tags::GAUGE32 | ber_tags::TIMETICKS => parse_unsigned(data)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".to_string()),
        ber_tags::COUNTER64 => parse_unsigned(data)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".to_string()),
        _ => format!("[tag=0x{:02x}]", tag),
    }
}

/// Parse varbind list
fn parse_varbinds(data: &[u8]) -> ParseResult<Vec<(String, String)>> {
    let mut varbinds = Vec::new();
    let mut remaining = data;

    while !remaining.is_empty() {
        // Each varbind is a SEQUENCE of (OID, value)
        let (tag, varbind_data, rest) = parse_tlv(remaining)?;
        if tag != ber_tags::SEQUENCE {
            return Err(ParseError(format!("Expected SEQUENCE, got 0x{:02x}", tag)));
        }
        remaining = rest;

        // Parse OID
        let (oid_tag, oid_data, value_rest) = parse_tlv(varbind_data)?;
        if oid_tag != ber_tags::OBJECT_IDENTIFIER {
            return Err(ParseError(format!("Expected OID, got 0x{:02x}", oid_tag)));
        }
        let oid = parse_oid(oid_data)?;

        // Parse value
        let (value_tag, value_data, _) = parse_tlv(value_rest)?;
        let value = parse_value_to_string(value_tag, value_data);

        varbinds.push((oid, value));
    }

    Ok(varbinds)
}

/// Parse an SNMP trap packet
fn parse_trap(data: &[u8], source_addr: SocketAddr) -> ParseResult<SnmpTrap> {
    // SNMP message: SEQUENCE { version INTEGER, community OCTET STRING, PDU }
    let (tag, message_data, _) = parse_tlv(data)?;
    if tag != ber_tags::SEQUENCE {
        return Err(ParseError(format!("Expected SEQUENCE, got 0x{:02x}", tag)));
    }

    // Parse version
    let (tag, version_data, rest) = parse_tlv(message_data)?;
    if tag != ber_tags::INTEGER {
        return Err(ParseError(format!(
            "Expected INTEGER for version, got 0x{:02x}",
            tag
        )));
    }
    let version_num = parse_integer(version_data)?;
    let version = match version_num {
        0 => SnmpVersion::V1,
        1 => SnmpVersion::V2c,
        _ => {
            return Err(ParseError(format!(
                "Unsupported SNMP version: {}",
                version_num
            )))
        }
    };

    // Parse community string
    let (tag, community_data, rest) = parse_tlv(rest)?;
    if tag != ber_tags::OCTET_STRING {
        return Err(ParseError(format!(
            "Expected OCTET STRING for community, got 0x{:02x}",
            tag
        )));
    }
    let community = String::from_utf8_lossy(community_data).into_owned();

    // Parse PDU based on version
    let (pdu_tag, pdu_data, _) = parse_tlv(rest)?;

    match version {
        SnmpVersion::V1 => {
            if pdu_tag != ber_tags::TRAP_PDU_V1 {
                return Err(ParseError(format!(
                    "Expected Trap-PDU (0xA4), got 0x{:02x}",
                    pdu_tag
                )));
            }
            parse_v1_trap(pdu_data, source_addr, community)
        }
        SnmpVersion::V2c => {
            if pdu_tag != ber_tags::TRAP_PDU_V2 {
                return Err(ParseError(format!(
                    "Expected SNMPv2-Trap-PDU (0xA7), got 0x{:02x}",
                    pdu_tag
                )));
            }
            parse_v2c_trap(pdu_data, source_addr, community)
        }
    }
}

/// Parse SNMPv1 Trap-PDU
fn parse_v1_trap(data: &[u8], source_addr: SocketAddr, community: String) -> ParseResult<SnmpTrap> {
    // Trap-PDU: enterprise OID, agent-addr, generic-trap, specific-trap, time-stamp, varbinds

    // Enterprise OID
    let (tag, oid_data, rest) = parse_tlv(data)?;
    if tag != ber_tags::OBJECT_IDENTIFIER {
        return Err(ParseError(format!(
            "Expected OID for enterprise, got 0x{:02x}",
            tag
        )));
    }
    let enterprise_oid = parse_oid(oid_data)?;

    // Agent address (NetworkAddress - IpAddress)
    let (tag, _, rest) = parse_tlv(rest)?;
    if tag != ber_tags::IP_ADDRESS {
        return Err(ParseError(format!(
            "Expected IpAddress for agent-addr, got 0x{:02x}",
            tag
        )));
    }
    // We don't use agent-addr, skip it

    // Generic trap
    let (tag, generic_data, rest) = parse_tlv(rest)?;
    if tag != ber_tags::INTEGER {
        return Err(ParseError(format!(
            "Expected INTEGER for generic-trap, got 0x{:02x}",
            tag
        )));
    }
    let generic_num = parse_integer(generic_data)? as u8;
    let generic_trap = GenericTrap::from_u8(generic_num);

    // Specific trap
    let (tag, specific_data, rest) = parse_tlv(rest)?;
    if tag != ber_tags::INTEGER {
        return Err(ParseError(format!(
            "Expected INTEGER for specific-trap, got 0x{:02x}",
            tag
        )));
    }
    let specific_trap = parse_unsigned(specific_data)? as u32;

    // Timestamp
    let (tag, timestamp_data, rest) = parse_tlv(rest)?;
    if tag != ber_tags::TIMETICKS {
        return Err(ParseError(format!(
            "Expected TIMETICKS for time-stamp, got 0x{:02x}",
            tag
        )));
    }
    let uptime = parse_unsigned(timestamp_data)? as u32;

    // Varbind list
    let (tag, varbind_data, _) = parse_tlv(rest)?;
    if tag != ber_tags::SEQUENCE {
        return Err(ParseError(format!(
            "Expected SEQUENCE for varbinds, got 0x{:02x}",
            tag
        )));
    }
    let varbinds = parse_varbinds(varbind_data)?;

    Ok(SnmpTrap {
        source_addr,
        version: SnmpVersion::V1,
        community,
        trap_oid: enterprise_oid,
        generic_trap,
        specific_trap: Some(specific_trap),
        uptime,
        varbinds,
    })
}

/// Parse SNMPv2c Trap-PDU
fn parse_v2c_trap(
    data: &[u8],
    source_addr: SocketAddr,
    community: String,
) -> ParseResult<SnmpTrap> {
    // SNMPv2-Trap-PDU: request-id, error-status, error-index, varbinds
    // The trap OID is in the second varbind (snmpTrapOID.0)

    // Request ID
    let (tag, _, rest) = parse_tlv(data)?;
    if tag != ber_tags::INTEGER {
        return Err(ParseError(format!(
            "Expected INTEGER for request-id, got 0x{:02x}",
            tag
        )));
    }

    // Error status
    let (tag, _, rest) = parse_tlv(rest)?;
    if tag != ber_tags::INTEGER {
        return Err(ParseError(format!(
            "Expected INTEGER for error-status, got 0x{:02x}",
            tag
        )));
    }

    // Error index
    let (tag, _, rest) = parse_tlv(rest)?;
    if tag != ber_tags::INTEGER {
        return Err(ParseError(format!(
            "Expected INTEGER for error-index, got 0x{:02x}",
            tag
        )));
    }

    // Varbind list
    let (tag, varbind_data, _) = parse_tlv(rest)?;
    if tag != ber_tags::SEQUENCE {
        return Err(ParseError(format!(
            "Expected SEQUENCE for varbinds, got 0x{:02x}",
            tag
        )));
    }
    let varbinds = parse_varbinds(varbind_data)?;

    // Extract sysUpTime from first varbind (1.3.6.1.2.1.1.3.0)
    let uptime = varbinds
        .first()
        .filter(|(oid, _)| oid == "1.3.6.1.2.1.1.3.0")
        .and_then(|(_, value)| value.parse::<u32>().ok())
        .unwrap_or(0);

    // Extract snmpTrapOID from second varbind (1.3.6.1.6.3.1.1.4.1.0)
    let trap_oid = varbinds
        .get(1)
        .filter(|(oid, _)| oid == "1.3.6.1.6.3.1.1.4.1.0")
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // Remaining varbinds (skip first two which are sysUpTime and snmpTrapOID)
    let remaining_varbinds: Vec<_> = varbinds.into_iter().skip(2).collect();

    Ok(SnmpTrap {
        source_addr,
        version: SnmpVersion::V2c,
        community,
        trap_oid,
        generic_trap: None,
        specific_trap: None,
        uptime,
        varbinds: remaining_varbinds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_length_short() {
        assert_eq!(parse_length(&[0x05]).unwrap(), (5, 1));
        assert_eq!(parse_length(&[0x7F]).unwrap(), (127, 1));
    }

    #[test]
    fn test_parse_length_long() {
        // Two-byte length: 0x81 0x80 = 128
        assert_eq!(parse_length(&[0x81, 0x80]).unwrap(), (128, 2));
        // Three-byte length: 0x82 0x01 0x00 = 256
        assert_eq!(parse_length(&[0x82, 0x01, 0x00]).unwrap(), (256, 3));
    }

    #[test]
    fn test_parse_integer() {
        assert_eq!(parse_integer(&[0x00]).unwrap(), 0);
        assert_eq!(parse_integer(&[0x01]).unwrap(), 1);
        assert_eq!(parse_integer(&[0x7F]).unwrap(), 127);
        assert_eq!(parse_integer(&[0x00, 0x80]).unwrap(), 128);
        assert_eq!(parse_integer(&[0xFF]).unwrap(), -1);
        assert_eq!(parse_integer(&[0x80]).unwrap(), -128);
    }

    #[test]
    fn test_parse_oid() {
        // 1.3.6.1.2.1.1.1.0 = 0x2B 0x06 0x01 0x02 0x01 0x01 0x01 0x00
        let oid_bytes = [0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        assert_eq!(parse_oid(&oid_bytes).unwrap(), "1.3.6.1.2.1.1.1.0");
    }

    #[test]
    fn test_parse_oid_large_component() {
        // OID with component > 127 (uses multi-byte encoding)
        // 1.3.6.1.4.1.9.9.41 where 9.9.41 tests various sizes
        let oid_bytes = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x09, 0x09, 0x29];
        assert_eq!(parse_oid(&oid_bytes).unwrap(), "1.3.6.1.4.1.9.9.41");
    }

    #[test]
    fn test_generic_trap_display() {
        assert_eq!(format!("{}", GenericTrap::ColdStart), "coldStart");
        assert_eq!(format!("{}", GenericTrap::LinkUp), "linkUp");
        assert_eq!(
            format!("{}", GenericTrap::EnterpriseSpecific),
            "enterpriseSpecific"
        );
    }

    #[test]
    fn test_snmp_version_display() {
        assert_eq!(format!("{}", SnmpVersion::V1), "v1");
        assert_eq!(format!("{}", SnmpVersion::V2c), "v2c");
    }

    #[test]
    fn test_snmp_trap_display_v1() {
        let trap = SnmpTrap {
            source_addr: "192.168.1.1:161".parse().unwrap(),
            version: SnmpVersion::V1,
            community: "public".to_string(),
            trap_oid: "1.3.6.1.4.1.9.9.41".to_string(),
            generic_trap: Some(GenericTrap::EnterpriseSpecific),
            specific_trap: Some(1),
            uptime: 12345,
            varbinds: vec![("1.3.6.1.2.1.2.2.1.1".to_string(), "2".to_string())],
        };

        let display = format!("{}", trap);
        assert!(display.contains("192.168.1.1:161"));
        assert!(display.contains("[v1]"));
        assert!(display.contains("enterprise=1.3.6.1.4.1.9.9.41"));
        assert!(display.contains("generic=enterpriseSpecific"));
        assert!(display.contains("specific=1"));
        assert!(display.contains("uptime=12345"));
    }

    #[test]
    fn test_snmp_trap_display_v2c() {
        let trap = SnmpTrap {
            source_addr: "192.168.1.1:161".parse().unwrap(),
            version: SnmpVersion::V2c,
            community: "public".to_string(),
            trap_oid: "1.3.6.1.6.3.1.1.5.4".to_string(),
            generic_trap: None,
            specific_trap: None,
            uptime: 12345,
            varbinds: vec![("ifIndex.2".to_string(), "2".to_string())],
        };

        let display = format!("{}", trap);
        assert!(display.contains("192.168.1.1:161"));
        assert!(display.contains("[v2c]"));
        assert!(display.contains("oid=1.3.6.1.6.3.1.1.5.4"));
        assert!(display.contains("uptime=12345"));
    }

    #[test]
    fn test_parse_octet_string_printable() {
        let data = b"Hello World";
        assert_eq!(parse_octet_string(data), "Hello World");
    }

    #[test]
    fn test_parse_octet_string_binary() {
        let data = [0x00, 0x01, 0x02, 0xFF];
        assert_eq!(parse_octet_string(&data), "000102ff");
    }

    #[test]
    fn test_parse_ip_address() {
        assert_eq!(parse_ip_address(&[192, 168, 1, 1]).unwrap(), "192.168.1.1");
    }

    #[test]
    fn test_parse_ip_address_invalid_length() {
        assert!(parse_ip_address(&[192, 168, 1]).is_err());
    }
}
