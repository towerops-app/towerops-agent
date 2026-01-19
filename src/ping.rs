use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// ICMP message types
const ICMP_ECHO: u8 = 8;
const ICMP_ECHOREPLY: u8 = 0;

/// Pings an IP address using raw ICMP and returns the round-trip time.
///
/// This implementation uses raw ICMP sockets instead of relying on the system
/// `ping` command, making it suitable for containerized environments.
///
/// # Arguments
///
/// * `ip` - The IP address to ping
/// * `timeout_duration` - Maximum time to wait for a response
///
/// # Returns
///
/// * `Ok(Duration)` - The round-trip time if successful
/// * `Err(anyhow::Error)` - If the ping fails or times out
///
/// # Note
///
/// Raw ICMP sockets require elevated privileges (CAP_NET_RAW on Linux).
/// The application should be run with appropriate capabilities.
pub async fn ping(ip: IpAddr, timeout_duration: Duration) -> Result<Duration> {
    let start = std::time::Instant::now();

    match ip {
        IpAddr::V4(ipv4) => ping_ipv4(ipv4, timeout_duration).await?,
        IpAddr::V6(_) => {
            return Err(anyhow!("IPv6 ping not yet implemented"));
        }
    }

    Ok(start.elapsed())
}

async fn ping_ipv4(ip: Ipv4Addr, timeout_duration: Duration) -> Result<()> {
    // Generate unique identifier and sequence number
    let identifier = rand::random::<u16>();
    let sequence = rand::random::<u16>();

    // Build ICMP echo request packet
    let packet = build_icmp_echo_request(identifier, sequence);

    // Create raw socket for ICMP
    // Note: This requires CAP_NET_RAW capability on Linux
    let socket = socket2::Socket::new_raw(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::ICMPV4),
    )?;

    socket.set_nonblocking(true)?;

    // Convert to tokio UdpSocket
    let std_socket: std::net::UdpSocket = socket.into();
    std_socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(std_socket)?;

    // Connect to the target IP (this is for sendto/recvfrom convenience)
    let addr = std::net::SocketAddr::new(IpAddr::V4(ip), 0);
    socket.connect(addr).await?;

    // Send ICMP echo request
    socket.send(&packet).await?;

    // Wait for ICMP echo reply with timeout
    let mut buf = [0u8; 1024];
    let n = timeout(timeout_duration, socket.recv(&mut buf))
        .await
        .map_err(|_| anyhow!("Ping timeout"))?
        .map_err(|e| anyhow!("Failed to receive ping reply: {}", e))?;

    // Parse and validate the reply
    parse_icmp_reply(&buf[..n], identifier, sequence)?;

    Ok(())
}

fn build_icmp_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
    // ICMP Echo Request format:
    // Type (8) | Code (0) | Checksum (16) | Identifier (16) | Sequence (16) | Data (variable)
    let type_code = ICMP_ECHO;
    let code = 0u8;
    let checksum = 0u16; // Placeholder
    let data = b"towerops_ping"; // Payload

    // Build packet without checksum
    let mut packet = Vec::new();
    packet.push(type_code);
    packet.push(code);
    packet.extend_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(data);

    // Calculate and insert checksum
    let calculated_checksum = icmp_checksum(&packet);
    packet[2..4].copy_from_slice(&calculated_checksum.to_be_bytes());

    packet
}

fn parse_icmp_reply(packet: &[u8], expected_identifier: u16, expected_sequence: u16) -> Result<()> {
    // ICMP reply might be wrapped in an IP header
    // Try both raw ICMP and IP-wrapped formats

    // Try to parse as raw ICMP first
    if let Ok(()) = try_parse_icmp(packet, expected_identifier, expected_sequence) {
        return Ok(());
    }

    // Check if this looks like an IP packet (version 4 in high nibble of first byte)
    if packet.len() >= 20 && (packet[0] >> 4) == 4 {
        // Extract IP header length from IHL field (low nibble of first byte)
        // IHL is in 32-bit words, so multiply by 4 to get bytes
        let ihl = (packet[0] & 0x0F) as usize * 4;

        if ihl >= 20 && packet.len() > ihl {
            // Try to parse ICMP after skipping the IP header
            if let Ok(()) = try_parse_icmp(&packet[ihl..], expected_identifier, expected_sequence) {
                return Ok(());
            }
        }
    }

    // Log diagnostic information to help debug
    // Determine the ICMP portion (might need to skip IP header)
    let icmp_packet = if packet.len() >= 20 && (packet[0] >> 4) == 4 {
        let ihl = (packet[0] & 0x0F) as usize * 4;
        if ihl >= 20 && packet.len() > ihl {
            &packet[ihl..]
        } else {
            packet
        }
    } else {
        packet
    };

    let packet_preview = if icmp_packet.len() >= 8 {
        format!(
            "type={} code={} id={} seq={} len={} (total={})",
            icmp_packet[0],
            icmp_packet.get(1).unwrap_or(&0),
            u16::from_be_bytes([
                *icmp_packet.get(4).unwrap_or(&0),
                *icmp_packet.get(5).unwrap_or(&0)
            ]),
            u16::from_be_bytes([
                *icmp_packet.get(6).unwrap_or(&0),
                *icmp_packet.get(7).unwrap_or(&0)
            ]),
            icmp_packet.len(),
            packet.len()
        )
    } else {
        format!("len={} (too short)", packet.len())
    };

    Err(anyhow!(
        "Invalid ICMP reply packet (expected id={}, seq={}): {}",
        expected_identifier,
        expected_sequence,
        packet_preview
    ))
}

fn try_parse_icmp(packet: &[u8], expected_identifier: u16, expected_sequence: u16) -> Result<()> {
    if packet.len() < 8 {
        return Err(anyhow!("Packet too short"));
    }

    let icmp_type = packet[0];
    let icmp_code = packet[1];
    let identifier = u16::from_be_bytes([packet[4], packet[5]]);
    let sequence = u16::from_be_bytes([packet[6], packet[7]]);

    if icmp_type == ICMP_ECHOREPLY
        && icmp_code == 0
        && identifier == expected_identifier
        && sequence == expected_sequence
    {
        Ok(())
    } else {
        Err(anyhow!(
            "ICMP packet mismatch (type={}, code={}, id={}, seq={})",
            icmp_type,
            icmp_code,
            identifier,
            sequence
        ))
    }
}

fn icmp_checksum(data: &[u8]) -> u16 {
    // ICMP checksum is the 16-bit one's complement of the one's complement sum
    let mut sum = 0u32;

    // Sum all 16-bit words
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            // Odd byte - pad with zero
            (chunk[0] as u32) << 8
        };
        sum += word;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_checksum() {
        // Test that checksum calculation is consistent
        // ICMP echo request packet: type=8, code=0, id=1, seq=1, data="abcd"
        let mut packet = vec![
            0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x61, 0x62, 0x63, 0x64,
        ];

        // Calculate checksum
        let checksum = icmp_checksum(&packet);
        assert_ne!(checksum, 0, "Checksum should not be zero");

        // Insert checksum into packet
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        // Verify: recalculating checksum with checksum field included should give 0
        // (because the sum of all words including the checksum should wrap to 0xFFFF,
        // and one's complement of 0xFFFF is 0)
        let verification = icmp_checksum(&packet);
        assert_eq!(verification, 0, "Checksum verification should be 0");
    }

    #[test]
    fn test_build_icmp_echo_request() {
        let identifier = 0x0001;
        let sequence = 0x0001;
        let packet = build_icmp_echo_request(identifier, sequence);

        // Verify packet structure
        assert_eq!(packet[0], ICMP_ECHO); // Type
        assert_eq!(packet[1], 0); // Code

        // Verify identifier and sequence
        let id = u16::from_be_bytes([packet[4], packet[5]]);
        let seq = u16::from_be_bytes([packet[6], packet[7]]);
        assert_eq!(id, identifier);
        assert_eq!(seq, sequence);

        // Verify checksum is non-zero
        let checksum = u16::from_be_bytes([packet[2], packet[3]]);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_try_parse_icmp_success() {
        // Valid ICMP echo reply packet
        let packet = vec![
            0x00, 0x00, 0x00, 0x00, // type=0 (reply), code=0, checksum
            0x12, 0x34, // identifier
            0x56, 0x78, // sequence
            0x61, 0x62, 0x63, 0x64, // data
        ];

        let result = try_parse_icmp(&packet, 0x1234, 0x5678);
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_parse_icmp_too_short() {
        let packet = vec![0x00, 0x00, 0x00];
        let result = try_parse_icmp(&packet, 0x1234, 0x5678);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_try_parse_icmp_wrong_type() {
        let packet = vec![
            0x08, 0x00, 0x00, 0x00, // type=8 (request, not reply), code=0
            0x12, 0x34, // identifier
            0x56, 0x78, // sequence
        ];

        let result = try_parse_icmp(&packet, 0x1234, 0x5678);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mismatch"));
    }

    #[test]
    fn test_try_parse_icmp_wrong_identifier() {
        let packet = vec![
            0x00, 0x00, 0x00, 0x00, // type=0, code=0
            0x99, 0x99, // wrong identifier
            0x56, 0x78, // sequence
        ];

        let result = try_parse_icmp(&packet, 0x1234, 0x5678);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_icmp_reply_raw() {
        // Raw ICMP packet (no IP header)
        let packet = vec![
            0x00, 0x00, 0x00, 0x00, // type=0, code=0, checksum
            0x12, 0x34, // identifier
            0x56, 0x78, // sequence
        ];

        let result = parse_icmp_reply(&packet, 0x1234, 0x5678);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_icmp_reply_with_ip_header() {
        // IPv4 packet with ICMP payload
        let packet = vec![
            0x45, 0x00, 0x00, 0x54, // IPv4 header: version=4, IHL=5 (20 bytes)
            0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, // TTL, protocol=ICMP
            0xc0, 0xa8, 0x01, 0x01, // Source IP
            0xc0, 0xa8, 0x01, 0x02, // Dest IP
            // ICMP payload starts here (at byte 20)
            0x00, 0x00, 0x00, 0x00, // type=0, code=0, checksum
            0x12, 0x34, // identifier
            0x56, 0x78, // sequence
        ];

        let result = parse_icmp_reply(&packet, 0x1234, 0x5678);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_icmp_reply_invalid() {
        let packet = vec![0x00, 0x00];
        let result = parse_icmp_reply(&packet, 0x1234, 0x5678);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid ICMP reply"));
    }

    #[test]
    fn test_parse_icmp_reply_short_packet_error_message() {
        let packet = vec![0x01, 0x02, 0x03];
        let result = parse_icmp_reply(&packet, 0x1234, 0x5678);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("too short"));
    }
}
