use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// ICMP protocol number
const IPPROTO_ICMP: i32 = 1;

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
    // ICMP reply might be wrapped in an IP header (20 bytes minimum)
    // Try both raw ICMP and IP-wrapped formats

    // Try to parse as raw ICMP first
    if let Ok(()) = try_parse_icmp(packet, expected_identifier, expected_sequence) {
        return Ok(());
    }

    // Try to parse with IP header (skip first 20 bytes)
    if packet.len() > 20 {
        if let Ok(()) = try_parse_icmp(&packet[20..], expected_identifier, expected_sequence) {
            return Ok(());
        }
    }

    Err(anyhow!("Invalid ICMP reply packet"))
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
        // Known ICMP echo request packet with correct checksum
        let packet = vec![
            0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01, 0x61, 0x62, 0x63, 0x64,
        ];

        // Calculate checksum for packet with checksum field zeroed
        let mut test_packet = packet.clone();
        test_packet[2] = 0;
        test_packet[3] = 0;

        let checksum = icmp_checksum(&test_packet);
        assert_eq!(checksum, 0xf7ff);
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
}
