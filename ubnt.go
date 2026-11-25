package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/towerops-app/towerops-agent/pb"
)

// Ubiquiti broadcast discovery (UDP 10001). Devices answer the 4-byte
// request below with a packet in the same framing (4-byte header, then
// TLV records) carrying model, firmware, MAC, hostname and uptime. The
// job collects replies for a bounded window and reports every responder
// so the server can seed discovery candidates.

const (
	ubntDefaultPort      = 10001
	ubntDefaultCollectMS = 3000
	// Broadcast replies arrive in bursts; a small socket buffer per reply is
	// plenty and keeps the collection window cheap.
	ubntReadBufferBytes = 2048
	// A device that ships an absurd TLV payload must not grow the result
	// unboundedly.
	ubntMaxFieldBytes = 255
)

// ubntDiscoveryRequest is the fixed 4-byte probe every UBNT device
// answers: version 1, command 0 (discovery), length 0.
var ubntDiscoveryRequest = []byte{0x01, 0x00, 0x00, 0x00}

// TLV types from the UBNT discovery format. Unknown types are skipped:
// newer firmware adds fields older tools never decoded.
const (
	ubntTLVMAC      = 0x01 // 6 bytes, MAC address
	ubntTLVMACIP    = 0x02 // 6-byte MAC + 4-byte IPv4
	ubntTLVFirmware = 0x03 // version string
	ubntTLVUptime   = 0x0a // uint32 seconds
	ubntTLVHostname = 0x0b // device name
	ubntTLVModel    = 0x0c // short model string
)

// executeUbntDiscovery broadcasts the request, collects TLV replies for
// the window, and reports one UbntDiscoveryResult.
func executeUbntDiscovery(ctx context.Context, job *pb.AgentJob, out *resultQueue) {
	started := time.Now()
	result := &pb.UbntDiscoveryResult{ProbeId: job.JobId}

	send := func() {
		result.DurationMs = uint32(time.Since(started).Milliseconds())
		result.Timestamp = time.Now().Unix()
		if result.ErrorMessage != "" {
			recordJobFailure()
		}
		slog.Debug("ubnt discovery complete",
			"probe_id", result.ProbeId,
			"peers", len(result.Peers),
			"duration_ms", result.DurationMs)
		sendResult(ctx, out, "ubnt_discovery_result", result, job.JobId)
	}

	cfg := job.UbntDiscovery
	if cfg == nil {
		result.ErrorMessage = "missing ubnt discovery configuration"
		send()
		return
	}

	port := int(cfg.Port)
	if port == 0 {
		port = ubntDefaultPort
	}
	collect := time.Duration(ubntDefaultCollectMS) * time.Millisecond
	if cfg.CollectMs > 0 {
		collect = time.Duration(cfg.CollectMs) * time.Millisecond
	}
	dest := cfg.Target
	if dest == "" {
		dest = cfg.BroadcastAddress
	}
	if dest == "" {
		dest = "255.255.255.255"
	}

	peers, err := runUbntProbe(ctx, dest, port, collect)
	switch {
	case err != nil && ctx.Err() != nil:
		return
	case err != nil:
		result.ErrorMessage = err.Error()
	default:
		result.Peers = peers
	}
	send()
}

// runUbntProbe sends the request to dest:port and collects replies until
// the window closes or ctx cancels. Replies dedupe on MAC so a device
// answering on two interfaces reports once; reply order is stable.
func runUbntProbe(ctx context.Context, dest string, port int, collect time.Duration) ([]*pb.UbntDiscoveryPeer, error) {
	return runUbntProbeOn(ctx, ":0", dest, port, collect)
}

// runUbntProbeOn runs the probe on an explicit bind address; callers use
// ":0". Kept as a parameter so tests can reach the listen failure.
func runUbntProbeOn(ctx context.Context, bindAddr string, dest string, port int,
	collect time.Duration) ([]*pb.UbntDiscoveryPeer, error) {
	conn, err := ubntListen(ctx, bindAddr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	dst := &net.UDPAddr{IP: net.ParseIP(dest), Port: port}
	if err := ubntSendRequest(conn, dst, dest); err != nil {
		return nil, err
	}
	return collectUbntReplies(ctx, conn, collect)
}

// collectUbntReplies reads replies until collect elapses or ctx cancels.
func collectUbntReplies(ctx context.Context, conn net.PacketConn,
	collect time.Duration) ([]*pb.UbntDiscoveryPeer, error) {
	deadline := time.Now().Add(collect)
	seen := make(map[string]*pb.UbntDiscoveryPeer)
	buf := make([]byte, ubntReadBufferBytes)

	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(min(remaining, 50*time.Millisecond)))

		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				continue
			}
			return nil, fmt.Errorf("read: %w", err)
		}

		source := addr.String()
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			source = udpAddr.IP.String()
		}
		peer, err := parseUbntReply(buf[:n], source)
		if err != nil {
			slog.Debug("dropping malformed ubnt reply", "source", source, "error", err)
			continue
		}
		key := peer.MacAddress
		if key == "" {
			key = "ip:" + peer.SourceIp
		}
		// First reply wins: later copies carry the same TLVs and a second
		// interface's source would only duplicate the row.
		if _, ok := seen[key]; !ok {
			seen[key] = peer
		}
	}

	peers := make([]*pb.UbntDiscoveryPeer, 0, len(seen))
	for _, peer := range seen {
		peers = append(peers, peer)
	}
	// Deterministic order for the report and for tests.
	slices.SortFunc(peers, func(a, b *pb.UbntDiscoveryPeer) int {
		return strings.Compare(a.SourceIp, b.SourceIp)
	})
	return peers, nil
}

// ubntListen binds a UDP socket with SO_BROADCAST: DialUDP cannot send
// to a broadcast address without the option, and the bound socket is
// also the listener the replies arrive on.
func ubntListen(ctx context.Context, bindAddr string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return ubntSetBroadcast(c)
		},
	}
	conn, err := lc.ListenPacket(ctx, "udp4", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	return conn, nil
}

// ubntSetBroadcast turns on SO_BROADCAST for the bound socket.
func ubntSetBroadcast(c syscall.RawConn) error {
	var err error
	ctrlErr := c.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return err
}

// ubntSendRequest validates the destination and sends the discovery
// request on the bound socket.
func ubntSendRequest(conn net.PacketConn, dst *net.UDPAddr, dest string) error {
	if dst.IP == nil {
		return fmt.Errorf("invalid destination %q", dest)
	}
	if _, err := conn.WriteTo(ubntDiscoveryRequest, dst); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

// parseUbntReply decodes one reply packet into a peer. Replies carry the
// same framing as the request: a 4-byte header (version 1, command 0,
// 2-byte big endian payload length) followed by TLV records, each a
// type(1)/length(2 BE)/value sequence. Short or malformed packets are
// rejected, unknown TLVs skipped.
func parseUbntReply(packet []byte, sourceIP string) (*pb.UbntDiscoveryPeer, error) {
	if len(packet) < 4 {
		return nil, fmt.Errorf("short reply: %d bytes, no header", len(packet))
	}
	if packet[0] != 0x01 || packet[1] != 0x00 {
		return nil, fmt.Errorf("unexpected reply header: version %#x, command %#x",
			packet[0], packet[1])
	}
	declared := int(binary.BigEndian.Uint16(packet[2:4]))
	payload := packet[4 : 4+min(declared, len(packet)-4)]
	peer := &pb.UbntDiscoveryPeer{SourceIp: sourceIP}
	for len(payload) >= 3 {
		tlvType := payload[0]
		length := int(binary.BigEndian.Uint16(payload[1:3]))
		payload = payload[3:]
		if length > len(payload) {
			return nil, fmt.Errorf("truncated tlv type %#x: %d bytes advertised, %d present",
				tlvType, length, len(payload))
		}
		value := payload[:length]
		payload = payload[length:]

		switch tlvType {
		case ubntTLVMAC:
			if len(value) == 6 {
				peer.MacAddress = formatMAC(value)
			}
		case ubntTLVMACIP:
			if len(value) >= 6 {
				peer.MacAddress = formatMAC(value[:6])
			}
		case ubntTLVFirmware:
			peer.Firmware = truncateBytes(string(value), ubntMaxFieldBytes)
		case ubntTLVUptime:
			if len(value) == 4 {
				peer.UptimeSeconds = binary.BigEndian.Uint32(value)
			}
		case ubntTLVHostname:
			peer.Hostname = truncateBytes(string(value), ubntMaxFieldBytes)
		case ubntTLVModel:
			peer.Model = truncateBytes(string(value), ubntMaxFieldBytes)
		}
	}
	if len(payload) != 0 {
		return nil, fmt.Errorf("%d trailing bytes after last tlv", len(payload))
	}
	if peer.MacAddress == "" && peer.Model == "" && peer.Hostname == "" {
		return nil, errors.New("reply carried no usable device fields")
	}
	return peer, nil
}

func formatMAC(b []byte) string {
	return net.HardwareAddr(b).String()
}
