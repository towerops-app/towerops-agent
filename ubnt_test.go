package main

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

// ubntTLV builds one type/length/value record the way a device encodes it.
func ubntTLV(tlvType byte, value []byte) []byte {
	out := []byte{tlvType, 0, 0}
	binary.BigEndian.PutUint16(out[1:3], uint16(len(value)))
	return append(out, value...)
}

// ubntReply assembles a full TLV reply packet.
func ubntReply(tlvs ...[]byte) []byte {
	var packet []byte
	for _, t := range tlvs {
		packet = append(packet, t...)
	}
	return packet
}

func ubntTestMAC(b0, b1, b2, b3, b4, b5 byte) []byte {
	return []byte{b0, b1, b2, b3, b4, b5}
}

func TestParseUbntReply(t *testing.T) {
	t.Run("populates model, firmware, MAC and hostname", func(t *testing.T) {
		packet := ubntReply(
			ubntTLV(ubntTLVMACIP, append(ubntTestMAC(0xdc, 0x9f, 0xdb, 0x12, 0x34, 0x56),
				192, 168, 88, 20)),
			ubntTLV(ubntTLVModel, []byte("nRAY-60")),
			ubntTLV(ubntTLVFirmware, []byte("WA.v8.7.19")),
			ubntTLV(ubntTLVHostname, []byte("sector-east-3")),
			ubntTLV(ubntTLVUptime, []byte{0, 0x12, 0xd6, 0x87}), // 1234567
		)

		peer, err := parseUbntReply(packet, "192.168.88.20")
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		if peer.MacAddress != "dc:9f:db:12:34:56" {
			t.Errorf("mac = %q", peer.MacAddress)
		}
		if peer.Model != "nRAY-60" {
			t.Errorf("model = %q", peer.Model)
		}
		if peer.Firmware != "WA.v8.7.19" {
			t.Errorf("firmware = %q", peer.Firmware)
		}
		if peer.Hostname != "sector-east-3" {
			t.Errorf("hostname = %q", peer.Hostname)
		}
		if peer.UptimeSeconds != 1234567 {
			t.Errorf("uptime = %d", peer.UptimeSeconds)
		}
		if peer.SourceIp != "192.168.88.20" {
			t.Errorf("source_ip = %q", peer.SourceIp)
		}
	})

	t.Run("bare MAC tlv and unknown types", func(t *testing.T) {
		packet := ubntReply(
			ubntTLV(ubntTLVMAC, ubntTestMAC(0xb8, 0x69, 0xf4, 0xaa, 0xbb, 0xcc)),
			ubntTLV(0x14, []byte("unknown field the parser must skip")),
		)

		peer, err := parseUbntReply(packet, "10.0.0.9")
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		if peer.MacAddress != "b8:69:f4:aa:bb:cc" {
			t.Errorf("mac = %q", peer.MacAddress)
		}
	})

	t.Run("truncated tlv is rejected", func(t *testing.T) {
		packet := []byte{ubntTLVModel, 0, 9, 'n', 'R'}
		if _, err := parseUbntReply(packet, "10.0.0.1"); err == nil {
			t.Fatal("expected truncated tlv to fail")
		}
	})

	t.Run("field-less packet is rejected", func(t *testing.T) {
		packet := ubntTLV(0x7f, []byte("only an unknown tlv"))
		if _, err := parseUbntReply(packet, "10.0.0.1"); err == nil {
			t.Fatal("expected empty reply to fail")
		}
	})
}

// TestRunUbntProbe exercises the collect path against a stub responder on
// loopback: unicast target so no broadcast permission is needed.
func TestRunUbntProbe(t *testing.T) {
	responder, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("responder listen: %v", err)
	}
	defer func() { _ = responder.Close() }()
	port := responder.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 64)
		n, src, err := responder.ReadFromUDP(buf)
		if err != nil || n < len(ubntDiscoveryRequest) {
			return
		}
		_, _ = responder.WriteToUDP(ubntReply(
			ubntTLV(ubntTLVMACIP, append(ubntTestMAC(0xdc, 0x9f, 0xdb, 0x12, 0x34, 0x56),
				192, 168, 88, 20)),
			ubntTLV(ubntTLVModel, []byte("nRAY-60")),
			ubntTLV(ubntTLVFirmware, []byte("WA.v8.7.19")),
			ubntTLV(ubntTLVHostname, []byte("sector-east-3")),
		), src)
	}()

	peers, err := runUbntProbe(context.Background(), "127.0.0.1", port, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].MacAddress != "dc:9f:db:12:34:56" || peers[0].Model != "nRAY-60" {
		t.Errorf("peer = %+v", peers[0])
	}
}

func TestExecuteUbntDiscovery(t *testing.T) {
	t.Run("missing configuration reports an error result", func(t *testing.T) {
		out := testQueue()
		executeUbntDiscovery(context.Background(), &pb.AgentJob{
			JobId:   "u1",
			JobType: pb.JobType_UBNT_DISCOVERY,
		}, out)

		result := wantResult[*pb.UbntDiscoveryResult](t, out, "ubnt_discovery_result", 500*time.Millisecond)
		if result.ErrorMessage == "" {
			t.Error("expected an error message")
		}
	})

	t.Run("dispatch runs the job on the ubnt pool", func(t *testing.T) {
		pools := testPools(t)
		if pools.ubnt == nil {
			t.Skip("testPools has no ubnt pool")
		}
		out := testQueue()
		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:         "u2",
			JobType:       pb.JobType_UBNT_DISCOVERY,
			UbntDiscovery: &pb.UbntDiscoveryJob{Target: "127.0.0.1", CollectMs: 50},
		}, pools, out)

		result := wantResult[*pb.UbntDiscoveryResult](t, out, "ubnt_discovery_result", 2*time.Second)
		if result.ProbeId != "u2" {
			t.Errorf("probe_id = %q", result.ProbeId)
		}
	})
}
