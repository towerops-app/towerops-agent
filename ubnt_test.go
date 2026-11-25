package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
	"unicode/utf8"

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

	peers, _, err := runUbntProbe(context.Background(), "127.0.0.1", port, 300*time.Millisecond)
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

func TestExecuteUbntDiscoveryDefaults(t *testing.T) {
	// Every field defaulted: the destination falls back to the global
	// broadcast and the job still completes (it just sees nothing on the
	// test machine's broadcast domain).
	out := testQueue()
	executeUbntDiscovery(context.Background(), &pb.AgentJob{
		JobId:         "u3",
		JobType:       pb.JobType_UBNT_DISCOVERY,
		UbntDiscovery: &pb.UbntDiscoveryJob{CollectMs: 50},
	}, out)

	result := wantResult[*pb.UbntDiscoveryResult](t, out, "ubnt_discovery_result", 2*time.Second)
	// Broadcast may or may not succeed on CI; either way the result lands.
	if result.ProbeId != "u3" {
		t.Errorf("probe_id = %q", result.ProbeId)
	}
}

func TestExecuteUbntDiscoveryUnicastTarget(t *testing.T) {
	// An invalid destination reports an error result instead of panicking.
	out := testQueue()
	executeUbntDiscovery(context.Background(), &pb.AgentJob{
		JobId:         "u4",
		JobType:       pb.JobType_UBNT_DISCOVERY,
		UbntDiscovery: &pb.UbntDiscoveryJob{Target: "not-an-address", CollectMs: 10},
	}, out)

	result := wantResult[*pb.UbntDiscoveryResult](t, out, "ubnt_discovery_result", 2*time.Second)
	if result.ErrorMessage == "" {
		t.Error("expected an invalid destination error")
	}
}

func TestRunUbntProbeCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	responder, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("responder listen: %v", err)
	}
	defer func() { _ = responder.Close() }()
	port := responder.LocalAddr().(*net.UDPAddr).Port

	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	_, _, err = runUbntProbe(ctx, "127.0.0.1", port, 5*time.Second)
	if err == nil {
		t.Fatal("expected context cancellation to abort the probe")
	}
}

func TestRunUbntProbeDropsMalformedAndKeysByIP(t *testing.T) {
	responder, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("responder listen: %v", err)
	}
	defer func() { _ = responder.Close() }()
	port := responder.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 64)
		for {
			_, src, err := responder.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// A truncated packet: the reader drops it and keeps collecting.
			_, _ = responder.WriteToUDP([]byte{0x0c, 0x00, 0x09, 'n'}, src)
			// A reply whose only usable field is a model, keyed on source IP
			// since no MAC TLV arrived.
			_, _ = responder.WriteToUDP(ubntReply(
				ubntTLV(ubntTLVModel, []byte("LHG-5nD")),
			), src)
		}
	}()

	peers, _, err := runUbntProbe(context.Background(), "127.0.0.1", port, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(peers) != 1 || peers[0].Model != "LHG-5nD" {
		t.Fatalf("peers = %+v", peers)
	}
}

func TestParseUbntReplyTrailingBytes(t *testing.T) {
	packet := ubntReply(ubntTLV(ubntTLVModel, []byte("m5")))
	packet = append(packet, 0xff) // one dangling byte after the last TLV
	if _, err := parseUbntReply(packet, "10.0.0.1"); err == nil {
		t.Fatal("expected trailing bytes to fail")
	}
}

func TestJobTargetKeyUbnt(t *testing.T) {
	tests := []struct {
		name string
		job  *pb.AgentJob
		want string
	}{
		{
			"broadcast destination keys on the domain",
			&pb.AgentJob{UbntDiscovery: &pb.UbntDiscoveryJob{BroadcastAddress: "192.168.88.255", Port: 10001}},
			"ubnt:192.168.88.255:10001",
		},
		{
			"unicast target wins over broadcast",
			&pb.AgentJob{UbntDiscovery: &pb.UbntDiscoveryJob{Target: "10.0.0.20"}},
			"ubnt:10.0.0.20",
		},
		{
			"no destination falls back to the job key",
			&pb.AgentJob{JobId: "job-9", UbntDiscovery: &pb.UbntDiscoveryJob{}},
			"job:job-9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jobTargetKey(tt.job); got != tt.want {
				t.Errorf("jobTargetKey = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUbntListenErrors(t *testing.T) {
	// An unparseable bind address surfaces the listen error.
	if _, err := ubntListen(context.Background(), "256.256.256.256:0"); err == nil {
		t.Fatal("expected listen error")
	}
}

func TestUbntSetBroadcastCtrlError(t *testing.T) {
	if err := ubntSetBroadcast(failingRawConn{}); err == nil {
		t.Fatal("expected control error")
	}
}

// failingRawConn fails Control so ubntSetBroadcast's ctrlErr branch runs.
type failingRawConn struct{}

func (failingRawConn) Control(func(uintptr)) error    { return errors.New("ctrl boom") }
func (failingRawConn) Read(func(uintptr) bool) error  { return nil }
func (failingRawConn) Write(func(uintptr) bool) error { return nil }

func TestUbntSendRequestErrors(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := ubntSendRequest(conn, &net.UDPAddr{IP: nil, Port: 10001}, "bogus"); err == nil {
		t.Fatal("expected invalid destination error")
	}
	// Writing on a closed socket surfaces the send error.
	_ = conn.Close()
	if err := ubntSendRequest(conn, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001},
		"127.0.0.1"); err == nil {
		t.Fatal("expected send error")
	}
}

func TestRunUbntProbeSortsTwoPeers(t *testing.T) {
	responder, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("responder listen: %v", err)
	}
	defer func() { _ = responder.Close() }()
	port := responder.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 64)
		_, src, err := responder.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Two replies with different MACs exercise the result sort.
		_, _ = responder.WriteToUDP(ubntReply(
			ubntTLV(ubntTLVMAC, ubntTestMAC(0xdc, 0x9f, 0xdb, 0x00, 0x00, 0x02)),
			ubntTLV(ubntTLVModel, []byte("b")),
		), src)
		_, _ = responder.WriteToUDP(ubntReply(
			ubntTLV(ubntTLVMAC, ubntTestMAC(0xdc, 0x9f, 0xdb, 0x00, 0x00, 0x01)),
			ubntTLV(ubntTLVModel, []byte("a")),
		), src)
	}()

	peers, _, err := runUbntProbe(context.Background(), "127.0.0.1", port, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
}

func TestExecuteUbntDiscoveryCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	out := testQueue()
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	executeUbntDiscovery(ctx, &pb.AgentJob{
		JobId:   "u5",
		JobType: pb.JobType_UBNT_DISCOVERY,
		UbntDiscovery: &pb.UbntDiscoveryJob{
			Target:    "127.0.0.1",
			CollectMs: 5000,
		},
	}, out)
	// A cancelled ctx returns without emitting a result.
	select {
	case msg := <-out.items:
		t.Fatalf("unexpected result: %+v", msg)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestRunUbntProbeListenError(t *testing.T) {
	if _, _, err := runUbntProbeOn(context.Background(), "256.256.256.256:0",
		"127.0.0.1", 10001, time.Second); err == nil {
		t.Fatal("expected a listen error")
	}
}

func TestCollectUbntRepliesReadError(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Closing the socket under the reader is a non-timeout read error.
	_ = conn.Close()
	if _, _, err := collectUbntReplies(context.Background(), conn, 500*time.Millisecond); err == nil {
		t.Fatal("expected a read error")
	}
}

// A device name typed in Latin-1 (or any hostile non-UTF-8 bytes) used to
// pass through truncateBytes unchanged, so proto.Marshal rejected the whole
// UbntDiscoveryResult and one reply hid every peer on the segment (issue
// 5160). The text TLVs are sanitized to valid UTF-8 so the result encodes.
func TestParseUbntReplySanitizesNonUTF8(t *testing.T) {
	packet := ubntReply(
		ubntTLV(ubntTLVMAC, ubntTestMAC(0xdc, 0x9f, 0xdb, 0x12, 0x34, 0x56)),
		ubntTLV(ubntTLVHostname, []byte{0x43, 0x61, 0x66, 0xe9}), // "Caf\xe9" in Latin-1
		ubntTLV(ubntTLVModel, []byte{0x4c, 0x48, 0x47, 0xfe}),
		ubntTLV(ubntTLVFirmware, []byte{0x57, 0x41, 0x2e, 0xff}),
	)
	peer, err := parseUbntReply(packet, "192.168.88.20")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !utf8.ValidString(peer.Hostname) || !utf8.ValidString(peer.Model) || !utf8.ValidString(peer.Firmware) {
		t.Fatalf("non-UTF-8 field survived: host=%q model=%q firmware=%q",
			peer.Hostname, peer.Model, peer.Firmware)
	}
	if _, ok := encodeOutbound("ubnt_discovery_result", &pb.UbntDiscoveryResult{
		ProbeId: "u-utf8",
		Peers:   []*pb.UbntDiscoveryPeer{peer},
	}, "u-utf8"); !ok {
		t.Fatal("discovery result with sanitized fields did not encode")
	}
}

// The peer list is bounded: a burst of replies with distinct MACs beyond
// the cap is dropped and reported as truncated, so one result can never
// grow without limit (issue 5160).
func TestCollectUbntRepliesCapsPeers(t *testing.T) {
	orig := ubntMaxPeersPerSweep
	ubntMaxPeersPerSweep = 3
	t.Cleanup(func() { ubntMaxPeersPerSweep = orig })

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = conn.Close() }()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("sender listen: %v", err)
	}
	defer func() { _ = sender.Close() }()
	dst := conn.LocalAddr().(*net.UDPAddr)

	for i := byte(0); i < 5; i++ {
		reply := ubntReply(
			ubntTLV(ubntTLVMAC, ubntTestMAC(0xdc, 0x9f, 0xdb, 0x00, 0x00, i)),
			ubntTLV(ubntTLVModel, []byte("LHG-5nD")),
		)
		if _, err := sender.WriteToUDP(reply, dst); err != nil {
			t.Fatalf("send reply %d: %v", i, err)
		}
	}

	peers, truncated, err := collectUbntReplies(context.Background(), conn, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(peers) > 3 {
		t.Fatalf("cap 3 but collected %d peers", len(peers))
	}
	if !truncated {
		t.Fatal("an over-cap sweep was not reported as truncated")
	}
}
