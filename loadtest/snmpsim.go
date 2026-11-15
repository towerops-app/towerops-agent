// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

// Package loadtest contains the D6 load-test infrastructure: a loopback SNMP
// simulator, the stub Phoenix channel server and the benchmark scenario
// definitions. The Go test in the repository root drives a real agent build
// against them.
package loadtest

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BER tags used by the simulator's hand-written encoder. They match the
// gosnmp Asn1BER values on the agent side without importing gosnmp here.
const (
	berInteger     = 0x02
	berOctetString = 0x04
	berNull        = 0x05
	berOID         = 0x06
	berCounter     = 0x41
	berGauge       = 0x42
	berTimeTicks   = 0x43
	berNoSuch      = 0x80
	berEndOfMib    = 0x82
)

// SNMP PDU types (context class, constructed bit set).
const (
	pduGet      = 0xa0
	pduGetNext  = 0xa1
	pduResponse = 0xa2
	pduGetBulk  = 0xa5
)

// v1/v2c error status values used when an exact GET misses the MIB.
const (
	snmpErrNoSuchName = 2
	snmpErrNoSuchObj  = 6
)

// maxReplyBytes keeps every simulated reply under macOS's 9,216-byte UDP
// datagram ceiling (net.inet.udp.maxdgram) with headroom for headers.
const maxReplyBytes = 8900

// SimulatorConfig shapes the virtual-device fleet. Zero values mean "off";
// every field is read by the running devices without locks because the
// harness owns their lifetime.
type SimulatorConfig struct {
	DeviceCount      int
	Community        string
	DeadSharePercent int           // Deterministic first-N devices do not answer.
	Latency          time.Duration // Added to every answered request.
	LossPercent      float64       // Deterministic per-request drop chance.
	// Interfaces controls how many ifTable rows each virtual device serves.
	// The 3,000-device scenario requests 10 columns over 30 rows.
	Interfaces int
	// WalkRoots controls the enterprise subtree roots offered for WALK
	// queries; each root exposes two leaves.
	WalkRoots int
}

// SimulatorStats counts requests at the UDP boundary. A request that is
// dropped by loss or a dead device still increments Requests; Responses
// counts packets actually written.
type SimulatorStats struct {
	Requests   atomic.Uint64
	Responses  atomic.Uint64
	Malformed  atomic.Uint64
	Dropped    atomic.Uint64
	SendErrors atomic.Uint64
}

// Simulator serves one UDP socket per virtual device on loopback. Devices are
// stateless apart from a deterministic pseudo-random sequence, so thousands of
// them cost one goroutine and one socket each and no per-device MIB copy.
type Simulator struct {
	cfg    SimulatorConfig
	stats  SimulatorStats
	conns  []net.PacketConn
	ports  []int
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mib *simMIB
}

// simObject is one OID template shared by every device. Value is generated
// per device so counters look alive without keeping device state.
type simObject struct {
	oid    []uint32
	tag    byte
	column int // -1 for system and enterprise objects
	row    int
}

type simMIB struct {
	objects []simObject // Sorted lexicographically by OID.
	byOID   map[string]int
}

// Start binds every virtual device and starts its read goroutine. A partial
// bind is torn down before the error is returned, so callers never inherit a
// half-populated port range.
func StartSimulator(ctx context.Context, cfg SimulatorConfig) (*Simulator, error) {
	if cfg.DeviceCount <= 0 {
		return nil, errors.New("loadtest: device count must be positive")
	}
	if cfg.Community == "" {
		cfg.Community = "public"
	}
	if cfg.Interfaces <= 0 {
		cfg.Interfaces = 30
	}
	if cfg.WalkRoots <= 0 {
		cfg.WalkRoots = 19
	}

	s := &Simulator{cfg: cfg, mib: buildMIB(cfg.Interfaces, cfg.WalkRoots)}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	for i := range cfg.DeviceCount {
		conn, err := net.ListenPacket("udp", net.JoinHostPort(DeviceAddress(i), "0"))
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("bind virtual device %d on %s:0 after %d devices bound: %w",
				i, DeviceAddress(i), i, err)
		}
		udp := conn.(*net.UDPConn)
		s.conns = append(s.conns, conn)
		s.ports = append(s.ports, udp.LocalAddr().(*net.UDPAddr).Port)
		s.wg.Add(1)
		go s.serveDevice(runCtx, conn, i)
	}
	return s, nil
}

// Close stops every device goroutine and releases the sockets.
func (s *Simulator) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	for _, conn := range s.conns {
		_ = conn.Close()
	}
	s.wg.Wait()
}

// Stats exposes the live counters.
func (s *Simulator) Stats() *SimulatorStats { return &s.stats }

// DeviceAddress returns the loopback address a job must target. Linux routes
// the whole 127/8 block through loopback, which preserves one distinct target
// per virtual device for per-target gates. macOS configures only 127.0.0.1 by
// default, so the harness must fall back to the shared address there.
func DeviceAddress(index int) string {
	if runtime.GOOS == "linux" {
		subnet := index/253 + 1
		host := index%253 + 1
		return fmt.Sprintf("127.%d.%d.1", subnet, host)
	}
	_ = index
	return "127.0.0.1"
}

// DeviceAddress returns the loopback address of one virtual device.
func (s *Simulator) DeviceAddress(index int) string { return DeviceAddress(index) }

// DevicePort returns the kernel-assigned UDP port of one virtual device.
func (s *Simulator) DevicePort(index int) int { return s.ports[index] }

// Ports returns every kernel-assigned virtual-device port in device order.
func (s *Simulator) Ports() []int { return s.ports }

// IsDead reports the deterministic dead-device classification. The first
// DeadSharePercent indexes are dead, which keeps a failed run reproducible.
func (s *Simulator) IsDead(index int) bool {
	return DeadIndex(index, s.cfg.DeviceCount, s.cfg.DeadSharePercent)
}

// DeadIndex is the shared dead-device rule: a power-lost tower answers
// nothing, not its SNMP agent and not ICMP. Both the simulator and the job
// builder use it so dead devices never receive a ping job whose probe the
// loopback kernel would otherwise echo.
func DeadIndex(index, deviceCount, deadSharePercent int) bool {
	return (index*100)/deviceCount < deadSharePercent
}

// serveDevice reads one device's UDP socket. Requests are answered in order:
// the SNMP jobs serialize per device through the agent's target gate, so a
// latency sleep never becomes a concurrency hazard.
func (s *Simulator) serveDevice(ctx context.Context, conn net.PacketConn, index int) {
	defer s.wg.Done()
	rng := rand.New(rand.NewPCG(uint64(index), 0x746f7765726f7073))
	var buf [8192]byte
	for {
		n, from, err := conn.ReadFrom(buf[:])
		if err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
		s.stats.Requests.Add(1)
		if s.IsDead(index) {
			s.stats.Dropped.Add(1)
			continue
		}
		if s.cfg.LossPercent > 0 && rng.Float64()*100 < s.cfg.LossPercent {
			s.stats.Dropped.Add(1)
			continue
		}

		request, err := decodePacket(buf[:n])
		if err != nil || request.pduType != pduGet && request.pduType != pduGetNext && request.pduType != pduGetBulk {
			s.stats.Malformed.Add(1)
			continue
		}
		varbinds := s.answer(request, index)
		reply := encodeResponse(request, varbinds)
		// macOS caps UDP datagrams at 9,216 bytes (net.inet.udp.maxdgram) and
		// fails sendto with EMSGSIZE beyond it. Real devices clamp GETBULK
		// responses the same way when the requested repetitions exceed their
		// own response budget, so the simulator shrink-fits the repetition
		// count until the reply fits rather than dropping the walk mid-poll.
		for len(reply) > maxReplyBytes && request.pduType == pduGetBulk && request.maxRepetitions > 1 {
			request.maxRepetitions /= 2
			varbinds = s.answer(request, index)
			reply = encodeResponse(request, varbinds)
		}
		if s.cfg.Latency > 0 {
			timer := time.NewTimer(s.cfg.Latency)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		if _, err := conn.WriteTo(reply, from); err != nil {
			s.stats.SendErrors.Add(1)
			fmt.Fprintf(os.Stderr, "simulator write failed: device=%d peer=%s reply_bytes=%d err=%v\n",
				index, from, len(reply), err)
			return
		}
		s.stats.Responses.Add(1)
	}
}

// answer builds the response varbinds for one request against one device.
func (s *Simulator) answer(req *snmpRequest, device int) []snmpVarbind {
	mib := s.mib
	varbinds := make([]snmpVarbind, 0, len(req.varbinds))
	switch req.pduType {
	case pduGet:
		for _, vb := range req.varbinds {
			idx, ok := mib.byOID[vb.oid]
			if !ok {
				if req.version == 0 {
					varbinds = append(varbinds, snmpVarbind{oid: vb.oid, tag: berNull})
					if req.errorStatus == 0 {
						req.errorStatus = snmpErrNoSuchName
						req.errorIndex = len(varbinds)
					}
					continue
				}
				varbinds = append(varbinds, snmpVarbind{oid: vb.oid, tag: berNoSuch})
				continue
			}
			varbinds = append(varbinds, mib.value(idx, device))
		}
	case pduGetNext, pduGetBulk:
		nonRepeaters := 0
		repetitions := 1
		if req.pduType == pduGetBulk {
			nonRepeaters = req.nonRepeaters
			repetitions = req.maxRepetitions
			if repetitions < 1 {
				repetitions = 1
			}
		}
		for i, vb := range req.varbinds {
			count := 1
			if i >= nonRepeaters {
				count = repetitions
			}
			current := parseOID(vb.oid)
			for range count {
				next := mib.next(current)
				if next < 0 {
					varbinds = append(varbinds, snmpVarbind{oid: joinOID(current), tag: berEndOfMib})
					break
				}
				obj := mib.value(next, device)
				varbinds = append(varbinds, obj)
				current = mib.objects[next].oid
			}
		}
	}
	return varbinds
}

// buildMIB builds the shared OID table: the system group, a 10-column x
// row interface table, and WalkRoots two-leaf enterprise subtrees. The
// resulting object list is sorted for GetNext/GetBulk traversal.
func buildMIB(rows, walkRoots int) *simMIB {
	mib := &simMIB{}
	add := func(oid []uint32, tag byte, column, row int) {
		mib.objects = append(mib.objects, simObject{oid: oid, tag: tag, column: column, row: row})
	}

	system := []struct {
		oid string
		tag byte
	}{
		{"1.3.6.1.2.1.1.1.0", berOctetString}, // sysDescr
		{"1.3.6.1.2.1.1.2.0", berOID},         // sysObjectID
		{"1.3.6.1.2.1.1.3.0", berTimeTicks},   // sysUpTime
		{"1.3.6.1.2.1.1.5.0", berOctetString}, // sysName
	}
	for _, obj := range system {
		add(parseOID(obj.oid), obj.tag, -1, -1)
	}

	// Ten interface columns chosen from ifTable/ifXTable. Their leaves make
	// up the scenario's 300 GET OIDs (10 columns x rows).
	columns := []struct {
		oid string
		tag byte
	}{
		{"1.3.6.1.2.1.2.2.1.1", berInteger},     // ifIndex
		{"1.3.6.1.2.1.2.2.1.2", berOctetString}, // ifDescr
		{"1.3.6.1.2.1.2.2.1.3", berInteger},     // ifType
		{"1.3.6.1.2.1.2.2.1.7", berInteger},     // ifAdminStatus
		{"1.3.6.1.2.1.2.2.1.8", berInteger},     // ifOperStatus
		{"1.3.6.1.2.1.2.2.1.10", berCounter},    // ifInOctets
		{"1.3.6.1.2.1.2.2.1.16", berCounter},    // ifOutOctets
		{"1.3.6.1.2.1.31.1.1.1.6", berCounter},  // ifHCInOctets
		{"1.3.6.1.2.1.31.1.1.1.10", berCounter}, // ifHCOutOctets
		{"1.3.6.1.2.1.31.1.1.1.15", berGauge},   // ifHighSpeed
	}
	for c, column := range columns {
		base := parseOID(column.oid)
		for row := 1; row <= rows; row++ {
			add(append(append([]uint32(nil), base...), uint32(row)), column.tag, c, row)
		}
	}

	for root := 1; root <= walkRoots; root++ {
		base := []uint32{1, 3, 6, 1, 4, 1, 50000, uint32(root)}
		add(append(append([]uint32(nil), base...), 1), berInteger, -1, -1)
		add(append(append([]uint32(nil), base...), 2), berOctetString, -1, -1)
	}

	// GetNext needs lexicographic order; the insertion order above is not.
	objects := mib.objects
	for i := 1; i < len(objects); i++ {
		for j := i; j > 0 && oidLess(objects[j].oid, objects[j-1].oid); j-- {
			objects[j], objects[j-1] = objects[j-1], objects[j]
		}
	}
	mib.byOID = make(map[string]int, len(objects))
	for i, obj := range objects {
		mib.byOID[joinOID(obj.oid)] = i
	}
	return mib
}

// value renders one MIB object for one device. Counters derive from the
// device index so repeated polls return stable, non-overflowing values.
func (m *simMIB) value(index, device int) snmpVarbind {
	obj := m.objects[index]
	vb := snmpVarbind{oid: joinOID(obj.oid), tag: obj.tag}
	switch obj.tag {
	case berInteger:
		vb.value = int32(1000 + device%900 + obj.row)
	case berOctetString:
		switch {
		case obj.column == 1: // ifDescr
			vb.value = []byte("eth" + strconv.Itoa(obj.row))
		case len(obj.oid) > 7 && obj.oid[7] == 1: // sysDescr
			vb.value = []byte("towerops-load-sim")
		case len(obj.oid) > 7 && obj.oid[7] == 5: // sysName
			vb.value = []byte("sim-" + strconv.Itoa(device))
		default: // enterprise leaf
			vb.value = []byte("leaf-" + joinOID(obj.oid))
		}
	case berOID:
		vb.value = ".1.3.6.1.4.1.50000.1.1"
	case berTimeTicks:
		vb.value = uint32(100_000_000 + device)
	case berCounter:
		vb.value = uint64(1000 + device*17 + obj.column*100 + obj.row)
	case berGauge:
		vb.value = uint32(1_000 + obj.row)
	default:
		vb.tag = berNull
	}
	return vb
}

// next finds the first object strictly greater than oid, or -1 at the end.
func (m *simMIB) next(oid []uint32) int {
	lo, hi := 0, len(m.objects)
	for lo < hi {
		mid := (lo + hi) / 2
		if oidLess(m.objects[mid].oid, oid) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(m.objects) && equalOID(m.objects[lo].oid, oid) {
		lo++
	}
	if lo >= len(m.objects) {
		return -1
	}
	return lo
}

func oidLess(a, b []uint32) bool {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func equalOID(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func parseOID(s string) []uint32 {
	parts := strings.Split(s, ".")
	oid := make([]uint32, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		v, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil
		}
		oid = append(oid, uint32(v))
	}
	return oid
}

func joinOID(oid []uint32) string {
	var b strings.Builder
	for i, v := range oid {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

// GETOIDColumns returns the column bases the scenario polls, and GETOIDs
// expands them over rows into the exact OID list a legacy job carries.
// Splitting them keeps both the new column form and the legacy per-OID form
// on the same virtual devices.
func GETOIDColumns(rows int) (columns []string, indexes []uint32, flat []string) {
	columns = []string{
		"1.3.6.1.2.1.2.2.1.1",
		"1.3.6.1.2.1.2.2.1.2",
		"1.3.6.1.2.1.2.2.1.3",
		"1.3.6.1.2.1.2.2.1.7",
		"1.3.6.1.2.1.2.2.1.8",
		"1.3.6.1.2.1.2.2.1.10",
		"1.3.6.1.2.1.2.2.1.16",
		"1.3.6.1.2.1.31.1.1.1.6",
		"1.3.6.1.2.1.31.1.1.1.10",
		"1.3.6.1.2.1.31.1.1.1.15",
	}
	indexes = make([]uint32, rows)
	for i := range indexes {
		indexes[i] = uint32(i + 1)
	}
	for _, column := range columns {
		for _, index := range indexes {
			flat = append(flat, fmt.Sprintf("%s.%d", column, index))
		}
	}
	return columns, indexes, flat
}

// WalkRoots returns the enterprise roots the scenario walks. They match the
// simulator's enterprise subtrees, each with two leaves, so a walk completes
// in one GETBULK round trip plus the agent's out-of-subtree check.
func WalkRoots(count int) []string {
	roots := make([]string, count)
	for i := range roots {
		roots[i] = fmt.Sprintf("1.3.6.1.4.1.50000.%d", i+1)
	}
	return roots
}

// ScenarioSchedulePhase returns the wall-clock phase a recurring job with
// this stable ID should have ticked last, using the D3 formula
// (t - hash(id)) mod interval == 0. The benchmark compares server arrival
// times against this phase.
func ScenarioSchedulePhase(id string, interval time.Duration, now time.Time) time.Time {
	if interval <= 0 {
		return now
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(id))
	phase := int64(time.Duration(hash.Sum64() % uint64(interval)))
	// The scheduler aligns UnixNano instants; time.Truncate counts from a
	// different zero, so derive the previous planned instant from UnixNano.
	elapsed := now.UnixNano() % int64(interval)
	planned := now.UnixNano() - elapsed + phase
	if planned > now.UnixNano() {
		planned -= int64(interval)
	}
	return time.Unix(0, planned)
}

// snmpRequest mirrors the decoded v1/v2c request fields the simulator needs.
type snmpRequest struct {
	version        int
	community      []byte
	pduType        byte
	requestID      int64
	nonRepeaters   int
	maxRepetitions int
	errorStatus    int
	errorIndex     int
	varbinds       []snmpVarbind
}

type snmpVarbind struct {
	oid   string
	tag   byte
	value any // int32, uint32, uint64, string or []byte
}

// decodePacket parses the outer sequence, version, community and PDU without
// pulling in gosnmp. Anything it cannot fully parse is reported as malformed
// and counted rather than answered.
func decodePacket(data []byte) (*snmpRequest, error) {
	packet, _, err := decodeTLV(data)
	if err != nil || packet.tag != 0x30 {
		return nil, fmt.Errorf("outer sequence: %w", err)
	}
	req := &snmpRequest{}
	version, rest, err := decodeInt(packet.value)
	if err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	req.version = version
	community, rest, err := decodeTLV(rest)
	if err != nil || community.tag != berOctetString {
		return nil, fmt.Errorf("community: %w", err)
	}
	req.community = append([]byte(nil), community.value...)
	pdu, _, err := decodeTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("pdu: %w", err)
	}
	req.pduType = pdu.tag
	body := pdu.value
	requestID, body, err := decodeInt(body)
	if err != nil {
		return nil, fmt.Errorf("request id: %w", err)
	}
	req.requestID = int64(requestID)
	errorStatus, body, err := decodeInt(body)
	if err != nil {
		return nil, fmt.Errorf("error status: %w", err)
	}
	req.errorStatus = errorStatus
	errorIndex, body, err := decodeInt(body)
	if err != nil {
		return nil, fmt.Errorf("error index: %w", err)
	}
	req.errorIndex = errorIndex
	list, _, err := decodeTLV(body)
	if err != nil || list.tag != 0x30 {
		return nil, fmt.Errorf("varbind list: %w", err)
	}
	bindings := list.value
	for len(bindings) > 0 {
		entry, tail, err := decodeTLV(bindings)
		if err != nil || entry.tag != 0x30 {
			return nil, fmt.Errorf("varbind: %w", err)
		}
		bindings = tail
		nameTLV, valueTLV, err := decodePair(entry.value)
		if err != nil {
			return nil, fmt.Errorf("varbind pair: %w", err)
		}
		if nameTLV.tag != berOID {
			return nil, errors.New("varbind name is not an OID")
		}
		oid, err := decodeOIDValue(nameTLV.value)
		if err != nil {
			return nil, fmt.Errorf("varbind OID: %w", err)
		}
		vb := snmpVarbind{oid: oid, tag: valueTLV.tag}
		if valueTLV.tag == berInteger {
			v, _, err := decodeInt(valueTLV.value)
			if err != nil {
				return nil, fmt.Errorf("varbind integer: %w", err)
			}
			vb.value = int32(v)
		}
		req.varbinds = append(req.varbinds, vb)
	}
	if req.pduType == pduGetBulk && len(req.varbinds) > 0 {
		// nonRepeaters/maxRepetitions live in the error-status/error-index
		// fields of a GETBULK PDU.
		req.nonRepeaters = req.errorStatus
		req.maxRepetitions = req.errorIndex
		req.errorStatus = 0
		req.errorIndex = 0
	}
	return req, nil
}

// decodePair splits a varbind sequence into its name and value TLVs.
func decodePair(data []byte) (tlv, tlv, error) {
	name, rest, err := decodeTLV(data)
	if err != nil {
		return tlv{}, tlv{}, err
	}
	value, _, err := decodeTLV(rest)
	return name, value, err
}

type tlv struct {
	tag   byte
	value []byte
}

// decodeTLV reads one definite-length header and its content.
func decodeTLV(data []byte) (tlv, []byte, error) {
	if len(data) < 2 {
		return tlv{}, nil, errors.New("truncated header")
	}
	tag := data[0]
	length := int(data[1])
	header := 2
	if length&0x80 != 0 {
		size := length & 0x7f
		if size == 0 || size > len(data)-2 {
			return tlv{}, nil, errors.New("unsupported long-form length")
		}
		length = 0
		for _, b := range data[2 : 2+size] {
			length = length<<8 | int(b)
		}
		header = 2 + size
	}
	if length > len(data)-header {
		return tlv{}, nil, errors.New("length exceeds packet")
	}
	return tlv{tag: tag, value: data[header : header+length]}, data[header+length:], nil
}

func decodeInt(data []byte) (int, []byte, error) {
	v, rest, err := decodeTLV(data)
	if err != nil || v.tag != berInteger || len(v.value) == 0 || len(v.value) > 8 {
		return 0, rest, errors.New("not an integer")
	}
	var out int64
	for i, b := range v.value {
		if i == 0 {
			out = int64(int8(b))
		} else {
			out = out<<8 | int64(b)
		}
	}
	return int(out), rest, nil
}

// decodeOIDValue decodes the object-identifier content octets, including
// base-128 arcs larger than 127 (the scenario's enterprise roots use them).
func decodeOIDValue(content []byte) (string, error) {
	if len(content) < 1 {
		return "", errors.New("empty OID")
	}
	first := int(content[0])
	parts := make([]string, 0, len(content)+1)
	parts = append(parts, strconv.Itoa(first/40), strconv.Itoa(first%40))
	for at := 1; at < len(content); {
		value := 0
		for {
			b := content[at]
			at++
			if value>>57 != 0 {
				return "", errors.New("OID arc overflow")
			}
			value = value<<7 | int(b&0x7f)
			if b < 0x80 {
				break
			}
			if at >= len(content) {
				return "", errors.New("truncated OID arc")
			}
		}
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, "."), nil
}

// encodeResponse rebuilds a v1/v2c response packet for the request.
func encodeResponse(req *snmpRequest, varbinds []snmpVarbind) []byte {
	body := encodeInt(int(req.requestID))
	body = append(body, encodeInt(req.errorStatus)...)
	body = append(body, encodeInt(req.errorIndex)...)

	var list []byte
	for _, vb := range varbinds {
		entry := encodeOID(vb.oid)
		entry = append(entry, encodeValue(vb)...)
		list = append(list, encodeTLVBytes(0x30, entry)...)
	}
	body = append(body, encodeTLVBytes(0x30, list)...)
	pdu := encodeTLVBytes(pduResponse, body)

	version := encodeInt(req.version)
	community := encodeTLVBytes(berOctetString, req.community)
	outer := append(append(version, community...), pdu...)
	return encodeTLVBytes(0x30, outer)
}

func encodeValue(vb snmpVarbind) []byte {
	switch vb.tag {
	case berInteger:
		switch v := vb.value.(type) {
		case int32:
			return encodeTLVBytes(berInteger, encodeIntContent(int64(v)))
		case int:
			return encodeTLVBytes(berInteger, encodeIntContent(int64(v)))
		}
	case berOctetString:
		switch v := vb.value.(type) {
		case string:
			return encodeTLVBytes(berOctetString, []byte(v))
		case []byte:
			return encodeTLVBytes(berOctetString, v)
		}
	case berOID:
		if v, ok := vb.value.(string); ok {
			return encodeTLVBytes(berOID, encodeOIDContent(parseOID(v)))
		}
	case berTimeTicks:
		if v, ok := vb.value.(uint32); ok {
			return encodeTLVBytes(berTimeTicks, encodeUintContent(uint64(v)))
		}
	case berCounter:
		if v, ok := vb.value.(uint64); ok {
			return encodeTLVBytes(berCounter, encodeUintContent(v))
		}
	case berGauge:
		if v, ok := vb.value.(uint32); ok {
			return encodeTLVBytes(berGauge, encodeUintContent(uint64(v)))
		}
	case berNull, berNoSuch, berEndOfMib:
		return []byte{vb.tag, 0}
	}
	return []byte{berNull, 0}
}

func encodeTLVBytes(tag byte, content []byte) []byte {
	length := len(content)
	if length < 0x80 {
		out := make([]byte, 0, length+2)
		out = append(out, tag, byte(length))
		return append(out, content...)
	}
	size := 0
	for v := length; v > 0; v >>= 8 {
		size++
	}
	out := make([]byte, 0, length+2+size)
	out = append(out, tag, byte(0x80|size))
	for shift := (size - 1) * 8; shift >= 0; shift -= 8 {
		out = append(out, byte(length>>shift))
	}
	return append(out, content...)
}

func encodeInt(v int) []byte {
	return encodeTLVBytes(berInteger, encodeIntContent(int64(v)))
}

func encodeIntContent(v int64) []byte {
	n := 1
	for v < -(1<<(8*n-1)) || v >= 1<<(8*n-1) {
		n++
		if n > 8 {
			n = 8
			break
		}
	}
	out := make([]byte, n)
	for i := range n {
		out[i] = byte(v >> (8 * (n - 1 - i)))
	}
	return out
}

func encodeUintContent(v uint64) []byte {
	n := 1
	for n < 8 && v >= 1<<(8*n) {
		n++
	}
	out := make([]byte, n)
	for i := range n {
		out[i] = byte(v >> (8 * (n - 1 - i)))
	}
	return out
}

// encodeOID turns a dotted OID string into BER content octets.
func encodeOID(oid string) []byte {
	return encodeTLVBytes(berOID, encodeOIDContent(parseOID(oid)))
}

func encodeOIDContent(oid []uint32) []byte {
	if len(oid) < 2 {
		return nil
	}
	out := []byte{byte(oid[0]*40 + oid[1])}
	for _, v := range oid[2:] {
		if v < 0x80 {
			out = append(out, byte(v))
			continue
		}
		var group []byte
		for v > 0 {
			group = append(group, byte(0x80|v&0x7f))
			v >>= 7
		}
		group[0] &= 0x7f
		for i := len(group) - 1; i >= 0; i-- {
			out = append(out, group[i])
		}
	}
	return out
}
