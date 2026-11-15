// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package loadtest

import (
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

// Scenario is one D6 benchmark run. Defaults model the shared target
// workload: 3,000 devices at a 60 s interval with 300 GET OIDs and 19 walk
// roots per poll plus one ping job per device.
type Scenario struct {
	Name              string
	Devices           int
	DeadSharePercent  int
	LatencyMS         int
	LossPercent       float64
	DropFor           time.Duration
	UplinkBytesPerSec int
	IntervalSeconds   uint32
	Warmup            time.Duration
	Measure           time.Duration
}

// DefaultScenarios returns the five required runs. Warmup lets every wall
// clock phase tick once; Measure spans a second full phase so every job has
// a completed result in the scored window.
func DefaultScenarios() []Scenario {
	const interval = 60 * time.Second
	warmup := interval + 15*time.Second
	measure := interval + 20*time.Second
	return []Scenario{
		{Name: "all_healthy_3000", Devices: 3000, IntervalSeconds: 60, Warmup: warmup, Measure: measure},
		{Name: "dead_20_percent_3000", Devices: 3000, DeadSharePercent: 20, IntervalSeconds: 60, Warmup: warmup, Measure: measure},
		{Name: "snmp_latency_100ms_3000", Devices: 3000, LatencyMS: 100, IntervalSeconds: 60, Warmup: warmup, Measure: measure},
		{Name: "websocket_drop_60s_3000", Devices: 3000, DropFor: 60 * time.Second, IntervalSeconds: 60, Warmup: warmup, Measure: measure},
		{Name: "uplink_1mbps_3000", Devices: 3000, UplinkBytesPerSec: 125_000, IntervalSeconds: 60, Warmup: warmup, Measure: measure},
	}
}

// SimulatorConfig returns the virtual-device fleet for the scenario.
func (s Scenario) SimulatorConfig() SimulatorConfig {
	return SimulatorConfig{
		DeviceCount:      s.Devices,
		Community:        "public",
		DeadSharePercent: s.DeadSharePercent,
		Latency:          time.Duration(s.LatencyMS) * time.Millisecond,
		LossPercent:      s.LossPercent,
		Interfaces:       30,
		WalkRoots:        19,
	}
}

// BuildJobs creates one POLL job and one PING job per virtual device. IDs are
// stable, so the D3 wall-clock phases survive reconnects and inventory
// re-pushes exactly as they do in production.
func BuildJobs(cfg SimulatorConfig, intervalSeconds uint32, ports []int) []*pb.AgentJob {
	if len(ports) < cfg.DeviceCount {
		panic("loadtest: BuildJobs requires one kernel-assigned port per device")
	}
	columns, indexes, _ := GETOIDColumns(cfg.Interfaces)
	walkRoots := WalkRoots(cfg.WalkRoots)
	jobs := make([]*pb.AgentJob, 0, cfg.DeviceCount*2)
	for i := range cfg.DeviceCount {
		deviceID := "sim-" + itoa(i)
		address := DeviceAddress(i)
		port := uint32(ports[i])
		dead := DeadIndex(i, cfg.DeviceCount, cfg.DeadSharePercent)
		device := &pb.SnmpDevice{
			Ip:        address,
			Community: cfg.Community,
			Version:   "2c",
			Port:      port,
			Transport: "udp",
		}

		get := &pb.SnmpQuery{QueryType: pb.QueryType_GET}
		applyQueryColumns(get, columns, indexes)
		poll := &pb.AgentJob{
			JobId:           "poll:sim:" + deviceID,
			JobType:         pb.JobType_POLL,
			DeviceId:        deviceID,
			SnmpDevice:      device,
			Queries:         []*pb.SnmpQuery{get, {QueryType: pb.QueryType_WALK, Oids: walkRoots}},
			IntervalSeconds: intervalSeconds,
			SnmpTimeoutMs:   3000,
			SnmpRetries:     1,
			DeadlineMs:      55_000,
		}
		ping := &pb.AgentJob{
			JobId:           "ping:sim:" + deviceID,
			JobType:         pb.JobType_PING,
			DeviceId:        deviceID,
			SnmpDevice:      device,
			IntervalSeconds: intervalSeconds,
			PingTimeoutMs:   5000,
		}
		jobs = append(jobs, poll)
		if !dead {
			jobs = append(jobs, ping)
		}
	}
	return jobs
}

// applyQueryColumns fills SnmpQuery's compact interface form. The agent
// expands these columns × indexes to the same 300 leaf OIDs the simulator
// serves; legacy jobs carry the expanded list instead.
func applyQueryColumns(query *pb.SnmpQuery, columns []string, indexes []uint32) {
	query.OidColumns = columns
	query.OidIndexes = indexes
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var digits [20]byte
	at := len(digits)
	for v > 0 {
		at--
		digits[at] = byte('0' + v%10)
		v /= 10
	}
	return string(digits[at:])
}
