// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

func TestJobScheduleDeduplicatesServerRefreshAndRunsOnTick(t *testing.T) {
	origDial := snmpDial
	defer func() { snmpDial = origDial }()

	snmpDial = func(_ context.Context, _ *pb.SnmpDevice) (snmpQuerier, func(), error) {
		return &mockSnmpQuerier{
			getFunc: func(_ []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{}, nil
			},
		}, func() {}, nil
	}

	ctx := context.Background()
	pools := testPools(t)
	out := testQueue()
	schedule := &jobSchedule{}
	msg := channelMsg{
		Topic: "agent:test",
		Event: "jobs",
		Payload: makeJobPayload(&pb.AgentJob{
			JobId:      "poll-1",
			JobType:    pb.JobType_POLL,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		}),
	}

	_, _ = handleScheduledMessage(ctx, msg, "agent:test", pools, out, schedule)
	_ = wantResult[*pb.SnmpResult](t, out, "result", time.Second)

	_, _ = handleScheduledMessage(ctx, msg, "agent:test", pools, out, schedule)
	select {
	case result := <-out:
		t.Fatalf("unchanged server refresh dispatched an extra %q", result.event)
	case <-time.After(25 * time.Millisecond):
	}

	schedule.dispatch(ctx, pools, out)
	_ = wantResult[*pb.SnmpResult](t, out, "result", time.Second)

}

func TestJobScheduleDoesNotRetainOneShotJobs(t *testing.T) {
	origDial := snmpDial
	defer func() { snmpDial = origDial }()

	snmpDial = func(_ context.Context, _ *pb.SnmpDevice) (snmpQuerier, func(), error) {
		return &mockSnmpQuerier{
			getFunc: func(_ []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{}, nil
			},
		}, func() {}, nil
	}

	ctx := context.Background()
	pools := testPools(t)
	out := testQueue()
	schedule := &jobSchedule{}
	msg := channelMsg{
		Topic: "agent:test",
		Event: "discovery_job",
		Payload: makeJobPayload(&pb.AgentJob{
			JobId:      "discovery-1",
			JobType:    pb.JobType_DISCOVER,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		}),
	}

	_, _ = handleScheduledMessage(ctx, msg, "agent:test", pools, out, schedule)
	_ = wantResult[*pb.SnmpResult](t, out, "result", time.Second)

	schedule.dispatch(ctx, pools, out)
	select {
	case result := <-out:
		t.Fatalf("one-shot job was retained as %q", result.event)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestJobScheduleClearsRemovedJobs(t *testing.T) {
	schedule := &jobSchedule{}
	if !schedule.replaceJobs(&pb.AgentJobList{Jobs: []*pb.AgentJob{{JobId: "poll-1"}}}) {
		t.Fatal("initial jobs were not accepted")
	}
	if !schedule.replaceJobs(&pb.AgentJobList{}) {
		t.Fatal("empty replacement did not clear jobs")
	}
	if len(schedule.jobs.Jobs) != 0 {
		t.Fatalf("scheduled jobs = %d, want 0", len(schedule.jobs.Jobs))
	}
}
