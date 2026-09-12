// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

var jobScheduleInterval = 60 * time.Second

// jobSchedule retains only recurring polling and monitoring work for the life
// of one authenticated session. Discovery and backup jobs remain one-shot.
type jobSchedule struct {
	jobs   *pb.AgentJobList
	checks *pb.CheckList
}

func (s *jobSchedule) replaceJobs(next *pb.AgentJobList) bool {
	if proto.Equal(s.jobs, next) {
		return false
	}
	s.jobs = next
	return true
}

func (s *jobSchedule) replaceChecks(next *pb.CheckList) bool {
	if proto.Equal(s.checks, next) {
		return false
	}
	s.checks = next
	return true
}

func (s *jobSchedule) dispatch(ctx context.Context, pools *jobPools, out resultQueue) {
	if s.jobs != nil {
		for _, job := range s.jobs.Jobs {
			dispatchJob(ctx, job, pools, out)
		}
	}

	if s.checks != nil {
		for _, check := range s.checks.Checks {
			executeCheck(ctx, check, pools, out)
		}
	}
}
