// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

func TestExecuteSnmpJob_GETFailureAttribution(t *testing.T) {
	oids := []string{
		".1.3.6.1.2.1.1.1.0",
		".1.3.6.1.2.1.1.2.0",
		".1.3.6.1.2.1.1.3.0",
		".1.3.6.1.2.1.1.4.0",
	}
	timeout := errors.New("request timeout")
	tests := []struct {
		name       string
		oids       []string
		get        func([]string) (*gosnmp.SnmpPacket, error)
		failed     []string
		excluded   []string
		wantValues map[string]string
		cause      string
	}{
		{
			name: "transport timeout",
			oids: oids[:2],
			get: func([]string) (*gosnmp.SnmpPacket, error) {
				return nil, timeout
			},
			failed: oids[:2], cause: timeout.Error(),
		},
		{
			name: "error status discards echoed values",
			oids: oids[:2],
			get: func(batch []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{
					Error: gosnmp.GenErr, ErrorIndex: 1,
					Variables: []gosnmp.SnmpPDU{{Name: batch[0], Type: gosnmp.OctetString, Value: []byte("unlogged-payload-value")}},
				}, nil
			},
			failed: oids[:2], cause: fmt.Sprint(gosnmp.GenErr),
		},
		{
			name: "oversized singleton",
			oids: oids[:1],
			get: func([]string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{Error: gosnmp.TooBig}, nil
			},
			failed: oids[:1], cause: fmt.Sprint(gosnmp.TooBig),
		},
		{
			name: "failed split excludes successful sibling",
			oids: oids,
			get: func(batch []string) (*gosnmp.SnmpPacket, error) {
				if len(batch) > 2 {
					return &gosnmp.SnmpPacket{Error: gosnmp.TooBig}, nil
				}
				if batch[0] == oids[2] {
					return nil, timeout
				}
				return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
					{Name: batch[0], Type: gosnmp.Integer, Value: 41},
					{Name: batch[1], Type: gosnmp.Integer, Value: 42},
				}}, nil
			},
			failed: oids[2:], excluded: oids[:2], cause: timeout.Error(),
			wantValues: map[string]string{canonicalOID(oids[0]): "41", canonicalOID(oids[1]): "42"},
		},
		{
			name: "both failed splits remain attributable",
			oids: oids,
			get: func(batch []string) (*gosnmp.SnmpPacket, error) {
				if len(batch) > 2 {
					return &gosnmp.SnmpPacket{Error: gosnmp.TooBig}, nil
				}
				return nil, timeout
			},
			failed: oids, cause: timeout.Error(),
		},
		{
			name: "indexed recovery excludes absent instance",
			oids: oids,
			get: func(batch []string) (*gosnmp.SnmpPacket, error) {
				if len(batch) == len(oids) {
					return &gosnmp.SnmpPacket{Error: gosnmp.NoSuchName, ErrorIndex: 2}, nil
				}
				return nil, timeout
			},
			failed: []string{oids[0], oids[2], oids[3]}, excluded: oids[1:2], cause: timeout.Error(),
			wantValues: map[string]string{canonicalOID(oids[1]): ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := snmpAttributionJob()
			job.Queries = []*pb.SnmpQuery{{QueryType: pb.QueryType_GET, Oids: tt.oids}}
			result, notice, logs := runSnmpAttributionJob(t, job, &mockSnmpQuerier{getFunc: tt.get})
			if len(result.OidValues) != len(tt.wantValues) {
				t.Fatalf("values = %v, want %v", result.OidValues, tt.wantValues)
			}
			for oid, want := range tt.wantValues {
				if got, exists := result.OidValues[oid]; !exists || got != want {
					t.Errorf("value for %s = %q/%t, want %q", oid, got, exists, want)
				}
			}
			if len(result.CompletedRoots) != 0 {
				t.Errorf("GET failure invented completed roots: %v", result.CompletedRoots)
			}
			if !strings.Contains(notice.Message, tt.cause) {
				t.Errorf("error %q lost cause %q", notice.Message, tt.cause)
			}
			record := assertSnmpFailureAttribution(t, job, notice, logs, "GET", tt.failed, tt.excluded)
			assertSnmpDiagnosticDuration(t, record.Error)
		})
	}
}

func TestExecuteSnmpJob_GETFailureSummarySurvivesStatusLimit(t *testing.T) {
	oids := make([]string, snmpMaxOIDsPerGet)
	for i := range oids {
		oids[i] = fmt.Sprintf(".1.3.6.1.4.1.41112.1.4.7.1.2.%d", i+1)
	}
	job := snmpAttributionJob()
	job.Queries = []*pb.SnmpQuery{{QueryType: pb.QueryType_GET, Oids: oids}}
	_, notice, logs := runSnmpAttributionJob(t, job, &mockSnmpQuerier{
		getFunc: func([]string) (*gosnmp.SnmpPacket, error) {
			return nil, errors.New("request timeout")
		},
	})
	assertSnmpFailureAttribution(t, job, notice, logs, "GET", oids, nil)
	// The server's device status retains only the first 500 characters.
	statusRunes := []rune(notice.Message)
	status := string(statusRunes[:min(500, len(statusRunes))])
	assertSnmpDiagnosticDuration(t, status)
	for _, identity := range []string{"GET", canonicalOID(oids[0]), canonicalOID(oids[len(oids)-1])} {
		if !strings.Contains(status, identity) {
			t.Errorf("bounded status lost request identity %q: %q", identity, status)
		}
	}
}

func TestExecuteSnmpJob_WalkFailureAttribution(t *testing.T) {
	const root = "1.3.6.1.2.1.2"
	for _, version := range []string{"1", "2c"} {
		t.Run(version, func(t *testing.T) {
			job := snmpAttributionJob()
			job.SnmpDevice.Version = version
			job.Queries = []*pb.SnmpQuery{
				{QueryType: pb.QueryType_GET, Oids: []string{"." + oidSysName}},
				{QueryType: pb.QueryType_WALK, Oids: []string{"." + root}},
			}
			mock := &mockSnmpQuerier{
				getFunc: func([]string) (*gosnmp.SnmpPacket, error) {
					return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{{
						Name: "." + oidSysName, Type: gosnmp.OctetString, Value: []byte("retained-scalar"),
					}}}, nil
				},
				walkFunc: func(string) ([]gosnmp.SnmpPDU, error) {
					return []gosnmp.SnmpPDU{{Name: "." + root + ".1", Type: gosnmp.Integer, Value: 7}}, errors.New("walk timeout")
				},
			}
			result, notice, logs := runSnmpAttributionJob(t, job, mock)
			want := map[string]string{oidSysName: "retained-scalar", root + ".1": "7"}
			if !reflect.DeepEqual(result.OidValues, want) {
				t.Errorf("failed walk lost useful values: got %v, want %v", result.OidValues, want)
			}
			if len(result.CompletedRoots) != 0 {
				t.Errorf("failed walk claimed completed roots: %v", result.CompletedRoots)
			}
			if mock.walkAllCalled != (version == "1") || mock.bulkWalkCalled != (version != "1") {
				t.Errorf("walk selection changed: walk=%t bulk=%t version=%s", mock.walkAllCalled, mock.bulkWalkCalled, version)
			}
			record := assertSnmpFailureAttribution(t, job, notice, logs, "WALK", []string{root}, nil)
			if record.Root != root || record.Elapsed <= 0 {
				t.Errorf("walk diagnostic root/duration = %q/%s", record.Root, record.Elapsed)
			}
			if !strings.Contains(notice.Message, "walk timeout") {
				t.Errorf("walk error lost cause: %q", notice.Message)
			}
		})
	}
}

func snmpAttributionJob() *pb.AgentJob {
	return &pb.AgentJob{
		JobId: "attributed-job", DeviceId: "attributed-device", JobType: pb.JobType_POLL,
		SnmpDevice: &pb.SnmpDevice{
			Ip: "192.0.2.44", Version: "1", Community: "secret-community-marker",
			V3Username: "secret-user-marker", V3AuthPassword: "secret-auth-marker", V3PrivPassword: "secret-privacy-marker",
		},
	}
}

func runSnmpAttributionJob(t *testing.T, job *pb.AgentJob, mock *mockSnmpQuerier) (*pb.SnmpResult, *pb.AgentError, string) {
	t.Helper()
	originalDial := snmpDial
	originalLogger := slog.Default()
	originalWriter, originalFlags := log.Writer(), log.Flags()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		return mock, func() {}, nil
	}
	t.Cleanup(func() {
		snmpDial = originalDial
		slog.SetDefault(originalLogger)
		log.SetOutput(originalWriter)
		log.SetFlags(originalFlags)
	})
	out := testQueue()
	executeSnmpJob(context.Background(), job, out)
	result := wantResult[*pb.SnmpResult](t, out, "result", time.Second)
	notice := wantResult[*pb.AgentError](t, out, "error", time.Second)
	return result, notice, logs.String()
}

type snmpFailureLog struct {
	Operation string        `json:"operation"`
	JobID     string        `json:"job_id"`
	Device    string        `json:"device"`
	Root      string        `json:"root"`
	Elapsed   time.Duration `json:"elapsed"`
	Error     string        `json:"error"`
}

func assertSnmpFailureAttribution(t *testing.T, job *pb.AgentJob, notice *pb.AgentError, logs, operation string, failed, excluded []string) snmpFailureLog {
	t.Helper()
	if notice.JobId != job.JobId || notice.DeviceId != job.DeviceId {
		t.Errorf("notice routed to %s/%s, want %s/%s", notice.JobId, notice.DeviceId, job.JobId, job.DeviceId)
	}
	if !strings.Contains(notice.Message, operation) {
		t.Errorf("error %q lost operation %s", notice.Message, operation)
	}
	assertSnmpDiagnosticDuration(t, notice.Message)
	for _, secret := range []string{job.SnmpDevice.Community, job.SnmpDevice.V3Username, job.SnmpDevice.V3AuthPassword, job.SnmpDevice.V3PrivPassword, "unlogged-payload-value", "retained-scalar"} {
		if strings.Contains(logs, secret) || strings.Contains(notice.Message, secret) {
			t.Errorf("failure diagnostics exposed credential or value %q", secret)
		}
	}
	var failure snmpFailureLog
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var record snmpFailureLog
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode structured log: %v", err)
		}
		if record.Operation == operation && record.Error != "" {
			failure = record
		}
	}
	if failure.JobID != job.JobId || failure.Device != job.SnmpDevice.Ip {
		t.Errorf("failure log lacks job/device context: %+v", failure)
	}
	for _, oid := range failed {
		canonical := canonicalOID(oid)
		for _, diagnostic := range []string{notice.Message, failure.Root + " " + failure.Error} {
			if !strings.Contains(diagnostic, canonical) || strings.Contains(diagnostic, "."+canonical) {
				t.Errorf("diagnostic %q lacks canonical failed identity %s", diagnostic, canonical)
			}
		}
	}
	for _, oid := range excluded {
		if strings.Contains(notice.Message, canonicalOID(oid)) || strings.Contains(failure.Error, canonicalOID(oid)) {
			t.Errorf("successful/absent OID %s attributed to failure: %q / %q", oid, notice.Message, failure.Error)
		}
	}
	return failure
}

func assertSnmpDiagnosticDuration(t *testing.T, diagnostic string) {
	t.Helper()
	matches := regexp.MustCompile(`[0-9]+(?:\.[0-9]+)?(?:ns|µs|ms|s)`).FindAllString(diagnostic, -1)
	for _, match := range matches {
		if elapsed, err := time.ParseDuration(match); err == nil && elapsed >= 0 {
			return
		}
	}
	t.Errorf("diagnostic has no valid elapsed request duration: %q", diagnostic)
}
