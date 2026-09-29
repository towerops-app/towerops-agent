// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

// cbTestExport is a RouterOS-looking export good enough for validation.
const cbTestExport = `# 2024-06-01 12:00:00 by RouterOS 7.15.3
# model = RB5009UG+S+
/interface bridge
add name=bridge1
/ip address
add address=10.0.0.1/24 interface=bridge1
`

func cbJob(host string, port uint32) *pb.AgentJob {
	return &pb.AgentJob{
		JobId:    "job-1",
		JobType:  pb.JobType_CONFIG_BACKUP,
		DeviceId: "dev-1",
		ConfigBackup: &pb.ConfigBackupJob{
			Vendor:         "mikrotik",
			Mode:           pb.ConfigBackupMode_CONFIG_BACKUP_MODE_BACKUP,
			Host:           host,
			SshPort:        port,
			Username:       "backup",
			Password:       "secret",
			IncludeSecrets: true,
		},
	}
}

func cbAddrPort(t *testing.T, addr string) (string, uint32) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var portNum uint32
	_, _ = fmt.Sscanf(port, "%d", &portNum)
	return host, portNum
}

// cbRouterHandler answers the vendor's commands with canned RouterOS output.
func cbRouterHandler(export string) func(ch ssh.Channel, command string) {
	return func(ch ssh.Channel, command string) {
		var out string
		switch {
		case strings.Contains(command, "system resource get version"):
			out = "7.15.3 (stable)\n"
		case strings.Contains(command, "system identity get name"):
			out = "test-router\n"
		case strings.Contains(command, "user group get"):
			out = "read,write,ssh\n"
		case strings.HasPrefix(command, "/export"):
			out = export
		default:
			out = "failure: bad command\n"
		}
		_, _ = ch.Write([]byte(out))
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	}
}

func cbReceiveConfigBackupResult(t *testing.T, out *resultQueue) *pb.ConfigBackupResult {
	t.Helper()
	select {
	case queued := <-out.items:
		if queued.event != "config_backup_result" {
			t.Fatalf("event = %q, want config_backup_result", queued.event)
		}
		return decodeQueuedResult[*pb.ConfigBackupResult](t, queued)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for config backup result")
		return nil
	}
}

func cbNewSigner(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestConfigBackupExportCommand(t *testing.T) {
	cases := []struct {
		version string
		secrets bool
		want    string
	}{
		{"7.15.3", true, "/export show-sensitive"},
		{"7.15.3", false, "/export"},
		{"7.1", true, "/export show-sensitive"},
		{"6.49.10", true, "/export"},
		{"6.49.10", false, "/export hide-sensitive"},
		{"6.0", false, "/export hide-sensitive"},
	}
	for _, tc := range cases {
		got := mikrotikExportCommand(routerOSVersionMajor(tc.version), tc.secrets)
		if got != tc.want {
			t.Errorf("export command for %s secrets=%v = %q, want %q", tc.version, tc.secrets, got, tc.want)
		}
	}
}

func TestClassifyConfigBackupError(t *testing.T) {
	job := &pb.AgentJob{ConfigBackup: &pb.ConfigBackupJob{Password: "hunter2"}}
	cases := []struct {
		name     string
		err      error
		wantCode pb.ConfigBackupErrorCode
		wantPart string
	}{
		{"timeout", context.DeadlineExceeded, pb.ConfigBackupErrorCode_TIMEOUT, "deadline"},
		{"auth", errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password]"),
			pb.ConfigBackupErrorCode_AUTH_FAILED, "unable to authenticate"},
		{"refused", &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")},
			pb.ConfigBackupErrorCode_CONNECTION_REFUSED, "refused"},
		{"unreachable", errors.New("dial tcp 10.0.0.1:22: i/o timeout"),
			pb.ConfigBackupErrorCode_UNREACHABLE, "timeout"},
		{"hostkey", fmt.Errorf("%w", errConfigBackupHostKeyMismatch),
			pb.ConfigBackupErrorCode_HOST_KEY_MISMATCH, "host key mismatch"},
		{"internal", errors.New("weird failure"), pb.ConfigBackupErrorCode_INTERNAL, "weird failure"},
	}
	for _, tc := range cases {
		code, detail := classifyConfigBackupError(tc.err, job)
		if code != tc.wantCode {
			t.Errorf("%s: code = %v, want %v", tc.name, code, tc.wantCode)
		}
		if !strings.Contains(detail, tc.wantPart) {
			t.Errorf("%s: detail = %q, want substring %q", tc.name, detail, tc.wantPart)
		}
	}

	code, detail := classifyConfigBackupError(errors.New("auth failed for hunter2 on device"), job)
	if code != pb.ConfigBackupErrorCode_AUTH_FAILED {
		t.Fatalf("code = %v, want AUTH_FAILED", code)
	}
	if strings.Contains(detail, "hunter2") || !strings.Contains(detail, "***") {
		t.Fatalf("password not scrubbed: %q", detail)
	}
}

func TestConfigBackupHostKey(t *testing.T) {
	resetHostKeyStore(t)
	serverSigner := cbNewSigner(t)

	cases := []struct {
		name         string
		expected     string
		wantCode     pb.ConfigBackupErrorCode
		wantObserved bool
	}{
		{"match", ssh.FingerprintSHA256(serverSigner.PublicKey()),
			pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK, true},
		{"mismatch", ssh.FingerprintSHA256(cbNewSigner(t).PublicKey()),
			pb.ConfigBackupErrorCode_HOST_KEY_MISMATCH, true},
		{"first-use", "", pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The single-connection test server must be restarted per case.
			a, c := startTestSSHServerWithSigner(t, serverSigner, cbRouterHandler(cbTestExport))
			defer c()
			h, p := cbAddrPort(t, a)

			job := cbJob(h, p)
			job.ConfigBackup.ExpectedHostKeyFingerprint = tc.expected
			out := testQueue()
			executeConfigBackupJob(context.Background(), job, out)

			result := cbReceiveConfigBackupResult(t, out)
			if result.ErrorCode != tc.wantCode {
				t.Fatalf("code = %v (%q), want %v", result.ErrorCode, result.ErrorDetail, tc.wantCode)
			}
			if tc.wantObserved && result.HostKeyFingerprint != ssh.FingerprintSHA256(serverSigner.PublicKey()) {
				t.Fatalf("fingerprint = %q, want observed server key", result.HostKeyFingerprint)
			}
		})
	}
}

func TestConfigBackupJobSuccess(t *testing.T) {
	resetHostKeyStore(t)
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbRouterHandler(cbTestExport))
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
		t.Fatalf("code = %v, detail = %q", result.ErrorCode, result.ErrorDetail)
	}
	if len(result.ConfigGzip) == 0 {
		t.Fatal("ConfigGzip empty")
	}
	zr, err := gzip.NewReader(bytes.NewReader(result.ConfigGzip))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != cbTestExport {
		t.Fatalf("gunzipped config mismatch: %q", raw)
	}
	if result.ConfigBytes != uint64(len(cbTestExport)) {
		t.Fatalf("ConfigBytes = %d, want %d", result.ConfigBytes, len(cbTestExport))
	}
	if !result.IncludesSecrets {
		t.Error("IncludesSecrets not mirrored")
	}
	if result.OsVersion == "" {
		t.Error("OsVersion empty")
	}
	if result.Model != "RB5009UG+S+" {
		t.Errorf("Model = %q, want RB5009UG+S+", result.Model)
	}
	if result.Identity != "test-router" {
		t.Errorf("Identity = %q", result.Identity)
	}
	if result.DurationMs == 0 && result.Timestamp == 0 {
		t.Error("DurationMs/Timestamp unset")
	}
}

func TestConfigBackupProbe(t *testing.T) {
	resetHostKeyStore(t)
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbRouterHandler(cbTestExport))
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
		t.Fatalf("code = %v, detail = %q", result.ErrorCode, result.ErrorDetail)
	}
	if len(result.ConfigGzip) != 0 {
		t.Error("probe must not export")
	}
	if result.OsVersion != "7.15.3 (stable)" {
		t.Errorf("OsVersion = %q", result.OsVersion)
	}
	if result.Identity != "test-router" {
		t.Errorf("Identity = %q", result.Identity)
	}
	want := []string{"read", "write", "ssh"}
	if strings.Join(result.UserPolicies, ",") != strings.Join(want, ",") {
		t.Errorf("UserPolicies = %v", result.UserPolicies)
	}
}

func TestConfigBackupTooLarge(t *testing.T) {
	resetHostKeyStore(t)
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbRouterHandler(cbTestExport))
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	job.ConfigBackup.MaxConfigBytes = 16
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_TOO_LARGE {
		t.Fatalf("code = %v, want TOO_LARGE", result.ErrorCode)
	}
}

func TestConfigBackupEmptyExport(t *testing.T) {
	resetHostKeyStore(t)
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbRouterHandler(""))
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_EXPORT_EMPTY {
		t.Fatalf("code = %v, want EXPORT_EMPTY", result.ErrorCode)
	}
}

func TestConfigBackupPoolRejection(t *testing.T) {
	// A stopped pool rejects every submission, exercising the AGENT_BUSY path.
	pool := newWorkerPool(1)
	pool.stop()
	ctx := context.Background()

	pools := &jobPools{
		backup:  pool,
		targets: &targetGates{},
		notices: make(chan outbound, 8),
	}
	out := testQueue()

	job := cbJob("192.0.2.1", 22)
	ok := submitJob(ctx, job, pools, out, func() {}, false)

	if ok {
		t.Fatal("submitJob succeeded on saturated pool")
	}
	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_AGENT_BUSY {
		t.Fatalf("code = %v, want AGENT_BUSY", result.ErrorCode)
	}
}

func TestConfigBackupContextCancel(t *testing.T) {
	resetHostKeyStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	job := cbJob("192.0.2.1", 22)
	out := testQueue()
	executeConfigBackupJob(ctx, job, out)

	select {
	case queued := <-out.items:
		t.Fatalf("unexpected result after cancel: %+v", queued)
	case <-time.After(100 * time.Millisecond):
	}
}
