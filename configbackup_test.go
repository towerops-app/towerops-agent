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
	"crypto/sha256"
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
			out = "read;write;ssh;!policy\n"
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
	// A stopped pool rejects every submission. The rejection is reported
	// asynchronously — the coordinator goroutine owns gate acquire and pool
	// submit — so the AGENT_BUSY result is what proves the path ran.
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
	if !submitJob(ctx, job, pools, out, func() {}, false) {
		t.Fatal("submitJob must always accept dispatch; rejection arrives as a result")
	}
	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_AGENT_BUSY {
		t.Fatalf("code = %v, want AGENT_BUSY", result.ErrorCode)
	}

	// The rejection must free the device gate it took before submit, or the
	// device stays blocked for the rest of the session.
	gateCtx, gateCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer gateCancel()
	r := pools.targets.acquire(gateCtx, jobTargetKey(job))
	if r == nil {
		t.Fatal("rejection leaked the device gate")
	}
	r()
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

func TestConfigBackupMissingPayload(t *testing.T) {
	job := cbJob("192.0.2.1", 22)
	job.ConfigBackup = nil
	out := testQueue()

	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_INTERNAL {
		t.Fatalf("code = %v, want INTERNAL", result.ErrorCode)
	}
}

func TestConfigBackupUnsupportedVendor(t *testing.T) {
	resetHostKeyStore(t)
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbRouterHandler(cbTestExport))
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	job.ConfigBackup.Vendor = " Juniper " // case/space-insensitive lookup must still miss
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_UNSUPPORTED_VENDOR {
		t.Fatalf("code = %v, want UNSUPPORTED_VENDOR", result.ErrorCode)
	}
	if result.HostKeyFingerprint == "" {
		t.Error("observed host key fingerprint not reported")
	}
}

func TestConfigBackupDialCancelled(t *testing.T) {
	origDial := sshDial
	defer func() { sshDial = origDial }()
	sshDial = func(ctx context.Context, _, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	job := cbJob("192.0.2.1", 22)
	out := testQueue()
	executeConfigBackupJob(ctx, job, out)

	select {
	case queued := <-out.items:
		t.Fatalf("unexpected result after cancel: %+v", queued)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestConfigBackupDispatchExecutesJob(t *testing.T) {
	// A rejected connection exercises the pooled execute closure end-to-end.
	origJitter := dispatchJitterMax
	dispatchJitterMax = 0
	t.Cleanup(func() { dispatchJitterMax = origJitter })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	host, port := cbAddrPort(t, addr)

	pools := &jobPools{
		backup:  newWorkerPool(1),
		targets: &targetGates{},
		notices: make(chan outbound, 8),
	}
	defer func() { pools.backup.stop() }()
	out := testQueue()

	job := cbJob(host, port)
	if !submitJob(context.Background(), job, pools, out, func() {}, false) {
		t.Fatal("submitJob rejected a fresh pool")
	}

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_CONNECTION_REFUSED {
		t.Fatalf("code = %v (%q), want CONNECTION_REFUSED", result.ErrorCode, result.ErrorDetail)
	}
}

func TestConfigBackupDialDefaultPort(t *testing.T) {
	origDial := sshDial
	defer func() { sshDial = origDial }()
	var capturedAddr string
	sshDial = func(_ context.Context, _, addr string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		capturedAddr = addr
		return nil, errors.New("mock dial")
	}

	job := cbJob("192.0.2.1", 0)
	_, _, err := configBackupDial(context.Background(), job)
	if err == nil {
		t.Fatal("expected dial error")
	}
	if capturedAddr != "192.0.2.1:22" {
		t.Fatalf("addr = %q, want port defaulted to 22", capturedAddr)
	}
}

func TestConfigBackupHostKeyHexFingerprint(t *testing.T) {
	resetHostKeyStore(t)
	serverSigner := cbNewSigner(t)
	hexFP := fmt.Sprintf("%x", sha256.Sum256(serverSigner.PublicKey().Marshal()))

	cases := []struct {
		name     string
		expected string
		wantCode pb.ConfigBackupErrorCode
	}{
		{"hex-match", hexFP, pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK},
		{"hex-mismatch", fmt.Sprintf("%x", sha256.Sum256(cbNewSigner(t).PublicKey().Marshal())),
			pb.ConfigBackupErrorCode_HOST_KEY_MISMATCH},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
		})
	}
}

type cbTimeoutErr struct{}

func (cbTimeoutErr) Error() string   { return "cb timeout" }
func (cbTimeoutErr) Timeout() bool   { return true }
func (cbTimeoutErr) Temporary() bool { return true }

func TestIsUnreachableNetTimeout(t *testing.T) {
	var netErr net.Error = cbTimeoutErr{}
	if !isUnreachable(netErr) {
		t.Error("net.Error timeout should classify as unreachable")
	}
}

func TestFirstLineEdges(t *testing.T) {
	if got := firstLine("first\nsecond", maxConfigBackupDetailLen); got != "first" {
		t.Errorf("firstLine multi-line = %q", got)
	}
	long := strings.Repeat("x", maxConfigBackupDetailLen+50)
	if got := firstLine(long, maxConfigBackupDetailLen); len(got) != maxConfigBackupDetailLen {
		t.Errorf("firstLine truncation len = %d", len(got))
	}
}

func TestSessionErrCode(t *testing.T) {
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if got := sessionErrCode(deadline); got != pb.ConfigBackupErrorCode_TIMEOUT {
		t.Errorf("deadline ctx = %v, want TIMEOUT", got)
	}
	if got := sessionErrCode(context.Background()); got != pb.ConfigBackupErrorCode_EXPORT_FAILED {
		t.Errorf("live ctx = %v, want EXPORT_FAILED", got)
	}
}

func TestRunConfigBackupSessionClosedClient(t *testing.T) {
	resetHostKeyStore(t)
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbRouterHandler(cbTestExport))
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	client, _, err := configBackupDial(context.Background(), job)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = client.Close()

	v := mikrotikBackupVendor{}
	if _, err := v.readVersion(client); err == nil {
		t.Error("readVersion on closed client should fail")
	}
	if _, err := v.readIdentity(client); err == nil {
		t.Error("readIdentity on closed client should fail")
	}
}

// cbFailOnHandler serves RouterOS replies but fails the command containing
// failOn with a non-zero exit status and no output.
func cbFailOnHandler(failOn string) func(ch ssh.Channel, command string) {
	return func(ch ssh.Channel, command string) {
		if strings.Contains(command, failOn) {
			_ = ch.CloseWrite()
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
			_ = ch.Close()
			return
		}
		cbRouterHandler(cbTestExport)(ch, command)
	}
}

func TestConfigBackupProbeSessionFailures(t *testing.T) {
	cases := []struct {
		name   string
		failOn string
	}{
		{"version", "system resource get version"},
		{"identity", "system identity get name"},
		{"policy", "user group get"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetHostKeyStore(t)
			addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbFailOnHandler(tc.failOn))
			defer cleanup()
			host, port := cbAddrPort(t, addr)

			job := cbJob(host, port)
			job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
			out := testQueue()
			executeConfigBackupJob(context.Background(), job, out)

			result := cbReceiveConfigBackupResult(t, out)
			if result.ErrorCode != pb.ConfigBackupErrorCode_EXPORT_FAILED {
				t.Fatalf("code = %v (%q), want EXPORT_FAILED", result.ErrorCode, result.ErrorDetail)
			}
		})
	}
}

func TestConfigBackupBackupVersionFails(t *testing.T) {
	resetHostKeyStore(t)
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbFailOnHandler("system resource get version"))
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_EXPORT_FAILED {
		t.Fatalf("code = %v (%q), want EXPORT_FAILED", result.ErrorCode, result.ErrorDetail)
	}
}

func TestConfigBackupUnparseableVersion(t *testing.T) {
	resetHostKeyStore(t)
	handler := func(ch ssh.Channel, command string) {
		if strings.Contains(command, "system resource get version") {
			_, _ = ch.Write([]byte("unknown\n"))
			_ = ch.CloseWrite()
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			_ = ch.Close()
			return
		}
		cbRouterHandler(cbTestExport)(ch, command)
	}
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), handler)
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
		t.Fatalf("code = %v (%q)", result.ErrorCode, result.ErrorDetail)
	}
	if result.OsVersion != "unknown" {
		t.Errorf("OsVersion = %q, want unknown", result.OsVersion)
	}
}

// cbExportExitHandler serves a fixed export reply with a fixed exit status.
func cbExportExitHandler(reply string, status uint32) func(ch ssh.Channel, command string) {
	return func(ch ssh.Channel, command string) {
		if strings.HasPrefix(command, "/export") {
			if reply != "" {
				_, _ = ch.Write([]byte(reply))
			}
			_ = ch.CloseWrite()
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			_ = ch.Close()
			return
		}
		cbRouterHandler(cbTestExport)(ch, command)
	}
}

func TestConfigBackupExportFailures(t *testing.T) {
	cases := []struct {
		name     string
		reply    string
		status   uint32
		wantCode pb.ConfigBackupErrorCode
	}{
		{"exit with valid-looking output", cbTestExport, 1, pb.ConfigBackupErrorCode_EXPORT_FAILED},
		{"exit with empty output", "", 1, pb.ConfigBackupErrorCode_EXPORT_EMPTY},
		{"exit with failure text", "failure: no such command\n", 1, pb.ConfigBackupErrorCode_EXPORT_FAILED},
		{"permission denied", "no permission\n", 0, pb.ConfigBackupErrorCode_PERMISSION_DENIED},
		{"incomplete", "just some words\n", 0, pb.ConfigBackupErrorCode_EXPORT_INCOMPLETE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetHostKeyStore(t)
			addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExportExitHandler(tc.reply, tc.status))
			defer cleanup()
			host, port := cbAddrPort(t, addr)

			job := cbJob(host, port)
			out := testQueue()
			executeConfigBackupJob(context.Background(), job, out)

			result := cbReceiveConfigBackupResult(t, out)
			if result.ErrorCode != tc.wantCode {
				t.Fatalf("code = %v (%q), want %v", result.ErrorCode, result.ErrorDetail, tc.wantCode)
			}
		})
	}
}

func TestParseExportModelVariants(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   string
	}{
		{"no model", "/interface bridge\nadd name=bridge1\n", ""},
		{"comment without equals", "# no key value\n/interface\n", ""},
		{"other key", "# date = today\n/interface\n", ""},
		{"model", "# model = hEX\n/interface\n", "hEX"},
	}
	for _, tc := range cases {
		if got := parseExportModel(tc.output); got != tc.want {
			t.Errorf("%s: parseExportModel = %q, want %q", tc.name, got, tc.want)
		}
	}
}

type cbErrWriter struct{}

func (cbErrWriter) Write([]byte) (int, error) { return 0, errors.New("write boom") }

// cbFailAfterWriter accepts the first `remaining` bytes so the gzip header
// lands, then fails — surfacing the error on Close rather than Write.
type cbFailAfterWriter struct{ remaining int }

func (w *cbFailAfterWriter) Write(p []byte) (int, error) {
	if w.remaining >= len(p) {
		w.remaining -= len(p)
		return len(p), nil
	}
	w.remaining = 0
	return 0, errors.New("close boom")
}

func TestGzipToErrors(t *testing.T) {
	if err := gzipTo(cbErrWriter{}, []byte("data")); err == nil {
		t.Error("write failure should surface")
	}
	if err := gzipTo(&cbFailAfterWriter{remaining: 10}, []byte("payload")); err == nil {
		t.Error("close failure should surface")
	}
	var buf bytes.Buffer
	if err := gzipTo(&buf, []byte("ok")); err != nil {
		t.Fatalf("gzipTo failed: %v", err)
	}
}

func TestConfigBackupGzipFailure(t *testing.T) {
	resetHostKeyStore(t)
	orig := gzipTo
	defer func() { gzipTo = orig }()
	gzipTo = func(io.Writer, []byte) error { return errors.New("gzip boom") }

	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbRouterHandler(cbTestExport))
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_INTERNAL {
		t.Fatalf("code = %v (%q), want INTERNAL", result.ErrorCode, result.ErrorDetail)
	}
	if !strings.Contains(result.ErrorDetail, "gzip boom") {
		t.Errorf("detail = %q, want gzip boom", result.ErrorDetail)
	}
}

func TestConfigBackupCancelDuringSession(t *testing.T) {
	resetHostKeyStore(t)
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	// The handler holds the session channel open until release closes, so the
	// probe can only finish after the cancel lands and the job context's
	// AfterFunc has closed the SSH client — no result can race sendResult.
	handler := func(ch ssh.Channel, _ string) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	}
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), handler)
	defer cleanup()
	defer close(release)
	host, port := cbAddrPort(t, addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jobDone := make(chan struct{})
	job := cbJob(host, port)
	job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
	out := testQueue()

	go func() {
		defer close(jobDone)
		executeConfigBackupJob(ctx, job, out)
	}()

	// Cancel once the first session channel opens — that is the moment the
	// job is provably mid-probe. If the job exits first, the cancel arrived
	// too early or the session never opened, and the test has nothing to say.
	select {
	case <-started:
		cancel()
	case <-jobDone:
		t.Fatal("job ended before the SSH session opened")
	case <-time.After(5 * time.Second):
		t.Fatal("no session channel opened; probe never reached the handler")
	}

	select {
	case <-jobDone:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled job did not unwind")
	}

	select {
	case queued := <-out.items:
		t.Fatalf("unexpected result after session cancel: %+v", queued)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestConfigBackupJobTimeoutDuringSession(t *testing.T) {
	resetHostKeyStore(t)
	release := make(chan struct{})
	handler := func(ch ssh.Channel, _ string) {
		<-release
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	}
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), handler)
	defer cleanup()
	defer close(release)
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	job.ConfigBackup.TimeoutMs = 200
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_TIMEOUT {
		t.Fatalf("code = %v (%q), want TIMEOUT", result.ErrorCode, result.ErrorDetail)
	}
}

func TestConfigBackupGateWaitReportsTimeout(t *testing.T) {
	// A job parked on the per-target gate must still honor its deadline: the
	// server sweeps dispatches that never answer, so waiting silently is a
	// lost job. Hold the device's gate and submit with a short timeout.
	resetHostKeyStore(t)
	origJitter := dispatchJitterMax
	dispatchJitterMax = 0
	t.Cleanup(func() { dispatchJitterMax = origJitter })
	origDial := sshDial
	sshDial = func(context.Context, string, string, *ssh.ClientConfig) (*ssh.Client, error) {
		t.Error("dial attempted while the device gate was held")
		return nil, errors.New("should not dial")
	}
	t.Cleanup(func() { sshDial = origDial })

	pools := &jobPools{
		backup:  newWorkerPool(1),
		targets: &targetGates{},
		notices: make(chan outbound, 8),
	}
	defer func() { pools.backup.stop() }()

	job := cbJob("192.0.2.1", 22)
	job.ConfigBackup.TimeoutMs = 150
	defer pools.targets.acquire(context.Background(), jobTargetKey(job))()

	out := testQueue()
	if !submitJob(context.Background(), job, pools, out, func() {}, false) {
		t.Fatal("submitJob rejected a fresh pool")
	}

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_TIMEOUT {
		t.Fatalf("code = %v (%q), want TIMEOUT", result.ErrorCode, result.ErrorDetail)
	}
	if result.ErrorDetail != "job deadline expired waiting for the device" {
		t.Fatalf("detail = %q, want the gate-wait message", result.ErrorDetail)
	}
}

func TestConfigBackupGateWaitSessionCancel(t *testing.T) {
	// A session that ends while a job waits on the device gate reports
	// nothing — the channel that would carry the result is gone.
	resetHostKeyStore(t)
	origJitter := dispatchJitterMax
	dispatchJitterMax = 0
	t.Cleanup(func() { dispatchJitterMax = origJitter })

	pools := &jobPools{
		backup:  newWorkerPool(1),
		targets: &targetGates{},
		notices: make(chan outbound, 8),
	}
	defer func() { pools.backup.stop() }()

	job := cbJob("192.0.2.1", 22)
	defer pools.targets.acquire(context.Background(), jobTargetKey(job))()

	session, endSession := context.WithCancel(context.Background())
	out := testQueue()
	done := make(chan struct{})
	if !submitJob(session, job, pools, out, func() { close(done) }, false) {
		t.Fatal("submitJob rejected a fresh pool")
	}
	endSession()

	select {
	case <-done:
		// The coordinator observed the cancel and unwound; nothing after this
		// point can race the cleanup that restores dispatchJitterMax.
	case <-time.After(2 * time.Second):
		t.Fatal("coordinator never unwound after session cancel")
	}
	select {
	case queued := <-out.items:
		t.Fatalf("unexpected result after session cancel: %+v", queued)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestConfigBackupDialClassification(t *testing.T) {
	origDial := sshDial
	defer func() { sshDial = origDial }()

	t.Run("tcp connect timeout reports unreachable", func(t *testing.T) {
		sshDial = func(context.Context, string, string, *ssh.ClientConfig) (*ssh.Client, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
		}
		job := cbJob("192.0.2.1", 22)
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_UNREACHABLE {
			t.Fatalf("code = %v (%q), want UNREACHABLE", result.ErrorCode, result.ErrorDetail)
		}
	})

	t.Run("handshake stalled past dial budget reports timeout", func(t *testing.T) {
		origTimeout := configBackupDialTimeout
		configBackupDialTimeout = 50 * time.Millisecond
		defer func() { configBackupDialTimeout = origTimeout }()

		// The handshake outlives dialCtx; its conn close surfaces as a
		// handshake error that must not classify as AUTH_FAILED.
		sshDial = func(ctx context.Context, _, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
			<-ctx.Done()
			return nil, errors.New("ssh: handshake failed: read tcp: use of closed network connection")
		}
		job := cbJob("192.0.2.1", 22)
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_TIMEOUT {
			t.Fatalf("code = %v (%q), want TIMEOUT", result.ErrorCode, result.ErrorDetail)
		}
	})
}

func TestConfigBackupResultUsesReservedLane(t *testing.T) {
	if !usesReservedLane(&pb.ConfigBackupResult{}) {
		t.Fatal("backup result should qualify for the reserved spool lane")
	}
	if usesReservedLane(&pb.SnmpResult{JobType: pb.JobType_POLL}) {
		t.Fatal("poll result must not use the reserved lane")
	}
}
