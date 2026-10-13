// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
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
		{"handshake EOF", errors.New("ssh: handshake failed: EOF"),
			pb.ConfigBackupErrorCode_INTERNAL, "handshake failed"},
		{"no common algorithm", errors.New("ssh: handshake failed: ssh: no common algorithm for key exchange"),
			pb.ConfigBackupErrorCode_INTERNAL, "no common algorithm"},
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

func TestConfigBackupErrorsRedactBeforeShortening(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		detail   string
		want     string
	}{
		{
			name:     "password crosses detail limit",
			password: "secret-password",
			detail:   strings.Repeat("x", maxConfigBackupDetailLen-3) + "secret-password",
			want:     strings.Repeat("x", maxConfigBackupDetailLen-3) + "***",
		},
		{
			name:     "password contains newline",
			password: "secret\npassword",
			detail:   "connection failed: secret\npassword\nextra detail",
			want:     "connection failed: ***",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := cbJob("192.0.2.1", 22)
			job.ConfigBackup.Password = tc.password
			t.Run("classified dial error", func(t *testing.T) {
				_, detail := classifyConfigBackupError(errors.New(tc.detail), job)
				if detail != tc.want {
					t.Fatalf("detail = %q, want %q", detail, tc.want)
				}
			})
			t.Run("vendor error", func(t *testing.T) {
				result := configBackupError(job.ConfigBackup, job.JobId, job.DeviceId, pb.ConfigBackupErrorCode_INTERNAL, tc.detail)
				if result.ErrorDetail != tc.want {
					t.Fatalf("detail = %q, want %q", result.ErrorDetail, tc.want)
				}
			})
		})
	}
}

func TestConfigBackupErrorDetailsPreserveUTF8(t *testing.T) {
	job := cbJob("192.0.2.1", 22)
	detail := strings.Repeat("x", maxConfigBackupDetailLen-1) + "é"
	code, message := classifyConfigBackupError(errors.New(detail), job)
	for _, tc := range []struct {
		name   string
		result *pb.ConfigBackupResult
	}{
		{
			name:   "classified dial error",
			result: &pb.ConfigBackupResult{ErrorCode: code, ErrorDetail: message},
		},
		{
			name:   "vendor error",
			result: configBackupError(job.ConfigBackup, job.JobId, job.DeviceId, pb.ConfigBackupErrorCode_INTERNAL, detail),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !utf8.ValidString(tc.result.ErrorDetail) {
				t.Errorf("detail contains an incomplete UTF-8 character: %q", tc.result.ErrorDetail)
			}
			if len(tc.result.ErrorDetail) > maxConfigBackupDetailLen {
				t.Errorf("detail length = %d, exceeds byte limit %d", len(tc.result.ErrorDetail), maxConfigBackupDetailLen)
			}
			if _, err := proto.Marshal(tc.result); err != nil {
				t.Errorf("marshal config backup error result: %v", err)
			}
		})
	}
}

type cbCloseRecordingConn struct {
	ssh.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *cbCloseRecordingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestConfigBackupSessionCanceledAfterDialClosesClient(t *testing.T) {
	sessionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &cbCloseRecordingConn{closed: make(chan struct{}, 1)}
	origDial := sshDial
	t.Cleanup(func() { sshDial = origDial })
	sshDial = func(context.Context, string, string, *ssh.ClientConfig) (*ssh.Client, error) {
		cancel()
		return &ssh.Client{Conn: conn}, nil
	}
	out := testQueue()
	executeConfigBackupJobCtx(sessionCtx, context.Background(), cbJob("192.0.2.1", 22), out)

	select {
	case <-conn.closed:
	default:
		t.Fatal("successfully dialed SSH client was left open after session cancellation")
	}
	select {
	case queued := <-out.items:
		t.Fatalf("unexpected result after session cancellation: %+v", queued)
	default:
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

func TestConfigBackupExpiredJobDeadlineReportsTimeout(t *testing.T) {
	jobCtx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	out := testQueue()
	executeConfigBackupJobCtx(context.Background(), jobCtx, cbJob("127.0.0.1", 22), out)
	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_TIMEOUT {
		t.Fatalf("code = %v, want TIMEOUT for an expired job budget", result.ErrorCode)
	}
}

func TestConfigBackupJobDeadlineDuringDialReportsTimeout(t *testing.T) {
	original := sshDial
	t.Cleanup(func() { sshDial = original })
	jobCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	sshDial = func(ctx context.Context, _, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	}
	out := testQueue()
	executeConfigBackupJobCtx(context.Background(), jobCtx, cbJob("127.0.0.1", 22), out)
	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_TIMEOUT {
		t.Fatalf("code = %v, want TIMEOUT", result.ErrorCode)
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
	if got := sessionErrCode(deadline, io.EOF); got != pb.ConfigBackupErrorCode_TIMEOUT {
		t.Errorf("deadline ctx = %v, want TIMEOUT", got)
	}
	if got := sessionErrCode(context.Background(), io.EOF); got != pb.ConfigBackupErrorCode_EXPORT_FAILED {
		t.Errorf("live ctx = %v, want EXPORT_FAILED", got)
	}
	if got := sessionErrCode(context.Background(), errConfigBackupTooLarge); got != pb.ConfigBackupErrorCode_TOO_LARGE {
		t.Errorf("overflow err = %v, want TOO_LARGE", got)
	}
}

func TestIsAuthFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"unable to authenticate", errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password]"), true},
		{"auth fail", errors.New("auth fail for user admin"), true},
		{"permission denied", errors.New("permission denied (password)"), true},
		{"handshake EOF", errors.New("ssh: handshake failed: EOF"), false},
		{"no common algorithm", errors.New("ssh: handshake failed: ssh: no common algorithm for host key"), false},
		{"kex error", errors.New("ssh: handshake failed: ssh: no common algorithm for key exchange"), false},
		{"closed conn", errors.New("ssh: handshake failed: read tcp: use of closed network connection"), false},
	}
	for _, tc := range cases {
		if got := isAuthFailure(tc.err); got != tc.want {
			t.Errorf("%s: isAuthFailure = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestBoundedBuffer(t *testing.T) {
	overflows := 0
	buf := &boundedBuffer{limit: 8, onOverflow: func() { overflows++ }}

	if n, err := buf.Write([]byte("hello")); n != 5 || err != nil {
		t.Fatalf("first write = %d, %v; want 5, nil", n, err)
	}
	if got := string(buf.Bytes()); got != "hello" {
		t.Fatalf("buf = %q, want %q", got, "hello")
	}
	if buf.overflow {
		t.Fatal("overflow flagged before the limit")
	}

	// Crossing the limit keeps only the cap's worth of bytes, reports the
	// full write to io.Copy, and fires onOverflow exactly once.
	if n, err := buf.Write([]byte("abcdefgh")); n != 8 || err != nil {
		t.Fatalf("crossing write = %d, %v; want 8, nil", n, err)
	}
	if got := string(buf.Bytes()); got != "helloabc" {
		t.Fatalf("buf = %q, want %q", got, "helloabc")
	}
	if !buf.overflow || overflows != 1 {
		t.Fatalf("overflow = %v, calls = %d; want true, 1", buf.overflow, overflows)
	}

	if n, err := buf.Write([]byte("more")); n != 4 || err != nil {
		t.Fatalf("post-overflow write = %d, %v; want 4, nil", n, err)
	}
	if overflows != 1 || len(buf.Bytes()) != 8 {
		t.Fatalf("post-overflow calls = %d, len = %d; want 1, 8", overflows, len(buf.Bytes()))
	}
}

// TestRunConfigBackupSessionTooLarge streams more stdout than the caller's
// cap and expects the sentinel plus a prompt return — the channel is closed
// on overflow rather than read to the deadline.
func TestRunConfigBackupSessionTooLarge(t *testing.T) {
	resetHostKeyStore(t)
	handler := func(ch ssh.Channel, _ string) {
		chunk := bytes.Repeat([]byte("x"), 4096)
		for range 64 { // 256 KiB > the 64-byte cap
			if _, err := ch.Write(chunk); err != nil {
				return
			}
		}
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	}
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), handler)
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	client, _, err := configBackupDial(context.Background(), cbJob(host, port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	stdout, _, err := runConfigBackupSession(context.Background(), client, "flood", 64)
	if !errors.Is(err, errConfigBackupTooLarge) {
		t.Fatalf("err = %v, want errConfigBackupTooLarge", err)
	}
	if len(stdout) > 64 {
		t.Fatalf("retained stdout = %d bytes, want <= 64", len(stdout))
	}
}

// TestConfigBackupProbeEscapesUsername verifies a hostile username cannot
// break out of the quoted script literal: quotable characters are escaped and
// brackets, which RouterOS evaluates even inside quotes, are rejected before
// the command is sent.
func TestConfigBackupProbeEscapesUsername(t *testing.T) {
	var mu sync.Mutex
	var commands []string
	handler := func(ch ssh.Channel, command string) {
		mu.Lock()
		commands = append(commands, command)
		mu.Unlock()
		cbRouterHandler(cbTestExport)(ch, command)
	}

	escaped := []struct {
		name     string
		username string
		wantPart string
	}{
		{"quote", `ad"min`, `ad\"min`},
		{"backslash", `ad\min`, `ad\\min`},
		{"dollar", `ad$min`, `ad\$min`},
	}
	for _, tc := range escaped {
		t.Run("escaped/"+tc.name, func(t *testing.T) {
			resetHostKeyStore(t)
			mu.Lock()
			commands = nil
			mu.Unlock()
			addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), handler)
			defer cleanup()
			host, port := cbAddrPort(t, addr)

			job := cbJob(host, port)
			job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
			job.ConfigBackup.Username = tc.username
			out := testQueue()
			executeConfigBackupJob(context.Background(), job, out)

			result := cbReceiveConfigBackupResult(t, out)
			if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
				t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
			}
			mu.Lock()
			defer mu.Unlock()
			var policy string
			for _, c := range commands {
				if strings.Contains(c, "user group get") {
					policy = c
				}
			}
			if !strings.Contains(policy, tc.wantPart) {
				t.Fatalf("policy command = %q, want escaped %q", policy, tc.wantPart)
			}
		})
	}

	for _, username := range []string{`ad[min`, `ad]min`, "x[:log info \"pwned\"]"} {
		t.Run("rejected/"+username, func(t *testing.T) {
			resetHostKeyStore(t)
			mu.Lock()
			commands = nil
			mu.Unlock()
			addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), handler)
			defer cleanup()
			host, port := cbAddrPort(t, addr)

			job := cbJob(host, port)
			job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
			job.ConfigBackup.Username = username
			out := testQueue()
			executeConfigBackupJob(context.Background(), job, out)

			result := cbReceiveConfigBackupResult(t, out)
			if result.ErrorCode != pb.ConfigBackupErrorCode_INTERNAL {
				t.Fatalf("code = %v (%q), want INTERNAL", result.ErrorCode, result.ErrorDetail)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, c := range commands {
				if strings.Contains(c, "user group get") {
					t.Fatalf("policy command sent for rejected username: %q", c)
				}
			}
		})
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
	if _, err := v.readVersion(context.Background(), client); err == nil {
		t.Error("readVersion on closed client should fail")
	}
	if _, err := v.readIdentity(context.Background(), client); err == nil {
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

func TestConfigBackupSuccessfulExitFailureRedactsBeforeTruncating(t *testing.T) {
	resetHostKeyStore(t)
	const password = "secret-password"
	prefix := "failure: " + strings.Repeat("x", maxConfigBackupDetailLen-3-len("failure: "))
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExportExitHandler(prefix+password+"\n", 0))
	defer cleanup()
	host, port := cbAddrPort(t, addr)
	job := cbJob(host, port)
	job.ConfigBackup.Password = password
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_EXPORT_FAILED {
		t.Fatalf("code = %v, want EXPORT_FAILED", result.ErrorCode)
	}
	if result.ErrorDetail != prefix+"***" {
		t.Fatalf("detail = %q, want %q", result.ErrorDetail, prefix+"***")
	}
	if !utf8.ValidString(result.ErrorDetail) {
		t.Fatalf("detail is not valid UTF-8: %q", result.ErrorDetail)
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

func TestConfigBackupExportTimeout(t *testing.T) {
	cases := []struct {
		name   string
		output string
	}{
		{"empty output", ""},
		{"partial configuration", cbTestExport},
		{"partial failure text", "no permission\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			handler := func(ch ssh.Channel, command string) {
				if strings.HasPrefix(command, "/export") {
					if _, err := ch.Write([]byte(tc.output)); err != nil {
						return
					}
					<-release
					return
				}
				cbRouterHandler(cbTestExport)(ch, command)
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
		})
	}
}

func TestConfigBackupExportStderr(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		status uint32
		want   pb.ConfigBackupErrorCode
		detail string
	}{
		{"permission failure after stdout", "no permission\n", 1, pb.ConfigBackupErrorCode_PERMISSION_DENIED, "no permission"},
		{"failure with successful exit", "failure: export aborted\n", 0, pb.ConfigBackupErrorCode_EXPORT_FAILED, "failure: export aborted"},
		{"failure after diagnostic", "diagnostic: export started\nfailure: export aborted\n", 0, pb.ConfigBackupErrorCode_EXPORT_FAILED, "failure: export aborted"},
		{"benign diagnostic", "diagnostic: export started\n", 0, pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(ch ssh.Channel, command string) {
				if strings.HasPrefix(command, "/export") {
					if _, err := ch.Write([]byte(cbTestExport)); err != nil {
						return
					}
					if _, err := ch.Stderr().Write([]byte(tc.stderr)); err != nil {
						return
					}
					if _, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{tc.status})); err != nil {
						return
					}
					if err := ch.Close(); err != nil {
						t.Errorf("close export channel: %v", err)
					}
					return
				}
				cbRouterHandler(cbTestExport)(ch, command)
			}
			addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), handler)
			defer cleanup()
			host, port := cbAddrPort(t, addr)
			out := testQueue()
			executeConfigBackupJob(context.Background(), cbJob(host, port), out)
			result := cbReceiveConfigBackupResult(t, out)
			if result.ErrorCode != tc.want {
				t.Fatalf("code = %v (%q), want %v", result.ErrorCode, result.ErrorDetail, tc.want)
			}
			if result.ErrorDetail != tc.detail {
				t.Fatalf("detail = %q, want %q", result.ErrorDetail, tc.detail)
			}
		})
	}
}

func TestConfigBackupExportFailureLines(t *testing.T) {
	for _, tc := range []struct {
		name   string
		output string
		want   pb.ConfigBackupErrorCode
	}{
		{"failure after config", cbTestExport + "failure: export aborted\n", pb.ConfigBackupErrorCode_EXPORT_FAILED},
		{"permission after header", "# RouterOS 7.15.3\n  no permission\n", pb.ConfigBackupErrorCode_PERMISSION_DENIED},
		{"failure in comment", "# identity = failure: uplink\n/ip address\n", pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK},
		{"failure in config value", "/system identity\nset name=\"no permission\"\n", pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyExportOutput(tc.output); got != tc.want {
				t.Fatalf("code = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConfigBackupProbeDeviceFailures(t *testing.T) {
	for _, command := range []string{"system resource get version", "system identity get name", "user group get"} {
		for _, stream := range []string{"stdout", "stderr"} {
			t.Run(command+"/"+stream, func(t *testing.T) {
				handler := func(ch ssh.Channel, cmd string) {
					if !strings.Contains(cmd, command) {
						cbRouterHandler(cbTestExport)(ch, cmd)
						return
					}
					var writer io.Writer = ch
					if stream == "stderr" {
						writer = ch.Stderr()
					}
					if _, err := io.WriteString(writer, "failure: not enough permissions\n"); err != nil {
						return
					}
					if _, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0})); err != nil {
						return
					}
					if err := ch.Close(); err != nil {
						t.Errorf("close metadata channel: %v", err)
					}
				}
				addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), handler)
				defer cleanup()
				host, port := cbAddrPort(t, addr)
				job := cbJob(host, port)
				job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
				out := testQueue()
				executeConfigBackupJob(context.Background(), job, out)
				result := cbReceiveConfigBackupResult(t, out)
				if result.ErrorCode != pb.ConfigBackupErrorCode_PERMISSION_DENIED {
					t.Fatalf("code = %v (%q), want PERMISSION_DENIED", result.ErrorCode, result.ErrorDetail)
				}
			})
		}
	}
}

func TestConfigBackupMetadataInvalidUTF8(t *testing.T) {
	cases := []struct {
		name    string
		command string
		output  string
		mode    pb.ConfigBackupMode
	}{
		{"version", "system resource get version", "7.15.3\xff\n", pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE},
		{"identity", "system identity get name", "router\xff\n", pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE},
		{"policy", "user group get", "read;custom\xff\n", pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE},
		{"model", "/export", "# model = router\xff\n/ip address\n", pb.ConfigBackupMode_CONFIG_BACKUP_MODE_BACKUP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(ch ssh.Channel, command string) {
				if strings.Contains(command, tc.command) {
					if _, err := ch.Write([]byte(tc.output)); err != nil {
						return
					}
					if _, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0})); err != nil {
						return
					}
					if err := ch.Close(); err != nil {
						t.Errorf("close metadata channel: %v", err)
					}
					return
				}
				cbRouterHandler(cbTestExport)(ch, command)
			}
			addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), handler)
			defer cleanup()
			host, port := cbAddrPort(t, addr)
			job := cbJob(host, port)
			client, _, err := configBackupDial(context.Background(), job)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := client.Close(); err != nil {
					t.Errorf("close client: %v", err)
				}
			}()
			vendor := mikrotikBackupVendor{}
			var result *pb.ConfigBackupResult
			if tc.mode == pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE {
				result = vendor.Probe(context.Background(), client, job.ConfigBackup, job.JobId, job.DeviceId)
			} else {
				result = vendor.Backup(context.Background(), client, job.ConfigBackup, job.JobId, job.DeviceId)
			}
			if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
				t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
			}
			encoded, err := proto.Marshal(result)
			if err != nil {
				t.Fatalf("device metadata prevents result delivery: %v", err)
			}
			if !bytes.Contains(encoded, []byte("\uFFFD")) {
				t.Fatal("metadata did not preserve the valid prefix and replace invalid UTF-8")
			}
			if tc.name == "model" {
				reader, err := gzip.NewReader(bytes.NewReader(result.ConfigGzip))
				if err != nil {
					t.Fatal(err)
				}
				config, readErr := io.ReadAll(reader)
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
				if readErr != nil {
					t.Fatal(readErr)
				}
				if string(config) != tc.output {
					t.Fatalf("archived configuration = %q, want original bytes %q", config, tc.output)
				}
			}
		})
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

// cbRouterOS6Handler behaves like RouterOS 6: it reports a 6.x version and,
// crucially, never sends an exit-status on the exec channel — session.Run on
// the client surfaces that as *ssh.ExitMissingError, which the backup path
// must tolerate or every ROS 6 backup reports EXPORT_FAILED.
func cbRouterOS6Handler(export string, gotExport *string) func(ch ssh.Channel, command string) {
	return func(ch ssh.Channel, command string) {
		var out string
		switch {
		case strings.Contains(command, "system resource get version"):
			out = "6.49.19 (stable)\n"
		case strings.Contains(command, "system identity get name"):
			out = "ros6-router\n"
		case strings.Contains(command, "user group get"):
			out = "read;write;ssh;!policy\n"
		case strings.HasPrefix(command, "/export"):
			*gotExport = command
			out = export
		default:
			out = "failure: bad command\n"
		}
		_, _ = ch.Write([]byte(out))
		_ = ch.CloseWrite()
		_ = ch.Close() // no exit-status: what ROS 6 sends
	}
}

func TestConfigBackupJobRouterOS6NoExitStatus(t *testing.T) {
	resetHostKeyStore(t)
	var gotExport string
	addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbRouterOS6Handler(cbTestExport, &gotExport))
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
		t.Fatalf("code = %v (%q)", result.ErrorCode, result.ErrorDetail)
	}
	if gotExport != "/export" {
		// ROS 6 includes secrets by default; the job asks for them, so the
		// ROS 6 export is the bare command — hide-sensitive would strip them.
		t.Fatalf("export command = %q, want /export (ROS 6 includes secrets by default)", gotExport)
	}
	if len(result.ConfigGzip) == 0 {
		t.Fatal("ConfigGzip empty")
	}
}

// TestConfigBackupJobLegacyAlgorithms serves SSH with a key exchange and
// cipher only a very old RouterOS 6 offers (group1-sha1, aes128-cbc) — both
// moved out of x/crypto's default client list.
func TestConfigBackupJobLegacyAlgorithms(t *testing.T) {
	resetHostKeyStore(t)

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.Ciphers = []string{ssh.InsecureCipherAES128CBC}
	config.KeyExchanges = []string{ssh.InsecureKeyExchangeDH1SHA1}
	config.MACs = []string{ssh.HMACSHA1}
	config.AddHostKey(cbNewSigner(t))

	addr, cleanup := startTestSSHServerWithConfig(t, config, cbRouterHandler(cbTestExport))
	defer cleanup()
	host, port := cbAddrPort(t, addr)

	job := cbJob(host, port)
	out := testQueue()
	executeConfigBackupJob(context.Background(), job, out)

	result := cbReceiveConfigBackupResult(t, out)
	if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
		t.Fatalf("code = %v (%q)", result.ErrorCode, result.ErrorDetail)
	}
	if len(result.ConfigGzip) == 0 {
		t.Fatal("ConfigGzip empty")
	}
}

// --- Plan engine ---------------------------------------------------------

// cbPlanJob builds a plan-driven backup job; the vendor string is one the
// agent has no built-in recipe for.
func cbPlanJob(host string, port uint32, plan *pb.ConfigBackupPlan) *pb.AgentJob {
	job := cbJob(host, port)
	job.ConfigBackup.Vendor = "cisco"
	job.ConfigBackup.Plan = plan
	return job
}

func cbExecPlan(steps ...*pb.ConfigBackupStep) *pb.ConfigBackupPlan {
	return &pb.ConfigBackupPlan{Transport: pb.ConfigBackupTransport_CONFIG_BACKUP_TRANSPORT_EXEC, Steps: steps}
}

func cbShellPlan(steps ...*pb.ConfigBackupStep) *pb.ConfigBackupPlan {
	return &pb.ConfigBackupPlan{Transport: pb.ConfigBackupTransport_CONFIG_BACKUP_TRANSPORT_SHELL, Steps: steps}
}

func cbCommand(cmd string, fallbacks ...string) *pb.ConfigBackupStep {
	return &pb.ConfigBackupStep{
		Kind:             pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND,
		Command:          cmd,
		FallbackCommands: fallbacks,
	}
}

func cbPrivileged(cmd string) *pb.ConfigBackupStep {
	return &pb.ConfigBackupStep{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_PRIVILEGED, Command: cmd}
}

// cbExecResponse is one command's canned exec-channel output.
type cbExecResponse struct {
	out    string
	errOut string
	exit   uint32
}

// cbExecHandler dispatches per-command exec responses; unknown commands
// fail loudly so tests catch commands the plan engine should never send.
func cbExecHandler(responses map[string]cbExecResponse, seen func(cmd string)) func(ch ssh.Channel, command string) {
	return func(ch ssh.Channel, command string) {
		if seen != nil {
			seen(command)
		}
		resp, ok := responses[command]
		if !ok {
			resp = cbExecResponse{out: "unexpected command: " + command + "\n", exit: 1}
		}
		if resp.out != "" {
			_, _ = ch.Write([]byte(resp.out))
		}
		if resp.errOut != "" {
			_, _ = ch.Stderr().Write([]byte(resp.errOut))
		}
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{resp.exit}))
		_ = ch.Close()
	}
}

func TestConfigBackupPlanRouting(t *testing.T) {
	t.Run("plan job with an unknown vendor runs the plan", func(t *testing.T) {
		resetHostKeyStore(t)
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(map[string]cbExecResponse{
			"show configuration | display set": {out: "set system host-name jr1\n"},
		}, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		job := cbPlanJob(host, port, cbExecPlan(cbCommand("show configuration | display set")))
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
		}
		if text := cbGunzip(t, result.ConfigGzip); text != "set system host-name jr1\n" {
			t.Fatalf("config = %q", text)
		}
	})

	t.Run("mikrotik job without a plan runs the RouterOS recipe", func(t *testing.T) {
		resetHostKeyStore(t)
		var mu sync.Mutex
		var commands []string
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(map[string]cbExecResponse{
			":put [/system resource get version]": {out: "7.15.3 (stable)\n"},
			"/export show-sensitive":              {out: cbTestExport},
			"/export":                             {out: cbTestExport},
		}, func(cmd string) {
			mu.Lock()
			commands = append(commands, cmd)
			mu.Unlock()
		}))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		out := testQueue()
		executeConfigBackupJob(context.Background(), cbJob(host, port), out)
		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q), want OK via the RouterOS recipe", result.ErrorCode, result.ErrorDetail)
		}
		if got := cbGunzip(t, result.ConfigGzip); got != cbTestExport {
			t.Fatalf("config = %q, want the RouterOS export", got)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(commands) == 0 || !strings.Contains(commands[0], "system resource get version") {
			t.Fatalf("commands = %v, want the RouterOS version probe first", commands)
		}
	})

	t.Run("unknown vendor without a plan is rejected before any command", func(t *testing.T) {
		resetHostKeyStore(t)
		var execCount int32
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(map[string]cbExecResponse{}, func(cmd string) {
			atomic.AddInt32(&execCount, 1)
		}))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		job := cbJob(host, port)
		job.ConfigBackup.Vendor = "juniper"
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_UNSUPPORTED_VENDOR {
			t.Fatalf("code = %v, want UNSUPPORTED_VENDOR", result.ErrorCode)
		}
		if atomic.LoadInt32(&execCount) != 0 {
			t.Fatalf("the fake server saw %d exec requests, want 0", execCount)
		}
		if result.HostKeyFingerprint == "" {
			t.Error("observed host key fingerprint not reported")
		}
	})
}

func cbGunzip(t *testing.T, gz []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// cbUserKeyPEM generates an Ed25519 keypair and its PEM private key.
func cbUserKeyPEM(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "cb test key")
	if err != nil {
		t.Fatal(err)
	}
	return signer, string(pem.EncodeToMemory(block))
}

func TestConfigBackupAuthOrder(t *testing.T) {
	plan := cbExecPlan(cbCommand("show version"))
	showVersion := map[string]cbExecResponse{"show version": {out: "Cisco IOS 15.2\n"}}

	t.Run("public key wins when the key parses", func(t *testing.T) {
		resetHostKeyStore(t)
		userSigner, userPEM := cbUserKeyPEM(t)
		config := &ssh.ServerConfig{
			PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				if bytes.Equal(key.Marshal(), userSigner.PublicKey().Marshal()) {
					return &ssh.Permissions{}, nil
				}
				return nil, fmt.Errorf("rejected")
			},
		}
		config.AddHostKey(cbNewSigner(t))
		addr, cleanup := startTestSSHServerWithConfig(t, config, cbExecHandler(showVersion, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		job := cbPlanJob(host, port, plan)
		job.ConfigBackup.PrivateKey = userPEM
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)
		if result := cbReceiveConfigBackupResult(t, out); result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
		}
	})

	t.Run("keyboard-interactive answers the password", func(t *testing.T) {
		resetHostKeyStore(t)
		config := &ssh.ServerConfig{
			KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				ans, err := client("auth", "", []string{"Password: "}, []bool{false})
				if err != nil {
					return nil, err
				}
				if len(ans) == 1 && ans[0] == "secret" {
					return &ssh.Permissions{}, nil
				}
				return nil, fmt.Errorf("denied")
			},
		}
		config.AddHostKey(cbNewSigner(t))
		addr, cleanup := startTestSSHServerWithConfig(t, config, cbExecHandler(showVersion, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		out := testQueue()
		executeConfigBackupJob(context.Background(), cbPlanJob(host, port, plan), out)
		if result := cbReceiveConfigBackupResult(t, out); result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
		}
	})

	t.Run("unparseable private key falls back to password", func(t *testing.T) {
		resetHostKeyStore(t)
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(showVersion, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		job := cbPlanJob(host, port, plan)
		job.ConfigBackup.PrivateKey = "not a pem key at all"
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)
		if result := cbReceiveConfigBackupResult(t, out); result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
		}
	})

	t.Run("rejected public key falls back to password", func(t *testing.T) {
		resetHostKeyStore(t)
		_, userPEM := cbUserKeyPEM(t)
		config := &ssh.ServerConfig{
			PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				return nil, fmt.Errorf("rejected")
			},
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				return &ssh.Permissions{}, nil
			},
		}
		config.AddHostKey(cbNewSigner(t))
		addr, cleanup := startTestSSHServerWithConfig(t, config, cbExecHandler(showVersion, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		job := cbPlanJob(host, port, plan)
		job.ConfigBackup.PrivateKey = userPEM
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)
		if result := cbReceiveConfigBackupResult(t, out); result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
		}
	})
}

func TestConfigBackupPlanConnectionRules(t *testing.T) {
	plan := cbExecPlan(cbCommand("show version"))
	showVersion := map[string]cbExecResponse{"show version": {out: "Cisco IOS 15.2\n"}}

	t.Run("first use reports the fingerprint", func(t *testing.T) {
		resetHostKeyStore(t)
		signer := cbNewSigner(t)
		addr, cleanup := startTestSSHServerWithSigner(t, signer, cbExecHandler(showVersion, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		out := testQueue()
		executeConfigBackupJob(context.Background(), cbPlanJob(host, port, plan), out)
		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q)", result.ErrorCode, result.ErrorDetail)
		}
		if result.HostKeyFingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
			t.Fatalf("fingerprint = %q, want the server key", result.HostKeyFingerprint)
		}
	})

	t.Run("mismatch rejects before any password is sent", func(t *testing.T) {
		resetHostKeyStore(t)
		var authAttempts int32
		config := &ssh.ServerConfig{
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				atomic.AddInt32(&authAttempts, 1)
				return &ssh.Permissions{}, nil
			},
		}
		serverSigner := cbNewSigner(t)
		config.AddHostKey(serverSigner)
		addr, cleanup := startTestSSHServerWithConfig(t, config, cbExecHandler(showVersion, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		job := cbPlanJob(host, port, plan)
		job.ConfigBackup.ExpectedHostKeyFingerprint = ssh.FingerprintSHA256(cbNewSigner(t).PublicKey())
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_HOST_KEY_MISMATCH {
			t.Fatalf("code = %v (%q), want HOST_KEY_MISMATCH", result.ErrorCode, result.ErrorDetail)
		}
		if result.HostKeyFingerprint != ssh.FingerprintSHA256(serverSigner.PublicKey()) {
			t.Fatalf("fingerprint = %q, want the observed server key", result.HostKeyFingerprint)
		}
		if atomic.LoadInt32(&authAttempts) != 0 {
			t.Fatalf("server saw %d auth attempts, want 0 before host key trust", authAttempts)
		}
	})

	t.Run("legacy ciphers connect", func(t *testing.T) {
		resetHostKeyStore(t)
		config := &ssh.ServerConfig{
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				return nil, nil
			},
		}
		config.Ciphers = []string{ssh.InsecureCipherAES128CBC}
		config.KeyExchanges = []string{ssh.InsecureKeyExchangeDH1SHA1}
		config.MACs = []string{ssh.HMACSHA1}
		config.AddHostKey(cbNewSigner(t))
		addr, cleanup := startTestSSHServerWithConfig(t, config, cbExecHandler(showVersion, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		out := testQueue()
		executeConfigBackupJob(context.Background(), cbPlanJob(host, port, plan), out)
		if result := cbReceiveConfigBackupResult(t, out); result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
		}
	})
}

// TestConfigBackupPlanSteps runs every exec-plan scenario on both
// transports: the failure regexes, fallbacks, exclusions and section
// joining must behave the same over exec channels and the PTY shell.
func TestConfigBackupPlanSteps(t *testing.T) {
	type stepCase struct {
		name     string
		steps    []*pb.ConfigBackupStep
		exec     map[string]cbExecResponse
		script   shellScript
		wantText string
		wantCode pb.ConfigBackupErrorCode
		wantGone []string // commands that must never reach the device
	}
	cases := []stepCase{
		{
			name:  "single command",
			steps: []*pb.ConfigBackupStep{cbCommand("show configuration | display set")},
			exec:  map[string]cbExecResponse{"show configuration | display set": {out: "set system host-name jr1\n"}},
			script: shellScript{
				"show configuration | display set": {lines: []string{"set system host-name jr1", "sw1> "}},
			},
			wantText: "set system host-name jr1\n",
			wantCode: pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK,
		},
		{
			name:  "fallback after no such file",
			steps: []*pb.ConfigBackupStep{cbCommand("cat /tmp/running.cfg", "cat /tmp/system.cfg")},
			exec: map[string]cbExecResponse{
				"cat /tmp/running.cfg": {errOut: "cat: /tmp/running.cfg: No such file or directory", exit: 1},
				"cat /tmp/system.cfg":  {out: "system config here\n"},
			},
			script: shellScript{
				"cat /tmp/running.cfg": {lines: []string{"cat: /tmp/running.cfg: No such file or directory", "sw1> "}},
				"cat /tmp/system.cfg":  {lines: []string{"system config here", "sw1> "}},
			},
			wantText: "system config here\n",
			wantCode: pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK,
		},
		{
			name:  "fallback after syntax error",
			steps: []*pb.ConfigBackupStep{cbCommand("show config | page", "show config")},
			exec: map[string]cbExecResponse{
				"show config | page": {out: "syntax error\n", exit: 1},
				"show config":        {out: "full config\n"},
			},
			script: shellScript{
				"show config | page": {lines: []string{"syntax error", "sw1> "}},
				"show config":        {lines: []string{"full config", "sw1> "}},
			},
			wantText: "full config\n",
			wantCode: pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK,
		},
		{
			name:  "every command unsupported",
			steps: []*pb.ConfigBackupStep{cbCommand("show running-config view full", "show running-config")},
			exec: map[string]cbExecResponse{
				"show running-config view full": {out: "Unknown command\n", exit: 1},
				"show running-config":           {out: "Unknown command\n", exit: 1},
			},
			script: shellScript{
				"show running-config view full": {lines: []string{"Unknown command", "sw1> "}},
				"show running-config":           {lines: []string{"Unknown command", "sw1> "}},
			},
			wantCode: pb.ConfigBackupErrorCode_COMMAND_UNSUPPORTED,
		},
		{
			name:  "permission text fails the step",
			steps: []*pb.ConfigBackupStep{cbCommand("show running-config")},
			exec: map[string]cbExecResponse{
				"show running-config": {errOut: "% Authorization failed", exit: 1},
			},
			script: shellScript{
				"show running-config": {lines: []string{"Permission denied", "sw1> "}},
			},
			wantCode: pb.ConfigBackupErrorCode_PERMISSION_DENIED,
		},
		{
			name:  "permission text falls back to a working command",
			steps: []*pb.ConfigBackupStep{cbCommand("show running-config view full", "show running-config")},
			exec: map[string]cbExecResponse{
				"show running-config view full": {errOut: "Permission denied", exit: 1},
				"show running-config":           {out: "hostname sw1\n"},
			},
			script: shellScript{
				"show running-config view full": {lines: []string{"Permission denied", "sw1> "}},
				"show running-config":           {lines: []string{"hostname sw1", "sw1> "}},
			},
			wantText: "hostname sw1\n",
			wantCode: pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK,
		},
		{
			name: "ignored setup failure continues",
			steps: []*pb.ConfigBackupStep{
				{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "terminal length 0", ExcludeOutput: true, IgnoreFailure: true},
				cbCommand("show running-config"),
			},
			exec: map[string]cbExecResponse{
				"terminal length 0":   {errOut: "Invalid input", exit: 1},
				"show running-config": {out: "hostname sw1\n"},
			},
			script: shellScript{
				"terminal length 0":   {lines: []string{"Invalid input", "sw1> "}},
				"show running-config": {lines: []string{"hostname sw1", "sw1> "}},
			},
			wantText: "hostname sw1\n",
			wantCode: pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK,
		},
		{
			name: "excluded step contributes no output",
			steps: []*pb.ConfigBackupStep{
				{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "set terminal width 512", ExcludeOutput: true},
				cbCommand("show running-config"),
			},
			exec: map[string]cbExecResponse{
				"set terminal width 512": {out: "width set\n"},
				"show running-config":    {out: "hostname sw1\n"},
			},
			script: shellScript{
				"set terminal width 512": {lines: []string{"width set", "sw1> "}},
				"show running-config":    {lines: []string{"hostname sw1", "sw1> "}},
			},
			wantText: "hostname sw1\n",
			wantCode: pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK,
		},
		{
			name: "two labelled sections join under headers",
			steps: []*pb.ConfigBackupStep{
				{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "cat /tmp/system.cfg", Section: "system.cfg"},
				{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "cat /tmp/running-config", Section: "running-config"},
			},
			exec: map[string]cbExecResponse{
				"cat /tmp/system.cfg":     {out: "system cfg text\n"},
				"cat /tmp/running-config": {out: "running cfg text\n"},
			},
			script: shellScript{
				"cat /tmp/system.cfg":     {lines: []string{"system cfg text", "sw1> "}},
				"cat /tmp/running-config": {lines: []string{"running cfg text", "sw1> "}},
			},
			wantText: "# ---- system.cfg ----\nsystem cfg text\n# ---- running-config ----\nrunning cfg text\n",
			wantCode: pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK,
		},
		{
			name: "a failed step stops the plan",
			steps: []*pb.ConfigBackupStep{
				cbCommand("first ok"),
				cbCommand("show broken"),
				cbCommand("third step"),
			},
			exec: map[string]cbExecResponse{
				"first ok":    {out: "first\n"},
				"show broken": {out: "Unknown command\n", exit: 1},
			},
			script: shellScript{
				"first ok":    {lines: []string{"first", "sw1> "}},
				"show broken": {lines: []string{"Unknown command", "sw1> "}},
			},
			wantText: "first\n",
			wantCode: pb.ConfigBackupErrorCode_COMMAND_UNSUPPORTED,
			wantGone: []string{"third step"},
		},
	}

	for _, transport := range []struct {
		name string
		kind pb.ConfigBackupTransport
	}{
		{"exec", pb.ConfigBackupTransport_CONFIG_BACKUP_TRANSPORT_EXEC},
		{"shell", pb.ConfigBackupTransport_CONFIG_BACKUP_TRANSPORT_SHELL},
	} {
		t.Run(transport.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					resetHostKeyStore(t)
					plan := &pb.ConfigBackupPlan{Transport: transport.kind, Steps: tc.steps}
					var job *pb.AgentJob
					var received func() []string
					if transport.kind == pb.ConfigBackupTransport_CONFIG_BACKUP_TRANSPORT_EXEC {
						var mu sync.Mutex
						var seen []string
						handler := cbExecHandler(tc.exec, func(cmd string) {
							mu.Lock()
							seen = append(seen, cmd)
							mu.Unlock()
						})
						received = func() []string {
							mu.Lock()
							defer mu.Unlock()
							return append([]string(nil), seen...)
						}
						addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), handler)
						defer cleanup()
						host, port := cbAddrPort(t, addr)
						job = cbPlanJob(host, port, plan)
					} else {
						fake := startFakeShellServer(t, "", "sw1> ", tc.script)
						defer fake.cleanup()
						host, port := cbAddrPort(t, fake.addr)
						job = cbPlanJob(host, port, plan)
						received = fake.receivedLines
					}
					out := testQueue()
					executeConfigBackupJob(context.Background(), job, out)

					result := cbReceiveConfigBackupResult(t, out)
					if result.ErrorCode != tc.wantCode {
						t.Fatalf("code = %v (%q), want %v", result.ErrorCode, result.ErrorDetail, tc.wantCode)
					}
					if tc.wantCode == pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
						if got := cbGunzip(t, result.ConfigGzip); got != tc.wantText {
							t.Fatalf("config = %q, want %q", got, tc.wantText)
						}
						if result.ConfigBytes != uint64(len(tc.wantText)) {
							t.Fatalf("config_bytes = %d, want %d", result.ConfigBytes, len(tc.wantText))
						}
						if !result.IncludesSecrets {
							t.Error("includes_secrets not set")
						}
					}
					for _, gone := range tc.wantGone {
						for _, line := range received() {
							if line == gone {
								t.Fatalf("step %q ran after the plan should have stopped", gone)
							}
						}
					}
				})
			}
		})
	}
}

func TestConfigBackupPlanLimitsAndResult(t *testing.T) {
	megabyte := strings.Repeat("a", (1<<20)-1) + "\n"

	t.Run("two sections over the cap return TOO_LARGE", func(t *testing.T) {
		resetHostKeyStore(t)
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(map[string]cbExecResponse{
			"cat /tmp/system.cfg":     {out: strings.Repeat(megabyte, 4)},
			"cat /tmp/running-config": {out: strings.Repeat(megabyte, 4)},
		}, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		job := cbPlanJob(host, port, cbExecPlan(
			&pb.ConfigBackupStep{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "cat /tmp/system.cfg", Section: "system.cfg"},
			&pb.ConfigBackupStep{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "cat /tmp/running-config", Section: "running-config"},
		))
		job.ConfigBackup.MaxConfigBytes = 7 << 20
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_TOO_LARGE {
			t.Fatalf("code = %v (%q), want TOO_LARGE", result.ErrorCode, result.ErrorDetail)
		}
		if len(result.ConfigGzip) != 0 {
			t.Error("TOO_LARGE must not carry config output")
		}
	})

	t.Run("section headers count toward the cap", func(t *testing.T) {
		resetHostKeyStore(t)
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(map[string]cbExecResponse{
			"cat /tmp/system.cfg":     {out: strings.Repeat(megabyte, 4)},
			"cat /tmp/running-config": {out: strings.Repeat(megabyte, 4)},
		}, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		job := cbPlanJob(host, port, cbExecPlan(
			&pb.ConfigBackupStep{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "cat /tmp/system.cfg", Section: "system.cfg"},
			&pb.ConfigBackupStep{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "cat /tmp/running-config", Section: "running-config"},
		))
		// The two outputs alone fit 8 MiB exactly; only the headers overflow.
		job.ConfigBackup.MaxConfigBytes = 8 << 20
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_TOO_LARGE {
			t.Fatalf("code = %v, want TOO_LARGE when headers cross the cap", result.ErrorCode)
		}
	})

	t.Run("successful plan fills the result", func(t *testing.T) {
		resetHostKeyStore(t)
		signer := cbNewSigner(t)
		addr, cleanup := startTestSSHServerWithSigner(t, signer, cbExecHandler(map[string]cbExecResponse{
			"show running-config": {out: strings.Repeat("x", 122880)},
		}, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		out := testQueue()
		executeConfigBackupJob(context.Background(), cbPlanJob(host, port, cbExecPlan(cbCommand("show running-config"))), out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q)", result.ErrorCode, result.ErrorDetail)
		}
		if got := cbGunzip(t, result.ConfigGzip); len(got) != 122880 {
			t.Fatalf("config length = %d, want 122880", len(got))
		}
		if result.ConfigBytes != 122880 {
			t.Fatalf("config_bytes = %d, want 122880", result.ConfigBytes)
		}
		if !result.IncludesSecrets {
			t.Error("includes_secrets = false, want true")
		}
		if result.HostKeyFingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
			t.Errorf("fingerprint = %q, want the server key", result.HostKeyFingerprint)
		}
		if result.DurationMs == 0 && result.Timestamp == 0 {
			t.Error("duration and timestamp unset")
		}
	})
}

func TestConfigBackupPlanRedaction(t *testing.T) {
	_, userPEM := cbUserKeyPEM(t)
	keyBody := "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB"

	t.Run("shell echo of every secret is redacted", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{
			"show run": {lines: []string{"Permission denied for logpass (en4ble) near " + keyBody, "sw1> "}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		job := cbPlanJob(host, port, cbShellPlan(cbCommand("show run")))
		job.ConfigBackup.Password = "logpass"
		job.ConfigBackup.EnablePassword = "en4ble"
		job.ConfigBackup.PrivateKey = userPEM
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_PERMISSION_DENIED {
			t.Fatalf("code = %v (%q), want PERMISSION_DENIED", result.ErrorCode, result.ErrorDetail)
		}
		detail := result.ErrorDetail
		for _, secret := range []string{"logpass", "en4ble", keyBody, "PRIVATE KEY"} {
			if strings.Contains(detail, secret) {
				t.Errorf("error detail leaks %q: %q", secret, detail)
			}
		}
		if !strings.Contains(detail, "***") {
			t.Errorf("error detail has no redaction marker: %q", detail)
		}
	})

	t.Run("exec output echoing secrets is redacted", func(t *testing.T) {
		resetHostKeyStore(t)
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(map[string]cbExecResponse{
			"show running-config": {errOut: "% Password: refused (login logpass, key " + keyBody + ")", exit: 1},
		}, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		job := cbPlanJob(host, port, cbExecPlan(cbCommand("show running-config")))
		job.ConfigBackup.Password = "logpass"
		job.ConfigBackup.PrivateKey = userPEM
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_PERMISSION_DENIED {
			t.Fatalf("code = %v (%q), want PERMISSION_DENIED", result.ErrorCode, result.ErrorDetail)
		}
		for _, secret := range []string{"logpass", keyBody, "PRIVATE KEY"} {
			if strings.Contains(result.ErrorDetail, secret) {
				t.Errorf("error detail leaks %q: %q", secret, result.ErrorDetail)
			}
		}
	})

	t.Run("classifier redacts enable password and key", func(t *testing.T) {
		job := cbJob("192.0.2.1", 22)
		job.ConfigBackup.EnablePassword = "en4ble"
		job.ConfigBackup.PrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + keyBody + "\n-----END OPENSSH PRIVATE KEY-----\n"
		_, detail := classifyConfigBackupError(
			errors.New("handshake failed after en4ble with "+keyBody), job)
		if strings.Contains(detail, "en4ble") || strings.Contains(detail, keyBody) {
			t.Fatalf("detail = %q, want secrets redacted", detail)
		}
		if !strings.Contains(detail, "***") {
			t.Fatalf("detail = %q, want a redaction marker", detail)
		}
	})
}

func TestConfigBackupPlanProbe(t *testing.T) {
	t.Run("probe with enable reports the prompt host", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "edge1> ", shellScript{
			"enable": {lines: []string{"Password: "}},
			"s3cret": {lines: []string{"edge1# "}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		job := cbPlanJob(host, port, cbShellPlan(cbPrivileged("enable"), cbCommand("show running-config")))
		job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
		job.ConfigBackup.EnablePassword = "s3cret"
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
		}
		if result.Identity != "edge1" {
			t.Fatalf("identity = %q, want edge1", result.Identity)
		}
		if len(result.ConfigGzip) != 0 {
			t.Error("probe must not export")
		}
		for _, line := range fake.receivedLines() {
			if line == "show running-config" {
				t.Fatal("probe ran a command step")
			}
		}
	})

	t.Run("probe with a refused enable password", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "edge1> ", shellScript{
			"enable": {lines: []string{"Password: "}},
			"s3cret": {lines: []string{"% Access denied", "edge1> "}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		job := cbPlanJob(host, port, cbShellPlan(cbPrivileged("enable")))
		job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
		job.ConfigBackup.EnablePassword = "s3cret"
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_ENABLE_FAILED {
			t.Fatalf("code = %v (%q), want ENABLE_FAILED", result.ErrorCode, result.ErrorDetail)
		}
	})

	t.Run("exec probe connects without a prompt", func(t *testing.T) {
		resetHostKeyStore(t)
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(map[string]cbExecResponse{}, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		job := cbPlanJob(host, port, cbExecPlan(cbPrivileged("enable")))
		job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
		}
	})
}

func TestConfigBackupPlanLifecycle(t *testing.T) {
	t.Run("job deadline wins over a longer step timeout", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{
			"show stall": {lines: []string{"starting the collection"}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		plan := cbShellPlan(cbCommand("show stall"))
		plan.StepTimeoutMs = 60_000
		job := cbPlanJob(host, port, plan)

		before := runtimeNumGoroutine()
		jobCtx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
		defer cancel()
		out := testQueue()
		executeConfigBackupJobCtx(context.Background(), jobCtx, job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_TIMEOUT {
			t.Fatalf("code = %v (%q), want TIMEOUT", result.ErrorCode, result.ErrorDetail)
		}
		cbWaitGoroutines(t, before)
	})

	t.Run("session end mid-collection sends no result", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{
			"show stall": {lines: []string{"starting the collection"}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		plan := cbShellPlan(cbCommand("show stall"))
		plan.StepTimeoutMs = 5_000
		job := cbPlanJob(host, port, plan)

		sessionCtx, cancel := context.WithCancel(context.Background())
		out := testQueue()
		done := make(chan struct{})
		go func() {
			defer close(done)
			executeConfigBackupJobCtx(sessionCtx, context.Background(), job, out)
		}()
		// Wait until the device received the command, then end the session.
		deadline := time.Now().Add(3 * time.Second)
		for {
			for _, line := range fake.receivedLines() {
				if line == "show stall" {
					goto received
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("the command never reached the fake device")
			}
			time.Sleep(20 * time.Millisecond)
		}
	received:
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("job did not finish after the session ended")
		}
		select {
		case queued := <-out.items:
			t.Fatalf("a result was sent after the session ended: %+v", queued)
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("device closing mid-collection reports a failure", func(t *testing.T) {
		resetHostKeyStore(t)
		// The fake device closes the channel on "exit": a session ending
		// mid-collection must surface as a non-OK result, not a hang.
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{
			"exit": {lines: []string{"goodbye"}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		job := cbPlanJob(host, port, cbShellPlan(cbCommand("exit")))
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode == pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatal("a dead session produced an OK result")
		}
	})

	t.Run("goroutines return to baseline after each job", func(t *testing.T) {
		resetHostKeyStore(t)
		scenarios := []struct {
			name   string
			script shellScript
			plan   *pb.ConfigBackupPlan
		}{
			{"success", shellScript{"show run": {lines: []string{"hostname sw1", "sw1> "}}},
				cbShellPlan(cbCommand("show run"))},
			{"failure", shellScript{"show broken": {lines: []string{"Unknown command", "sw1> "}}},
				cbShellPlan(cbCommand("show broken"))},
			{"deadline", shellScript{"show stall": {lines: []string{"starting"}}},
				cbShellPlan(cbCommand("show stall"))},
		}
		for _, sc := range scenarios {
			t.Run(sc.name, func(t *testing.T) {
				fake := startFakeShellServer(t, "", "sw1> ", sc.script)
				defer fake.cleanup()
				host, port := cbAddrPort(t, fake.addr)

				plan := sc.plan
				plan.StepTimeoutMs = 600
				before := runtimeNumGoroutine()
				out := testQueue()
				executeConfigBackupJob(context.Background(), cbPlanJob(host, port, plan), out)
				cbReceiveConfigBackupResult(t, out)
				cbWaitGoroutines(t, before)
			})
		}
	})
}

func runtimeNumGoroutine() int { return runtime.NumGoroutine() }

// cbWaitGoroutines fails the test unless the goroutine count returns to
// baseline within a few seconds.
func cbWaitGoroutines(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutines did not settle: before %d, after %d", before, runtime.NumGoroutine())
}

func TestConfigBackupPlanPool(t *testing.T) {
	t.Run("same host runs one plan job at a time", func(t *testing.T) {
		resetHostKeyStore(t)
		origJitter := dispatchJitterMax
		dispatchJitterMax = 0
		t.Cleanup(func() { dispatchJitterMax = origJitter })

		var active, maxActive int32
		handler := cbExecHandler(map[string]cbExecResponse{
			"show version": {out: "Cisco IOS 15.2\n"},
		}, nil)
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), func(ch ssh.Channel, command string) {
			n := atomic.AddInt32(&active, 1)
			for {
				old := atomic.LoadInt32(&maxActive)
				if n <= old || atomic.CompareAndSwapInt32(&maxActive, old, n) {
					break
				}
			}
			defer atomic.AddInt32(&active, -1)
			handler(ch, command)
		})
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		pools := &jobPools{
			backup:  newWorkerPool(8),
			targets: &targetGates{},
			notices: make(chan outbound, 8),
		}
		defer func() { pools.backup.stop() }()
		out := testQueue()

		plan := cbExecPlan(cbCommand("show version"))
		for _, jobID := range []string{"job-a", "job-b"} {
			job := cbPlanJob(host, port, plan)
			job.JobId = jobID
			if !submitJob(context.Background(), job, pools, out, func() {}, false) {
				t.Fatal("submitJob rejected a fresh pool")
			}
		}
		cbReceiveConfigBackupResult(t, out)
		cbReceiveConfigBackupResult(t, out)
		if atomic.LoadInt32(&maxActive) != 1 {
			t.Fatalf("max concurrent plan jobs for one host = %d, want 1", maxActive)
		}
	})

	t.Run("saturated pool rejects a plan job with AGENT_BUSY", func(t *testing.T) {
		pool := newWorkerPool(1)
		pool.stop()
		pools := &jobPools{
			backup:  pool,
			targets: &targetGates{},
			notices: make(chan outbound, 8),
		}
		out := testQueue()
		job := cbPlanJob("192.0.2.1", 22, cbExecPlan(cbCommand("show version")))
		if !submitJob(context.Background(), job, pools, out, func() {}, false) {
			t.Fatal("submitJob must always accept dispatch")
		}
		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_AGENT_BUSY {
			t.Fatalf("code = %v, want AGENT_BUSY", result.ErrorCode)
		}
	})
}
