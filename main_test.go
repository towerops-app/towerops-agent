// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestEnvOrDefault(t *testing.T) {
	key := "TOWEROPS_TEST_ENV_OR_DEFAULT"

	// Unset case
	_ = os.Unsetenv(key)
	if got := envOrDefault(key, "fallback"); got != "fallback" {
		t.Errorf("unset: got %q, want %q", got, "fallback")
	}

	// Set case
	t.Setenv(key, "custom")
	if got := envOrDefault(key, "fallback"); got != "custom" {
		t.Errorf("set: got %q, want %q", got, "custom")
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"wss://towerops.net/socket", "wss://towerops.net/socket"},
		{"wss://towerops.net/socket?token=secret", "wss://towerops.net/socket?***"},
		{"wss://towerops.net/socket?token=secret&key=abc", "wss://towerops.net/socket?***"},
		{"wss://user:password@towerops.net/socket", "wss://%2A%2A%2A@towerops.net/socket"},
		{"://invalid url", "[invalid URL]"},
		{"", ""},
	}
	for _, tt := range tests {
		got := sanitizeURL(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFlagIsSet(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("my-flag", "", "test flag")
	fs.String("other", "", "another flag")

	// Not set
	_ = fs.Parse([]string{})
	if flagIsSet(fs, "my-flag") {
		t.Error("expected false for unset flag")
	}

	// Set
	_ = fs.Parse([]string{"--my-flag=hello"})
	if !flagIsSet(fs, "my-flag") {
		t.Error("expected true for set flag")
	}
	if flagIsSet(fs, "other") {
		t.Error("expected false for other unset flag")
	}
}

func TestStopSignalNotifierAfterShutdownStarts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})

	go stopSignalNotifier(ctx, func() {
		close(stopped)
	})

	select {
	case <-stopped:
		t.Fatal("signal notifier stopped before shutdown started")
	default:
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("signal notifier was not stopped after shutdown started")
	}
}

func TestToWebSocketURL(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"http://localhost:4000", "ws://localhost:4000"},
		{"HTTP://LocalHost:4000", "ws://LocalHost:4000"},
		{"https://towerops.net", "wss://towerops.net"},
		{"HTTPS://TowerOps.NET", "wss://TowerOps.NET"},
		{"hTtPs://TowerOps.NET/Socket", "wss://TowerOps.NET/Socket"},
		{"ws://localhost:4000", "ws://localhost:4000"},
		{"WS://LocalHost:4000", "ws://LocalHost:4000"},
		{"wss://towerops.net", "wss://towerops.net"},
		{"WsS://TowerOps.NET", "wss://TowerOps.NET"},
		{"towerops.net", "wss://towerops.net"},
		{"localhost:4000", "wss://localhost:4000"},
	}
	for _, tt := range tests {
		got, err := toWebSocketURL(tt.input, true)
		if err != nil {
			t.Errorf("toWebSocketURL(%q, true) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("toWebSocketURL(%q, true) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestToWebSocketURLRejectsPlaintext(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"ws:// scheme", "ws://localhost:4000"},
		{"uppercase WS:// scheme", "WS://localhost:4000"},
		{"http:// converts to ws://", "http://localhost:4000"},
		{"uppercase HTTP:// converts to ws://", "HTTP://localhost:4000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := toWebSocketURL(tt.input, false)
			if err == nil {
				t.Error("expected error for plaintext URL")
			}
			if err != nil && !strings.Contains(err.Error(), "plaintext") {
				t.Errorf("expected 'plaintext' in error, got: %v", err)
			}
		})
	}
}

func TestRunMainMissingArgs(t *testing.T) {
	// Unset env vars to ensure flags are required
	t.Setenv("TOWEROPS_API_URL", "")
	t.Setenv("TOWEROPS_AGENT_TOKEN", "")

	code := runMain(context.Background(), []string{})
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
}

func TestRunMainInvalidFlag(t *testing.T) {
	code := runMain(context.Background(), []string{"--nonexistent-flag"})
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
}

func TestRunMainTokenFile(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	_ = os.WriteFile(tokenPath, []byte("  test-token-123  \n"), 0600)

	t.Setenv("TOWEROPS_API_URL", "")
	t.Setenv("TOWEROPS_AGENT_TOKEN", "")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so runAgent returns

	code := runMain(ctx, []string{
		"--api-url=wss://example.com",
		"--token-file=" + tokenPath,
	})
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
}

func TestRunMainTokenFileMissing(t *testing.T) {
	code := runMain(context.Background(), []string{
		"--api-url=wss://example.com",
		"--token-file=/nonexistent/path",
	})
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
}

func TestRunMainPlaintextRejected(t *testing.T) {
	origInsecure := insecureFlag
	defer func() { insecureFlag = origInsecure }()

	t.Setenv("TOWEROPS_API_URL", "")
	t.Setenv("TOWEROPS_AGENT_TOKEN", "")

	code := runMain(context.Background(), []string{
		"--api-url=http://localhost:4000",
		"--token=test-token",
	})
	if code != 1 {
		t.Errorf("expected exit 1 for plaintext rejection, got %d", code)
	}
}

func TestRunMainPlaintextAllowedWithInsecureFlag(t *testing.T) {
	origInsecure := insecureFlag
	defer func() { insecureFlag = origInsecure }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	code := runMain(ctx, []string{
		"--api-url=HTTP://LocalHost:4000",
		"--token=test-token",
		"--insecure",
	})
	if code != 0 {
		t.Errorf("expected exit 0 with --insecure, got %d", code)
	}
}

func TestRunMainLogLevels(t *testing.T) {
	for _, level := range []string{"debug", "warn", "warning", "error", "info", "unknown"} {
		t.Run(level, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			code := runMain(ctx, []string{
				"--api-url=wss://example.com",
				"--token=test-token",
				"--log-level=" + level,
			})
			if code != 0 {
				t.Errorf("log level %q: expected exit 0, got %d", level, code)
			}
		})
	}
}

func TestRunMainJSONLogFormat(t *testing.T) {
	t.Setenv("LOG_FORMAT", "json")
	t.Setenv("TOWEROPS_API_URL", "wss://example.com")
	t.Setenv("TOWEROPS_AGENT_TOKEN", "test-token")

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	originalStderr := os.Stderr
	originalLogger := slog.Default()
	t.Cleanup(func() {
		os.Stderr = originalStderr
		slog.SetDefault(originalLogger)
		_ = writer.Close()
		_ = reader.Close()
	})
	os.Stderr = writer

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code := runMain(ctx, nil)

	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	os.Stderr = originalStderr
	slog.SetDefault(originalLogger)
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, output)
	}

	var foundStart bool
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		if record["msg"] == "towerops agent starting" {
			foundStart = true
		}
	}
	if !foundStart {
		t.Fatalf("JSON logs missing startup record:\n%s", output)
	}
}

func TestRunMainNormalRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	code := runMain(ctx, []string{
		"--api-url=wss://example.com",
		"--token=test-token",
	})
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
}

func TestRunMainTokenFlagWarning(t *testing.T) {
	// This tests the warning path when --token is passed via CLI
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Setenv("TOWEROPS_API_URL", "")
	t.Setenv("TOWEROPS_AGENT_TOKEN", "")

	code := runMain(ctx, []string{
		"--api-url=wss://example.com",
		"--token=my-secret-token",
	})
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
}

func TestRunMainWithRunAgent(t *testing.T) {
	// Test the full path through runAgent with a real (but immediately cancelled) context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	code := runMain(ctx, []string{
		"--api-url=wss://127.0.0.1:1",
		"--token=test-token",
	})
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
}

// cliTCoverDir returns the coverage output directory `go test -coverprofile`
// hands to the test binary, so a re-exec'd child can contribute counters.
func cliTCoverDir() string {
	if f := flag.Lookup("test.gocoverdir"); f != nil {
		return f.Value.String()
	}
	return ""
}

// TestCliTMainSubprocess re-execs the test binary so main() — which ends in
// os.Exit — can be exercised without terminating the test process.
func TestCliTMainSubprocess(t *testing.T) {
	if os.Getenv("CLIT_RUN_MAIN") == "1" {
		os.Args = []string{"towerops-agent"}
		main()
		return
	}

	args := []string{"-test.run=^TestCliTMainSubprocess$"}
	if dir := cliTCoverDir(); dir != "" {
		args = append(args, "-test.gocoverdir="+dir)
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(),
		"CLIT_RUN_MAIN=1",
		"TOWEROPS_API_URL=",
		"TOWEROPS_AGENT_TOKEN=",
	)
	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected child to exit non-zero, got err=%v output:\n%s", err, out)
	}
	if got := exitErr.ExitCode(); got != 1 {
		t.Fatalf("child exit code = %d, want 1; output:\n%s", got, out)
	}
	if !strings.Contains(string(out), "--api-url and --token are required") {
		t.Fatalf("child output missing usage error:\n%s", out)
	}
}

// cliTFreeUDPPort returns a UDP port that was bindable a moment ago.
func cliTFreeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatalf("close reserved port: %v", err)
	}
	return port
}

func TestCliTRunMainTrapPortOutOfRange(t *testing.T) {
	origInsecure := insecureFlag
	defer func() { insecureFlag = origInsecure }()

	for _, port := range []string{"0", "65536"} {
		t.Run("port"+port, func(t *testing.T) {
			code := runMain(context.Background(), []string{
				"--api-url=wss://example.com",
				"--token=test-token",
				"--trap-enabled",
				"--trap-port=" + port,
			})
			if code != 1 {
				t.Fatalf("trap-port %s: exit = %d, want 1", port, code)
			}
		})
	}
}

func TestCliTRunMainTrapListenerBindFailure(t *testing.T) {
	origInsecure := insecureFlag
	defer func() { insecureFlag = origInsecure }()

	// Hold the port so the agent's trap listener cannot bind it.
	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("bind blocking socket: %v", err)
	}
	defer func() { _ = conn.Close() }()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	code := runMain(context.Background(), []string{
		"--api-url=wss://example.com",
		"--token=test-token",
		"--trap-enabled",
		"--trap-port=" + strconv.Itoa(port),
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1 when trap port is already bound", code)
	}
}

func TestCliTRunMainTrapListenerStarts(t *testing.T) {
	origInsecure := insecureFlag
	defer func() { insecureFlag = origInsecure }()

	port := cliTFreeUDPPort(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // runAgent returns immediately; the listener is closed on the way out

	code := runMain(ctx, []string{
		"--api-url=wss://example.com",
		"--token=test-token",
		"--trap-enabled",
		"--trap-port=" + strconv.Itoa(port),
		"--trap-community=public",
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}

	// The deferred listener.Close() must have released the port.
	conn, err := net.ListenPacket("udp", "0.0.0.0:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("trap port still bound after runMain returned: %v", err)
	}
	_ = conn.Close()
}

func TestCliTEnvBoolUnparseable(t *testing.T) {
	key := "CLIT_ENV_BOOL"
	t.Setenv(key, "not-a-bool")
	if got := envBool(key, true); got != true {
		t.Errorf("envBool = %v, want fallback true", got)
	}
	if got := envBool(key, false); got != false {
		t.Errorf("envBool = %v, want fallback false", got)
	}

	t.Setenv(key, "true")
	if got := envBool(key, false); got != true {
		t.Errorf("envBool = %v, want parsed true", got)
	}
}

func TestCliTEnvUintUnparseable(t *testing.T) {
	key := "CLIT_ENV_UINT"
	for _, v := range []string{"not-a-number", "-1", "99999999999999999999"} {
		t.Setenv(key, v)
		if got := envUint(key, 162); got != 162 {
			t.Errorf("envUint(%q) = %d, want fallback 162", v, got)
		}
	}

	t.Setenv(key, "1162")
	if got := envUint(key, 162); got != 1162 {
		t.Errorf("envUint = %d, want 1162", got)
	}
}

func TestPropCliSanitizeURL(t *testing.T) {
	if got := sanitizeURL(""); got != "" {
		t.Fatalf("sanitizeURL(%q) = %q, want empty string", "", got)
	}

	rapid.Check(t, func(t *rapid.T) {
		scheme := rapid.SampledFrom([]string{"http", "https", "ws", "wss"}).Draw(t, "scheme")
		host := rapid.StringMatching(`[a-z]{1,10}(\.[a-z]{2,4})?`).Draw(t, "host")
		path := rapid.SampledFrom([]string{"", "/", "/socket", "/a/b"}).Draw(t, "path")
		// Digit-bearing markers keep the secrets from colliding with host/path.
		user := rapid.SampledFrom([]string{"", "u5er", "u5er:p4ssword"}).Draw(t, "user")
		query := rapid.SampledFrom([]string{"", "t0ken=s3cret", "a=1&b=2"}).Draw(t, "query")

		raw := scheme + "://"
		if user != "" {
			raw += user + "@"
		}
		raw += host + path
		if query != "" {
			raw += "?" + query
		}

		got := sanitizeURL(raw)

		if _, err := url.Parse(raw); err != nil {
			if got != "[invalid URL]" {
				t.Fatalf("sanitizeURL(%q) = %q, want %q", raw, got, "[invalid URL]")
			}
			return
		}

		if got == "" {
			t.Fatalf("sanitizeURL(%q) returned empty string", raw)
		}
		if query != "" {
			if strings.Contains(got, query) {
				t.Fatalf("sanitizeURL(%q) = %q leaks raw query", raw, got)
			}
			if !strings.Contains(got, "?***") {
				t.Fatalf("sanitizeURL(%q) = %q, want masked query", raw, got)
			}
		}
		if user != "" {
			if !strings.Contains(got, "%2A%2A%2A@") && !strings.Contains(got, "***@") {
				t.Fatalf("sanitizeURL(%q) = %q, want masked userinfo", raw, got)
			}
			if strings.Contains(got, user) {
				t.Fatalf("sanitizeURL(%q) = %q leaks userinfo", raw, got)
			}
			if pass, ok := strings.CutPrefix(user, "u5er:"); ok && strings.Contains(got, pass) {
				t.Fatalf("sanitizeURL(%q) = %q leaks password", raw, got)
			}
		}
		if !strings.Contains(got, host) {
			t.Fatalf("sanitizeURL(%q) = %q dropped host %q", raw, got, host)
		}
	})
}

func TestPropCliToWebSocketURL(t *testing.T) {
	// The suffix alphabet excludes '/', so a masked-out "http://" can never
	// reappear from the caller-supplied remainder.
	suffix := rapid.StringMatching(`[a-z0-9.:-]{0,20}`)
	prefixes := []string{
		"",
		"http://", "HTTP://", "HtTp://",
		"https://", "HTTPS://", "HtTpS://",
		"ws://", "WS://", "Ws://",
		"wss://", "WSS://", "WsS://",
	}

	t.Run("insecure", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			raw := rapid.SampledFrom(prefixes).Draw(t, "prefix") + suffix.Draw(t, "suffix")
			got, err := toWebSocketURL(raw, true)
			if err != nil {
				t.Fatalf("toWebSocketURL(%q, true) unexpected error: %v", raw, err)
			}
			if !strings.HasPrefix(got, "ws://") && !strings.HasPrefix(got, "wss://") {
				t.Fatalf("toWebSocketURL(%q, true) = %q, want ws:// or wss:// prefix", raw, got)
			}
			if strings.Contains(got, "http://") || strings.Contains(got, "https://") {
				t.Fatalf("toWebSocketURL(%q, true) = %q still carries an http scheme", raw, got)
			}
		})
	})

	t.Run("secure", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			prefix := rapid.SampledFrom(prefixes).Draw(t, "prefix")
			raw := prefix + suffix.Draw(t, "suffix")
			got, err := toWebSocketURL(raw, false)
			lowerPrefix := strings.ToLower(prefix)
			plaintext := lowerPrefix == "http://" || lowerPrefix == "ws://"
			if plaintext {
				if err == nil {
					t.Fatalf("toWebSocketURL(%q, false) = %q, want plaintext rejection", raw, got)
				}
				if got != "" {
					t.Fatalf("toWebSocketURL(%q, false) returned %q alongside error", raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("toWebSocketURL(%q, false) unexpected error: %v", raw, err)
			}
			if !strings.HasPrefix(got, "wss://") {
				t.Fatalf("toWebSocketURL(%q, false) = %q, want wss:// prefix", raw, got)
			}
		})
	})
}
