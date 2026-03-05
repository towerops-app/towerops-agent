package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestToWebSocketURL(t *testing.T) {
	origInsecure := insecureFlag
	defer func() { insecureFlag = origInsecure }()
	insecureFlag = true

	tests := []struct {
		input, want string
	}{
		{"http://localhost:4000", "ws://localhost:4000"},
		{"https://towerops.net", "wss://towerops.net"},
		{"ws://localhost:4000", "ws://localhost:4000"},
		{"wss://towerops.net", "wss://towerops.net"},
		{"towerops.net", "wss://towerops.net"},
		{"localhost:4000", "wss://localhost:4000"},
	}
	for _, tt := range tests {
		got, err := toWebSocketURL(tt.input)
		if err != nil {
			t.Errorf("toWebSocketURL(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("toWebSocketURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestToWebSocketURLRejectsPlaintext(t *testing.T) {
	origInsecure := insecureFlag
	defer func() { insecureFlag = origInsecure }()
	insecureFlag = false

	tests := []struct {
		name  string
		input string
	}{
		{"ws:// scheme", "ws://localhost:4000"},
		{"http:// converts to ws://", "http://localhost:4000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := toWebSocketURL(tt.input)
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
