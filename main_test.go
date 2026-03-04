package main

import (
	"os"
	"testing"
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

func TestIsFlagSet(t *testing.T) {
	// In tests, flags are not set via flag.Parse on the default flag set
	// so isFlagSet should return false for any arbitrary name.
	if isFlagSet("nonexistent-flag-xyz") {
		t.Error("expected isFlagSet to return false for unset flag")
	}
}

func TestToWebSocketURL(t *testing.T) {
	// Enable insecure for testing plaintext conversions
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
		got := toWebSocketURL(tt.input)
		if got != tt.want {
			t.Errorf("toWebSocketURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestToWebSocketURLRejectsPlaintext(t *testing.T) {
	origInsecure := insecureFlag
	origExit := osExit
	defer func() {
		insecureFlag = origInsecure
		osExit = origExit
	}()

	insecureFlag = false
	exitCode := -1
	osExit = func(code int) { exitCode = code }

	tests := []struct {
		name  string
		input string
	}{
		{"ws:// scheme", "ws://localhost:4000"},
		{"http:// converts to ws://", "http://localhost:4000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode = -1
			toWebSocketURL(tt.input)
			if exitCode != 1 {
				t.Errorf("expected osExit(1), got %d", exitCode)
			}
		})
	}
}
