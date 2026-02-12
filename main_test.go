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

func TestToWebSocketURL(t *testing.T) {
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
