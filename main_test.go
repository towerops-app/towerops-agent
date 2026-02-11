package main

import "testing"

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
