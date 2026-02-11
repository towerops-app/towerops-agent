package main

import (
	"encoding/json"
	"testing"
)

func TestPhoenixMsgSerialization(t *testing.T) {
	msg := phoenixMsg{
		Topic:   "agent:123",
		Event:   "phx_join",
		Payload: json.RawMessage(`{"token":"test"}`),
		Ref:     strPtr("1"),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)
	checks := []string{"agent:123", "phx_join", "token", "test"}
	for _, c := range checks {
		if !contains(s, c) {
			t.Errorf("expected %q in JSON output %q", c, s)
		}
	}
}

func TestPhoenixMsgDeserialization(t *testing.T) {
	raw := `{"topic":"agent:123","event":"phx_reply","payload":{"status":"ok"},"ref":"1"}`
	var msg phoenixMsg
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Topic != "agent:123" {
		t.Errorf("topic: got %q, want %q", msg.Topic, "agent:123")
	}
	if msg.Event != "phx_reply" {
		t.Errorf("event: got %q, want %q", msg.Event, "phx_reply")
	}
	if msg.Ref == nil || *msg.Ref != "1" {
		t.Errorf("ref: got %v, want %q", msg.Ref, "1")
	}
}

func TestPhoenixMsgNullRef(t *testing.T) {
	raw := `{"topic":"agent:123","event":"job","payload":{},"ref":null}`
	var msg phoenixMsg
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Ref != nil {
		t.Errorf("expected nil ref, got %q", *msg.Ref)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
