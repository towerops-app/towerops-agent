// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"testing"
	"time"
)

func TestParseContainerMemoryLimit(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  int64
		ok    bool
	}{
		{name: "v2 unlimited", value: "max\n", ok: false},
		{name: "empty", value: "", ok: false},
		{name: "invalid", value: "lots", ok: false},
		{name: "invalid negative", value: "-1", ok: false},
		{name: "v1 unlimited sentinel", value: "9223372036854771712", ok: false},
		{name: "container budget", value: "536870912\n", want: 536870912, ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseContainerMemoryLimit(tt.value)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("parseContainerMemoryLimit(%q) = (%d, %t), want (%d, %t)", tt.value, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestEnvDuration(t *testing.T) {
	t.Setenv("TOWEROPS_TEST_GRACE", "2m30s")
	if got := envDuration(time.Minute, "TOWEROPS_TEST_GRACE"); got != 150*time.Second {
		t.Fatalf("envDuration valid = %s, want 2m30s", got)
	}
	t.Setenv("TOWEROPS_TEST_GRACE", "not-a-duration")
	if got := envDuration(time.Minute, "TOWEROPS_TEST_GRACE"); got != time.Minute {
		t.Fatalf("envDuration invalid = %s, want fallback", got)
	}
	t.Setenv("TOWEROPS_TEST_GRACE", "-5m")
	if got := envDuration(time.Minute, "TOWEROPS_TEST_GRACE"); got != time.Minute {
		t.Fatalf("envDuration negative = %s, want fallback", got)
	}
}

func TestAgentRuntimeSettingsDefaults(t *testing.T) {
	settings := agentRuntimeSettings()
	if settings.SNMPDeviceRate != 50 || settings.ResultSpoolBytes != 64<<20 || settings.DisconnectGrace != 15*time.Minute {
		t.Fatalf("default runtime settings = %+v", settings)
	}
}
