// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// agentRuntimeConfig contains process-wide limits resolved from flags and the
// environment. It is immutable after startup; tests replace it before starting
// an agent or scheduler.
type agentRuntimeConfig struct {
	SNMPConcurrency     uint
	PingConcurrency     uint
	CheckConcurrency    uint
	MikrotikConcurrency uint
	SNMPDeviceRate      uint
	ResultSpoolBytes    uint
	DisconnectGrace     time.Duration
	DebugListen         string
}

var runtimeSettings = struct {
	sync.RWMutex
	config agentRuntimeConfig
}{config: agentRuntimeConfig{
	SNMPDeviceRate:   50,
	ResultSpoolBytes: 64 << 20,
	DisconnectGrace:  15 * time.Minute,
}}

func configureAgentRuntime(config agentRuntimeConfig) {
	runtimeSettings.Lock()
	runtimeSettings.config = config
	runtimeSettings.Unlock()
}

func agentRuntimeSettings() agentRuntimeConfig {
	runtimeSettings.RLock()
	defer runtimeSettings.RUnlock()
	return runtimeSettings.config
}

// configureMemoryLimit lets the Go collector use most of a container's memory
// before collecting more aggressively. An explicit GOMEMLIMIT remains
// authoritative and is already applied by the runtime before this function.
func configureMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		data, err := readCgroupFile(path)
		if err != nil {
			continue
		}
		if limit, ok := parseContainerMemoryLimit(string(data)); ok {
			debug.SetMemoryLimit(limit * 9 / 10)
			return
		}
	}
}

// readCgroupFile reads a container memory-limit pseudo-file. Tests stub it
// since cgroup v1/v2 files do not exist on developer workstations.
var readCgroupFile = os.ReadFile

func parseContainerMemoryLimit(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" || value == "max" {
		return 0, false
	}
	limit, err := strconv.ParseInt(value, 10, 64)
	// cgroup v1 reports a very large sentinel on unlimited hosts. Values at or
	// above 1 EiB are not actionable container budgets.
	if err != nil || limit <= 0 || limit >= 1<<60 {
		return 0, false
	}
	return limit, true
}
