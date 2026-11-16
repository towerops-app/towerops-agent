// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"sync/atomic"
)

// inventoryAvgDeviceBytes is the measured encoded-inventory cost of one
// recurring device, refreshed by every authoritative inventory the agent
// applies. The initial estimate is the measured fleet figure behind issue
// A2 (~9,048 bytes per device).
var inventoryAvgDeviceBytes atomic.Uint64

func init() {
	inventoryAvgDeviceBytes.Store(estimatedInventoryDeviceBytes)
}

// noteInventoryFootprint records the encoded size of an authoritative
// inventory and the device count it covered, so capacity reporting follows
// the deployment's real payload shape (compact OID columns count for their
// encoded size, not their expanded poll cost).
func noteInventoryFootprint(devices int, encodedBytes int) {
	if devices <= 0 || encodedBytes <= 0 {
		return
	}
	perDevice := uint64(encodedBytes) / uint64(devices)
	if perDevice == 0 {
		perDevice = 1
	}
	inventoryAvgDeviceBytes.Store(perDevice)
}

// inventoryCapacityDevices estimates how many recurring devices of the
// deployment's measured payload size still fit the agent's decoded-frame
// memory bound (the same bound that rejects an oversized inventory frame).
// The value saturates at uint32, the wire type of the heartbeat field.
func inventoryCapacityDevices() uint64 {
	perDevice := inventoryAvgDeviceBytes.Load()
	if perDevice == 0 {
		perDevice = estimatedInventoryDeviceBytes
	}
	return uint64(maxDecodedJobPayloadBytes) / perDevice
}

// installPoolLoadSnapshotHook publishes the poller's pool stats through the
// parent-owned hook the heartbeat and debug listener consume.
func installPoolLoadSnapshotHook(pools *jobPools) {
	if pools == nil {
		poolLoadSnapshotHook.Store(nil)
		return
	}
	snapshot := func() []poolLoadSnapshot { return pools.loadSnapshots() }
	poolLoadSnapshotHook.Store(&snapshot)
}

// heartbeatMetrics composes the process counter snapshot with the active
// spool, pool and inventory-capacity figures the heartbeat reports.
func heartbeatMetrics(results *resultQueue) metricsSnapshot {
	snapshot := processMetrics.snapshot()
	snapshot.Pools = poolLoadSnapshots()
	if results != nil {
		snapshot.SpoolDepth = results.depth.Load()
		snapshot.SpoolBytes = uint64(results.byteUsage.Load())
		// The configured cap travels with the usage so the server can flag a
		// spool at or past 90% of its limit (S5); without it the near/full
		// signals have no denominator and never fire.
		snapshot.SpoolLimit = uint64(results.byteLimit)
	}
	snapshot.InventoryCapacity = inventoryCapacityDevices()
	return snapshot
}
