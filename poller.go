// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

// defaultResultSpoolBytes backs the byte-bounded spool when the runtime
// configuration has not been resolved (package-level tests).
const defaultResultSpoolBytes = 64 << 20

// resultSpoolByteLimit resolves the configured --result-spool-bytes budget.
func resultSpoolByteLimit() int64 {
	limit := int64(agentRuntimeSettings().ResultSpoolBytes)
	if limit <= 0 {
		return defaultResultSpoolBytes
	}
	return limit
}

// disconnectGracePeriod resolves the configured --disconnect-grace window.
func disconnectGracePeriod() time.Duration {
	grace := agentRuntimeSettings().DisconnectGrace
	if grace <= 0 {
		return 15 * time.Minute
	}
	return grace
}

// processPoller owns the recurring inventory, scheduler and worker pools at
// process level (C1/D2). A WebSocket session is only a transport: when it
// drops, the poller keeps polling and spooling results for the configured
// grace period. When the grace expires the schedule is cancelled, the pools
// drain, and their credential-bearing payloads are released; the next
// successful join rebuilds them from the server's full sync.
//
// The result spool is intentionally NOT owned here: it is process-wide and
// survives poller replacement so results finished before the grace expiry are
// still replayed on reconnect.
type processPoller struct {
	agentCtx  context.Context
	workCtx   context.Context
	cancel    context.CancelFunc
	pools     *jobPools
	scheduler *recurringScheduler

	attached atomic.Bool
	stopped  atomic.Bool

	graceMu    sync.Mutex
	graceTimer *time.Timer

	// stopDone closes once stop has drained the pools and scheduler.
	stopDone chan struct{}
	stopOnce sync.Once
	// maintainDone closes once the SNMP session maintenance goroutine saw
	// the stop and will not touch a session again.
	maintainDone chan struct{}
}

func newProcessPoller(
	agentCtx context.Context,
	results *resultQueue,
	localScheduling bool,
) *processPoller {
	ctx, cancel := context.WithCancel(agentCtx)
	notices := make(chan outbound, overloadNoticeQueueSize)
	pools := &jobPools{
		snmp:            newWorkerPool(snmpPoolSize()),
		mikrotik:        newWorkerPool(mikrotikPoolSize()),
		ping:            newWorkerPool(pingPoolSize()),
		checks:          newWorkerPool(checksPoolSize()),
		backup:          newWorkerPool(backupPoolSize()),
		ubnt:            newWorkerPool(ubntPoolSize()),
		notices:         notices,
		targets:         &targetGates{},
		localScheduling: localScheduling,
	}
	scheduler := newRecurringScheduler(ctx, realScheduleClock{})
	pools.scheduler = scheduler
	pools.pingEngine = newPingEngine(ctx)
	pools.pingEngine.start()
	poller := &processPoller{
		agentCtx:     agentCtx,
		workCtx:      ctx,
		cancel:       cancel,
		pools:        pools,
		scheduler:    scheduler,
		stopDone:     make(chan struct{}),
		maintainDone: make(chan struct{}),
	}
	installPoolLoadSnapshotHook(pools)
	poller.startSNMPMaintenance()
	return poller
}

// startSNMPMaintenance expires idle SNMP device sessions periodically while
// the poller owns scheduled work, and closes every session when the poller
// stops (grace expiry or process shutdown).
func (p *processPoller) startSNMPMaintenance() {
	go func() {
		ticker := time.NewTicker(snmpSessionMaintenanceInterval)
		defer ticker.Stop()
		for {
			select {
			case <-p.workCtx.Done():
				close(p.maintainDone)
				return
			case <-ticker.C:
				expireSNMPSessions(time.Now())
			}
		}
	}()
}

// snmpSessionMaintenanceInterval bounds how long an unused SNMP device
// session can stay open past its idle expiry.
var snmpSessionMaintenanceInterval = 30 * time.Second

// Pool sizing follows the runtime flags; zero means the historical defaults.
func snmpPoolSize() int {
	if size := int(agentRuntimeSettings().SNMPConcurrency); size > 0 {
		return size
	}
	return 100
}

func mikrotikPoolSize() int {
	if size := int(agentRuntimeSettings().MikrotikConcurrency); size > 0 {
		return size
	}
	return 20
}

func pingPoolSize() int {
	if size := int(agentRuntimeSettings().PingConcurrency); size > 0 {
		return size
	}
	return 50
}

func checksPoolSize() int {
	if size := int(agentRuntimeSettings().CheckConcurrency); size > 0 {
		return size
	}
	return 50
}

func backupPoolSize() int { return 8 }

// UBNT discovery is a bounded UDP collection window: two workers is plenty
// for sweeps that finish in a few seconds each.
func ubntPoolSize() int { return 2 }

// connected cancels a pending grace expiry: a live session owns the poller.
func (p *processPoller) connected() {
	p.graceMu.Lock()
	if p.graceTimer != nil {
		p.graceTimer.Stop()
		p.graceTimer = nil
	}
	p.graceMu.Unlock()
	p.attached.Store(true)
}

// disconnected starts the disconnect grace countdown. Called only after a
// session that used the poller ended; the next session can still attach and
// cancel the timer. A countdown already running keeps counting: the retry
// loop calls this after every failed attempt, so re-arming here would let
// the grace never expire while the agent keeps trying (issue 5150).
func (p *processPoller) disconnected() {
	if !p.attached.Load() {
		return
	}
	grace := disconnectGracePeriod()
	p.graceMu.Lock()
	defer p.graceMu.Unlock()
	if p.graceTimer != nil {
		return
	}
	p.graceTimer = time.AfterFunc(grace, func() {
		slog.Warn("disconnect grace expired, stopping scheduled polling",
			"grace", grace)
		p.stop()
	})
}

// applyInventoryUpdate is the only mutation path for the recurring inventory
// once the poller is built. Sessions decode asynchronously and call this from
// the session loop; the scheduler guards against a closed or paused state.
func (p *processPoller) applyInventoryUpdate(update *pb.AgentInventoryUpdate, out *resultQueue) {
	if p == nil || p.stopped.Load() || update == nil {
		return
	}
	applyInventoryUpdate(p.pools, p.scheduler, update, out)
}

func (p *processPoller) stop() {
	p.stopOnce.Do(func() {
		p.graceMu.Lock()
		if p.graceTimer != nil {
			p.graceTimer.Stop()
			p.graceTimer = nil
		}
		p.graceMu.Unlock()
		p.stopped.Store(true)
		p.attached.Store(false)
		installPoolLoadSnapshotHook(nil)
		// End scheduled work, then drain the pools so in-flight jobs and
		// their credential-bearing closures finish before this function
		// returns. cancelAll clears the job/check maps; the pool drain is
		// what guarantees no job payload is still reachable by a worker.
		p.cancel()
		if p.scheduler != nil {
			p.scheduler.cancelAll()
		}
		deadline := time.Now().Add(poolShutdownTimeout)
		if p.pools != nil {
			for _, name := range p.pools.stop(time.Until(deadline)) {
				slog.Warn("poller pool shutdown timed out, abandoning in-flight jobs",
					"pool", name)
			}
		}
		if p.scheduler != nil {
			remaining := time.Until(deadline)
			if remaining <= 0 || !p.scheduler.wait(remaining) {
				slog.Warn("poller scheduler shutdown timed out")
			}
		}
		releaseInventoryAssembler(p.pools)
		// Maintenance stops on stopDone; only now can no worker still hold
		// an SNMP device session, so close them all. The poller's own ping
		// engine drains live and queued jobs as part of this teardown, so no
		// ping done callback is left behind for the next poller.
		<-p.maintainDone
		closeSNMPSessions()
		if p.pools != nil && p.pools.pingEngine != nil {
			p.pools.pingEngine.shutdown()
		}
		close(p.stopDone)
	})
}
