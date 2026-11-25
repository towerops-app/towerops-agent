package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

// jobPools holds the worker pools for each job type and the per-target
// semaphores that serialize jobs for the same device across all of them.
type jobPools struct {
	snmp            *workerPool
	mikrotik        *workerPool
	ping            *workerPool
	checks          *workerPool
	backup          *workerPool
	ubnt            *workerPool
	notices         chan outbound
	scheduler       *recurringScheduler
	targets         *targetGates
	localScheduling bool
	// pingEngine is owned by this poller: it starts in newProcessPoller and
	// is shut down inside stop(), so a rebuilt poller never shares an engine
	// with the one still draining.
	pingEngine *pingEngine

	// stopAccepting is set during a self-update drain so the session refuses
	// new job and check submissions while the spool flushes. In-flight work
	// keeps running so its results can still reach the spool.
	stopAccepting atomic.Bool

	// Inventory reconciliation state (issue #2755): the newest authoritative
	// inventory revision the agent applied and the name of the last
	// inventory frame it refused. Both ride the heartbeat so the server can
	// re-push a schedule that never landed instead of paging overdue on
	// every device the missed frame covered.
	appliedRevision   atomic.Uint64
	rejectedInventory atomic.Value // string; "" means nothing outstanding
}

// loadSnapshots samples every pool for the heartbeat and the debug page.
func (p *jobPools) loadSnapshots() []poolLoadSnapshot {
	if p == nil {
		return nil
	}
	definitions := []struct {
		name string
		pool *workerPool
	}{
		{"snmp", p.snmp}, {"mikrotik", p.mikrotik}, {"ping", p.ping},
		{"checks", p.checks}, {"backup", p.backup}, {"ubnt", p.ubnt},
	}
	loads := make([]poolLoadSnapshot, 0, len(definitions))
	for _, definition := range definitions {
		if definition.pool == nil {
			continue
		}
		stats := definition.pool.stats()
		loads = append(loads, poolLoadSnapshot{
			Name:   definition.name,
			Busy:   uint64(stats.Busy),
			Queued: uint64(stats.Queued),
		})
	}
	return loads
}

// idle reports whether every pool has finished all admitted work.
func (p *jobPools) idle() bool {
	for _, pool := range p.all() {
		if pool != nil && !pool.idle() {
			return false
		}
	}
	return true
}

// pause stops every pool from admitting new work; see workerPool.pause.
func (p *jobPools) pause() {
	for _, pool := range p.all() {
		if pool != nil {
			pool.pause()
		}
	}
}

func (p *jobPools) all() []*workerPool {
	return []*workerPool{p.snmp, p.mikrotik, p.ping, p.checks, p.backup, p.ubnt}
}

func (p *jobPools) stop(timeout time.Duration) []string {
	pools := map[string]*workerPool{
		"snmp": p.snmp, "mikrotik": p.mikrotik, "ping": p.ping, "checks": p.checks,
		"backup": p.backup, "ubnt": p.ubnt,
	}
	done := make(chan string, len(pools))
	for name, pool := range pools {
		if pool == nil {
			// Partially-constructed pools (tests) have nothing to drain.
			done <- name
			continue
		}
		go func() {
			pool.stop()
			done <- name
		}()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for len(pools) > 0 {
		select {
		case name := <-done:
			delete(pools, name)
		case <-timer.C:
			timedOut := make([]string, 0, len(pools))
			for name := range pools {
				timedOut = append(timedOut, name)
			}
			slices.Sort(timedOut)
			return timedOut
		}
	}
	return nil
}

// applyInventoryRevision records the newest authoritative inventory revision
// the agent accepted (issue #2755). Jobs and check_jobs share one revision
// stream, so the stamp is monotonic per connection and a replayed or
// reordered frame can only move it forward. The refused-frame marker is
// cleared only when the refused frame type itself applies: otherwise a
// successful apply of the other type would report the refused stream as
// reconciled and the server would never re-push it. While a refusal is
// outstanding the applied stamp is held back entirely, keeping the server's
// re-push logic (applied_revision trailing what it sent) active.
func (p *jobPools) applyInventoryRevision(event string, revision uint64) {
	if revision == 0 {
		return
	}
	rejected, _ := p.rejectedInventory.Load().(string)
	if rejected != "" && rejected != event {
		// A different frame type is still refused. Do not advance the stamp:
		// reporting this apply as reconciliation would tell the server the
		// refused stream landed when it never did.
		return
	}
	for {
		current := p.appliedRevision.Load()
		if revision <= current {
			break
		}
		if p.appliedRevision.CompareAndSwap(current, revision) {
			break
		}
	}
	if rejected != "" {
		p.rejectedInventory.Store("")
	}
}

// rejectInventory marks an authoritative inventory frame ("jobs" or
// "check_jobs") as refused: it arrived during the self-update drain or its
// payload failed to decode. The next heartbeat reports the name so the
// server records the refusal instead of silently re-pushing on a schedule
// it believes landed (issue #2755).
func (p *jobPools) rejectInventory(event string) {
	if event == "" {
		return
	}
	p.rejectedInventory.Store(event)
}

// dispatchJob routes a one-shot job to the appropriate worker pool.
func dispatchJob(
	ctx context.Context,
	job *pb.AgentJob,
	pools *jobPools,
	out *resultQueue,
) {
	_ = submitJob(ctx, job, pools, out, func() {}, false)
}

func submitJob(
	ctx context.Context,
	job *pb.AgentJob,
	pools *jobPools,
	out *resultQueue,
	done func(),
	wait bool,
) bool {
	if pools.stopAccepting.Load() {
		slog.Debug("job submission refused during self-update drain", "job_id", job.JobId)
		done()
		return false
	}
	slog.Debug("starting job", "job_id", job.JobId, "type", job.JobType)

	if job.JobType == pb.JobType_CONFIG_BACKUP {
		return submitConfigBackupJob(ctx, job, pools, out, done, wait)
	}

	task := func(execute func()) func() {
		return func() {
			defer done()
			if ctx.Err() != nil {
				return
			}
			// The "run" count lives here alone: executors record failure and
			// partial outcomes but must never count the run, or a poll counts
			// twice (issue 5168).
			recordJobRun()
			execute()
		}
	}

	var pool *workerPool
	var execute func()
	switch job.JobType {
	case pb.JobType_MIKROTIK:
		pool = pools.mikrotik
		execute = func() { executeMikrotikJob(ctx, job, out) }
	case pb.JobType_TEST_CREDENTIALS:
		pool = pools.snmp
		execute = func() { executeCredentialTest(ctx, job, out) }
	case pb.JobType_CREDENTIAL_PROBE:
		pool = pools.snmp
		execute = func() { executeCredentialProbe(ctx, job, out) }
	case pb.JobType_UBNT_DISCOVERY:
		// UDP broadcast, not SNMP: a dedicated small pool keeps a stuck
		// collection window from holding an SNMP worker.
		pool = pools.ubnt
		execute = func() { executeUbntDiscovery(ctx, job, out) }
	case pb.JobType_PING:
		// Pings run on the shared ICMP engine instead of holding a worker
		// for each timeout window. The worker closure returns as soon as the
		// engine admits the round; the target gate is released by the
		// engine's completion callback, so one target's active round still
		// serializes later jobs without occupying a worker while ICMP waits.
		if ctx.Err() != nil || pools.ping.refusing() {
			done()
			return false
		}
		pools.ping.dispatchGated(ctx, ctx, pools.targets, jobTargetKey(job),
			dispatchJitter(),
			func(release func()) {
				if pools.pingEngine == nil || !submitPingJob(ctx, pools.pingEngine, job, out, func() {
					release()
					done()
				}) {
					release()
					reportPoolRejection(ctx, pools.notices, job.DeviceId, job.JobId, job.JobType.String())
					done()
				}
			},
			func(reason dispatchFailure) {
				if reason != dispatchCancelled {
					reportPoolRejection(ctx, pools.notices, job.DeviceId, job.JobId, job.JobType.String())
				}
				done()
			})
		return true
	case pb.JobType_DISCOVER, pb.JobType_POLL:
		pool = pools.snmp
		execute = func() { executeSnmpJob(ctx, job, out) }
	default:
		reportUnsupportedJob(ctx, pools.notices, job)
		done()
		return false
	}

	target := jobTargetKey(job)

	if wait {
		// Recurring schedulers already run one goroutine per assignment, so
		// acquiring the gate here costs that goroutine, not a pool worker —
		// and the blocked wait is itself the backpressure that stops stale
		// polls of a dead device from piling up and later running back-to-back.
		jitterDispatch(ctx, dispatchJitter())
		release := pools.targets.acquire(ctx, target)
		if release == nil {
			done()
			return false
		}
		if !pool.submitMode(ctx, func() { defer release(); task(execute)() }, true) {
			release()
			// A paused pool is a drain refusal, not saturation.
			if !pool.paused.Load() {
				reportPoolRejection(ctx, pools.notices, job.DeviceId, job.JobId, job.JobType.String())
			}
			done()
			return false
		}
		return true
	}

	// The one-shot path cannot block the session event loop, so jitter and
	// the gate wait run off it in dispatchGated. Only jobs parked on a busy
	// target hold a dispatch slot; an uncontended job is refused only when the
	// pool queue is genuinely full. The jitter is read here — the coordinator
	// reads no package globals, which keeps tests that restore
	// dispatchJitterMax race-free.
	pool.dispatchGated(ctx, ctx, pools.targets, target, dispatchJitter(),
		func(release func()) { defer release(); task(execute)() },
		func(reason dispatchFailure) {
			if reason != dispatchCancelled {
				reportPoolRejection(ctx, pools.notices, job.DeviceId, job.JobId, job.JobType.String())
			}
			done()
		})
	return true
}

// submitConfigBackupJob dispatches a CONFIG_BACKUP job with its own deadline.
// Unlike the shared path, the job context is created at dispatch — the server
// starts its dispatch sweep when the job is sent, so the pool queue, the
// jitter delay, and the per-target gate all count against the same budget as
// the SSH work. A job that burns its budget waiting for the gate still reports
// TIMEOUT rather than never answering.
func submitConfigBackupJob(
	ctx context.Context,
	job *pb.AgentJob,
	pools *jobPools,
	out *resultQueue,
	done func(),
	wait bool,
) bool {
	jobCtx, cancel := context.WithTimeout(ctx, configBackupTimeout(job))
	report := func(code pb.ConfigBackupErrorCode, detail string) {
		sendResult(ctx, out, "config_backup_result", &pb.ConfigBackupResult{
			DeviceId:    job.DeviceId,
			JobId:       job.JobId,
			ErrorCode:   code,
			ErrorDetail: detail,
			Timestamp:   time.Now().Unix(),
		}, job.JobId)
		slog.Warn("config backup not completed",
			"job_id", job.JobId,
			"device_id", job.DeviceId,
			"error_code", code.String(),
			"detail", detail,
		)
	}

	// Read the jitter here, not inside the coordinator: it must not touch
	// package globals that tests restore from cleanup.
	delay := dispatchJitter()
	key := jobTargetKey(job)
	task := func(release func()) {
		defer release()
		defer done()
		defer cancel()
		executeConfigBackupJobCtx(ctx, jobCtx, job, out)
	}

	if wait {
		// Recurring backups run on their scheduler goroutine like submitJob's
		// wait path: the jitter, gate and queue waits are the backpressure,
		// so a busy dispatcher delays the backup instead of failing it.
		jitterDispatch(jobCtx, delay)
		release := pools.targets.acquire(jobCtx, key)
		if release == nil {
			cancel()
			report(pb.ConfigBackupErrorCode_TIMEOUT, "job deadline expired waiting for the device")
			done()
			return false
		}
		if !pools.backup.submitMode(jobCtx, func() { task(release) }, true) {
			release()
			timedOut := errors.Is(jobCtx.Err(), context.DeadlineExceeded)
			cancel()
			if timedOut {
				report(pb.ConfigBackupErrorCode_TIMEOUT, "job deadline expired waiting for a worker")
			} else {
				report(pb.ConfigBackupErrorCode_AGENT_BUSY, "")
			}
			done()
			return false
		}
		return true
	}

	// The gate is acquired by the coordinator rather than a worker, so a
	// device already mid-backup doesn't pin a backup-pool slot other devices
	// could use.
	pools.backup.dispatchGated(jobCtx, ctx, pools.targets, key, delay, task,
		func(reason dispatchFailure) {
			cancel()
			switch reason {
			case dispatchCancelled:
				report(pb.ConfigBackupErrorCode_TIMEOUT, "job deadline expired waiting for the device")
			case dispatchBacklogged:
				report(pb.ConfigBackupErrorCode_AGENT_BUSY, "backup dispatcher saturated")
			default:
				report(pb.ConfigBackupErrorCode_AGENT_BUSY, "")
			}
			done()
		})
	return true
}

// jobTargetKey identifies the device a job runs against so jobs for the same
// target serialize. The device IP is preferred; jobs without one fall back to
// the server-assigned device ID, then the job ID. The key is per protocol,
// not per job type: every SNMP job (POLL, DISCOVER, CREDENTIAL_PROBE,
// TEST_CREDENTIALS) shares the bare key so a device never serves two SNMP
// walks at once. PING (ICMP), CONFIG_BACKUP (SSH) and MIKROTIK (RouterOS API)
// each get a namespace — a stalled poll must not delay the outage signal a
// ping delivers, and a backup queued behind a running poll can wait out the
// poll's whole deadline, longer than the backup's dispatch budget.
func jobTargetKey(job *pb.AgentJob) string {
	prefix := ""
	switch job.JobType {
	case pb.JobType_PING:
		prefix = "ping:"
	case pb.JobType_CONFIG_BACKUP:
		prefix = "config_backup:"
	case pb.JobType_MIKROTIK:
		prefix = "mikrotik:"
	}
	if job.SnmpDevice != nil && job.SnmpDevice.Ip != "" {
		return prefix + hostPortKey(job.SnmpDevice.Ip, job.SnmpDevice.Port)
	}
	if job.MikrotikDevice != nil && job.MikrotikDevice.Ip != "" {
		return prefix + hostPortKey(job.MikrotikDevice.Ip, job.MikrotikDevice.Port)
	}
	if job.ConfigBackup != nil && job.ConfigBackup.Host != "" {
		return prefix + hostPortKey(job.ConfigBackup.Host, job.ConfigBackup.SshPort)
	}
	// Probe jobs carry the target in their candidates (snmp_device is nil):
	// key on the shared address so a probe cannot run concurrently with a
	// poll or discovery on the same device.
	if job.CredentialProbe != nil && len(job.CredentialProbe.Candidates) > 0 &&
		job.CredentialProbe.Candidates[0].Ip != "" {
		candidate := job.CredentialProbe.Candidates[0]
		return prefix + hostPortKey(candidate.Ip, candidate.Port)
	}
	// UBNT jobs sweep a broadcast domain: key on the destination so two
	// concurrent sweeps of the same domain serialize instead of doubling
	// replies, while different domains run in parallel.
	if job.UbntDiscovery != nil {
		dest := job.UbntDiscovery.Target
		if dest == "" {
			dest = job.UbntDiscovery.BroadcastAddress
		}
		if dest != "" {
			return "ubnt:" + hostPortKey(dest, job.UbntDiscovery.Port)
		}
	}
	if job.DeviceId != "" {
		return prefix + "device:" + job.DeviceId
	}
	return prefix + "job:" + job.JobId
}

// hostPortKey folds a non-default destination port into the target identity.
// Two devices behind the same NAT address on different ports are different
// targets; serializing them behind one gate is unnecessary and, for the load
// harness, fatal on platforms without a 127/8 loopback alias for each device.
func hostPortKey(host string, port uint32) string {
	if port == 0 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func reportUnsupportedJob(ctx context.Context, notices chan<- outbound, job *pb.AgentJob) {
	jobType := strconv.FormatInt(int64(job.JobType), 10)
	slog.Error("job dropped, unknown job type", "job_id", job.JobId, "type", jobType)
	reportJobRejection(
		ctx,
		notices,
		job.DeviceId,
		job.JobId,
		jobType,
		"unsupported job type "+jobType,
	)
}

func reportPoolRejection(
	ctx context.Context,
	notices chan<- outbound,
	deviceID, jobID, jobType string,
) {
	message := "worker pool overloaded; retry " + jobType + " job"
	slog.Warn("job rejected, pool full", "job_id", jobID, "type", jobType)
	reportJobRejection(ctx, notices, deviceID, jobID, jobType, message)
}

func reportJobRejection(
	ctx context.Context,
	notices chan<- outbound,
	deviceID, jobID, jobType, message string,
) {
	if ctx.Err() != nil {
		slog.Debug("job rejected, session ended", "job_id", jobID, "type", jobType)
		return
	}
	notice, ok := encodeOutbound("error", &pb.AgentError{
		DeviceId:  deviceID,
		JobId:     jobID,
		Message:   message,
		Timestamp: time.Now().Unix(),
	}, jobID)
	if !ok {
		return
	}
	select {
	case notices <- notice:
	default:
		slog.Warn("job rejection notice queue full, notification dropped", "job_id", jobID, "type", jobType)
	}
}

func submitCheck(
	ctx context.Context,
	check *pb.Check,
	pools *jobPools,
	out *resultQueue,
	done func(),
	wait bool,
) bool {
	if pools.stopAccepting.Load() {
		slog.Debug("check submission refused during self-update drain", "check", check.Id)
		done()
		return false
	}
	ok := pools.checks.submitMode(ctx, func() {
		defer done()
		if ctx.Err() != nil {
			return
		}
		result := ExecuteCheck(ctx, check)
		recordJobRun()
		if result.Status != checkOK {
			recordJobFailure()
		}
		slog.Debug("check complete", "check", result.CheckId, "status", result.Status)
		sendResult(ctx, out, "check_result", result, check.Id)
	}, wait)
	if !ok {
		// A paused pool is a drain refusal, not saturation.
		if !pools.checks.paused.Load() {
			reportPoolRejection(ctx, pools.notices, "", check.Id, "CHECK")
		}
		done()
	}
	return ok
}
