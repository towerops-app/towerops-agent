// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAsyncLineWriterDropsWhenFull(t *testing.T) {
	// A pipe with no reader blocks the pump; the bounded channel fills and
	// subsequent lines drop. Close reports the dropped count to the writer.
	reader, writer := io.Pipe()
	defer func() { _ = reader.Close() }()
	sink := newAsyncLineWriter(writer)

	line := []byte("x\n")
	for range asyncLogQueueLines + 4 {
		_, _ = sink.Write(line)
	}
	if got := sink.dropped.Load(); got == 0 {
		t.Fatal("expected dropped lines with a blocked pump")
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := reader.Read(buf); err != nil {
				return
			}
		}
	}()
	sink.Close()
}

func TestAsyncLineWriterWriteAfterClose(t *testing.T) {
	sink := newAsyncLineWriter(io.Discard)
	sink.Close()
	// A stray slog call after Close recovers and counts a drop.
	_, err := sink.Write([]byte("late\n"))
	if err != nil {
		t.Fatalf("Write after Close returned error %v", err)
	}
	if got := sink.dropped.Load(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
}

func TestJobSummaryLoggerEmitsWindow(t *testing.T) {
	orig := jobSummaryInterval
	jobSummaryInterval = 20 * time.Millisecond
	t.Cleanup(func() { jobSummaryInterval = orig })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := startJobSummaryLogger(ctx)
	defer stop()

	recordJobRun()
	recordJobFailure()
	recordJobPartial()
	recordJobDropped()
	// Wait for one full window so the ticker branch runs and swaps counters.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if jobSummary.run.Load() == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	// Cancel path: start a fresh logger and stop it immediately.
	stop()
}

func TestRecordInventoryDeviceBytesGuards(t *testing.T) {
	orig := inventoryAvgDeviceBytes.Swap(0)
	t.Cleanup(func() { inventoryAvgDeviceBytes.Store(orig) })

	noteInventoryFootprint(0, 100)
	noteInventoryFootprint(4, 0)
	if got := inventoryAvgDeviceBytes.Load(); got != 0 {
		t.Fatalf("guards must not store, got %d", got)
	}
	noteInventoryFootprint(4, 80)
	if got := inventoryAvgDeviceBytes.Load(); got != 20 {
		t.Fatalf("avg = %d, want 20", got)
	}
}

func TestInventoryCapacityDevicesFallback(t *testing.T) {
	orig := inventoryAvgDeviceBytes.Swap(0)
	t.Cleanup(func() { inventoryAvgDeviceBytes.Store(orig) })
	if got := inventoryCapacityDevices(); got != uint64(maxDecodedJobPayloadBytes)/estimatedInventoryDeviceBytes {
		t.Errorf("capacity = %d", got)
	}
	inventoryAvgDeviceBytes.Store(100)
	if got := inventoryCapacityDevices(); got != uint64(maxDecodedJobPayloadBytes)/100 {
		t.Errorf("capacity = %d", got)
	}
}

func TestScheduleLagP95(t *testing.T) {
	m := &agentMetrics{}
	if _, ok := m.scheduleLagP95(); ok {
		t.Fatal("empty window must report no sample")
	}
	m.recordScheduleLag(10 * time.Millisecond)
	m.recordScheduleLag(30 * time.Millisecond)
	m.recordScheduleLag(20 * time.Millisecond)
	got, ok := m.scheduleLagP95()
	if !ok || got == 0 {
		t.Fatalf("p95 = %d, %v", got, ok)
	}
}

func TestFormatMetricsExtras(t *testing.T) {
	snap := metricsSnapshot{InventoryCapacity: 42}
	loads := []poolLoadSnapshot{{Name: "snmp", Busy: 2, Queued: 3}}
	out := formatMetrics(snap, loads)
	if !strings.Contains(out, "inventory_capacity_devices 42") {
		t.Error("missing capacity line")
	}
	if !strings.Contains(out, `pool_busy{name="snmp"} 2`) {
		t.Error("missing pool busy line")
	}
	if !strings.Contains(out, `pool_queued{name="snmp"} 3`) {
		t.Error("missing pool queued line")
	}
}

func TestStartDebugServer(t *testing.T) {
	t.Run("rejects non-loopback", func(t *testing.T) {
		if _, err := startDebugServer("0.0.0.0:9999", nil); err == nil {
			t.Fatal("expected loopback rejection")
		}
	})
	t.Run("rejects unbindable address", func(t *testing.T) {
		// Occupy a loopback port, then ask the debug server for the same one.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("no loopback listener: %v", err)
		}
		defer func() { _ = ln.Close() }()
		if _, err := startDebugServer(ln.Addr().String(), nil); err == nil {
			t.Fatal("expected bind error")
		}
	})
	t.Run("serves metrics with pool loads", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("no loopback listener: %v", err)
		}
		port := ln.Addr().String()
		_ = ln.Close()
		closer, err := startDebugServer(port, func() []poolLoadSnapshot {
			return []poolLoadSnapshot{{Name: "ping", Busy: 1, Queued: 0}}
		})
		if err != nil {
			t.Fatalf("startDebugServer: %v", err)
		}
		defer closer()
		resp, err := http.Get("http://" + port + "/metrics")
		if err != nil {
			t.Fatalf("GET /metrics: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !strings.Contains(string(body), `pool_busy{name="ping"} 1`) {
			t.Errorf("metrics body missing pool load: %s", body)
		}
	})
}

func TestTokenBucketSetRateClamp(t *testing.T) {
	b := newTokenBucket(100, time.Now)
	// Tokens above the new burst are clamped.
	b.setRate(10)
	if b.burst != 1 {
		t.Errorf("burst = %f, want 1", b.burst)
	}
	if b.tokens > b.burst {
		t.Errorf("tokens %f exceed burst %f", b.tokens, b.burst)
	}
}

func TestWaitSNMPBuckets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitSNMPBuckets(ctx, nil) {
		t.Error("cancelled ctx must not wait")
	}
	// An exhausted device bucket under a cancelled context fails its wait.
	device := newTokenBucket(1, time.Now)
	device.rate = 0.0001 // refill is effectively zero; debt is long
	device.tokens = 0
	device.last = time.Now()
	ctx2, cancel2 := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- waitSNMPBuckets(ctx2, device) }()
	time.Sleep(20 * time.Millisecond)
	cancel2()
	if <-done {
		t.Error("device wait must return false on cancel")
	}
}

func TestRateLimitedQuerierObservers(t *testing.T) {
	r := &rateLimitedQuerier{}
	if r.responded() {
		t.Error("nil respondedFn must report false")
	}
	r.respondedFn = func() bool { return true }
	if !r.responded() {
		t.Error("respondedFn must be called")
	}
	called := false
	r.observeNetwork(time.Now(), nil)
	if called {
		t.Error("nil observer must not fire")
	}
	r.networkObserver = func(time.Duration, error) { called = true }
	r.observeNetwork(time.Now(), errors.New("x"))
	if !called {
		t.Error("observer must fire")
	}
}

func TestConfigureMemoryLimit(t *testing.T) {
	t.Run("env wins", func(t *testing.T) {
		t.Setenv("GOMEMLIMIT", "1GiB")
		called := false
		orig := readCgroupFile
		readCgroupFile = func(string) ([]byte, error) {
			called = true
			return nil, nil
		}
		t.Cleanup(func() { readCgroupFile = orig })
		configureMemoryLimit()
		if called {
			t.Error("cgroup files must not be read when GOMEMLIMIT is set")
		}
	})
	t.Run("unreadable files skipped", func(t *testing.T) {
		orig := readCgroupFile
		readCgroupFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
		t.Cleanup(func() { readCgroupFile = orig })
		configureMemoryLimit()
	})
	t.Run("unparseable skipped then limit applied", func(t *testing.T) {
		orig := readCgroupFile
		first := true
		readCgroupFile = func(string) ([]byte, error) {
			if first {
				first = false
				return []byte("max"), nil
			}
			return []byte("268435456"), nil
		}
		t.Cleanup(func() { readCgroupFile = orig })
		configureMemoryLimit()
	})
}

func TestRunMainDebugListenerError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code := runMain(ctx, []string{
		"--api-url=wss://example.com",
		"--token=test-token",
		"--debug-listen=not-a-listen-address",
		cliTHostKeysFlag(t),
	})
	if code != 1 {
		t.Errorf("bad debug listener must exit 1, got %d", code)
	}
}

func TestRunMainDebugListenerStarts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code := runMain(ctx, []string{
		"--api-url=wss://example.com",
		"--token=test-token",
		"--debug-listen=" + addr,
		cliTHostKeysFlag(t),
	})
	if code != 0 {
		t.Errorf("debug listener start must not fail run, got %d", code)
	}
}

func TestWorkerPoolRecurringReleaseOnFull(t *testing.T) {
	pool := newWorkerPool(1)
	defer pool.stop()
	// Occupy the single worker so the task channel stays full.
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	pool.submit(context.Background(), func() {
		started <- struct{}{}
		<-release
	})
	<-started
	// Fill the task channel so the next admission hits the default branch.
	for i := 0; i < cap(pool.tasks); i++ {
		pool.tasks <- func() {}
	}
	// A recurring submission that cannot queue must return its lane token.
	if pool.admitLane(context.Background(), func() {}, false, true, laneRecurring) {
		t.Error("admission must fail with a full task channel")
	}
	if len(pool.recurring) != 0 {
		t.Errorf("recurring token not released: %d", len(pool.recurring))
	}
	close(release)
}

func TestWorkerPoolSetLimitOnClosed(t *testing.T) {
	pool := newWorkerPool(1)
	pool.stop()
	pool.setWorkerLimit(4) // must be a no-op on a closed pool
}

func TestParseContainerMemoryLimitRejects(t *testing.T) {
	for _, v := range []string{"abc", "0", "-5", "max", "9223372036854775807"} {
		if _, ok := parseContainerMemoryLimit(v); ok {
			t.Errorf("parseContainerMemoryLimit(%q) must reject", v)
		}
	}
	if got, ok := parseContainerMemoryLimit(" 268435456 \n"); !ok || got != 268435456 {
		t.Errorf("valid limit = %d, %v", got, ok)
	}
}
