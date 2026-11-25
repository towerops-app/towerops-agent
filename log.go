// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

// colorHandler formats slog records and colorizes the level label on terminals.
type colorHandler struct {
	w     io.Writer
	level slog.Level
	color bool
	mu    *sync.Mutex
	attrs []colorHandlerAttr
	group string
}

type colorHandlerAttr struct {
	group string
	attr  slog.Attr
}

const (
	colorReset  = "\033[0m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
)

func newColorHandler(w io.Writer, level slog.Level) *colorHandler {
	return &colorHandler{
		w:     w,
		level: level,
		color: writerSupportsColor(w),
		mu:    &sync.Mutex{},
	}
}

func newLogHandler(w io.Writer, level slog.Level, format string) slog.Handler {
	opts := &slog.HandlerOptions{Level: level}
	if format == "json" {
		return slog.NewJSONHandler(w, opts)
	}
	return newColorHandler(w, level)
}

// resolveLogFormat maps a --log-format value to "text" or "json". Unknown
// values fall back to text and report false so the caller can warn.
func resolveLogFormat(value string) (string, bool) {
	switch strings.ToLower(value) {
	case "json":
		return "json", true
	case "text":
		return "text", true
	default:
		return "text", false
	}
}

func writerSupportsColor(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// asyncLineWriter decouples log emission from the write syscall (A6). A slow
// or blocked log driver (journald, a full pipe) can then never stall a
// worker: callers append one line to a bounded channel and a single
// goroutine drains it to the destination. On overflow the line is dropped
// and counted, the same policy as the result spool, and the total is
// reported when the writer closes.
type asyncLineWriter struct {
	mu      sync.RWMutex
	closed  bool
	ch      chan []byte
	done    chan struct{}
	w       io.Writer
	dropped atomic.Uint64
}

// logFlushHook drains the async stderr writer before a process image swap;
// deferred closes never run across syscall.Exec.
var logFlushHook atomic.Pointer[func()]

const asyncLogQueueLines = 4096

func newAsyncLineWriter(w io.Writer) *asyncLineWriter {
	a := &asyncLineWriter{
		ch:   make(chan []byte, asyncLogQueueLines),
		done: make(chan struct{}),
		w:    w,
	}
	go a.pump()
	return a
}

func (a *asyncLineWriter) pump() {
	defer close(a.done)
	for buf := range a.ch {
		// Write errors on the destination are surfaced by the driver itself
		// (journald) or visible as missing output; there is no logger left
		// to report them to.
		_, _ = a.w.Write(buf)
	}
}

// Write never blocks and never fails: a full queue drops the line. The
// read lock keeps the send from racing Close: a writer that arrives after
// Close holds the write lock takes the drop path instead of sending on a
// closed channel.
func (a *asyncLineWriter) Write(p []byte) (n int, err error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		a.dropped.Add(1)
		return len(p), nil
	}
	select {
	case a.ch <- buf:
	default:
		a.dropped.Add(1)
	}
	return len(p), nil
}

// Close drains the queue and reports how many lines an overloaded log
// driver caused the agent to drop.
func (a *asyncLineWriter) Close() {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.ch)
	}
	a.mu.Unlock()
	<-a.done
	if dropped := a.dropped.Load(); dropped > 0 {
		_, _ = fmt.Fprintf(a.w, "log writer dropped %d lines (log driver blocked)\n", dropped)
	}
}

func (h *colorHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func levelColor(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return colorRed
	case level >= slog.LevelWarn:
		return colorYellow
	case level >= slog.LevelInfo:
		return colorGreen
	default:
		return colorCyan
	}
}

func (h *colorHandler) Handle(_ context.Context, r slog.Record) error {
	levelStr := r.Level.String()

	// Build the line before taking the lock: the mutex serializes writes to
	// one output stream but must not turn formatting work into hold time
	// ahead of the actual syscall (A6).
	buf := make([]byte, 0, 256)
	buf = append(buf, r.Time.Format("2006/01/02 15:04:05")...)
	buf = append(buf, ' ')
	if h.color {
		buf = append(buf, levelColor(r.Level)...)
	}
	buf = append(buf, levelStr...)
	if h.color {
		buf = append(buf, colorReset...)
	}
	buf = append(buf, ' ')
	buf = append(buf, r.Message...)

	for _, a := range h.attrs {
		buf = appendAttr(buf, a.group, a.attr)
	}

	r.Attrs(func(a slog.Attr) bool {
		buf = appendAttr(buf, h.group, a)
		return true
	})

	buf = append(buf, '\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf)
	return err
}

func appendAttr(buf []byte, group string, a slog.Attr) []byte {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindGroup {
		if a.Key != "" {
			if group == "" {
				group = a.Key
			} else {
				group += "." + a.Key
			}
		}
		for _, attr := range a.Value.Group() {
			buf = appendAttr(buf, group, attr)
		}
		return buf
	}

	if a.Key == "" {
		return buf
	}
	buf = append(buf, ' ')
	if group != "" {
		buf = append(buf, group...)
		buf = append(buf, '.')
	}
	buf = append(buf, a.Key...)
	buf = append(buf, '=')

	value := a.Value.String()
	if attrValueNeedsQuote(value) {
		return append(buf, strconv.Quote(value)...)
	}
	return append(buf, value...)
}

func attrValueNeedsQuote(value string) bool {
	if value == "" {
		return true
	}
	for _, r := range value {
		if r == ' ' || r == '=' || r == '"' || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func (h *colorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]colorHandlerAttr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	for i, attr := range attrs {
		newAttrs[len(h.attrs)+i] = colorHandlerAttr{group: h.group, attr: attr}
	}
	derived := *h
	derived.attrs = newAttrs
	return &derived
}

func (h *colorHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	g := name
	if h.group != "" {
		g = h.group + "." + name
	}
	derived := *h
	derived.group = g
	return &derived
}

// jobSummary aggregates the per-minute run/fail/partial/dropped counters
// (A6). Individual executor paths record outcomes instead of emitting an
// info line per poll, so a 3,000-device fleet no longer writes ~1.7 GB of
// logs per day.
var jobSummary = struct {
	run     atomic.Uint64
	failed  atomic.Uint64
	partial atomic.Uint64
	dropped atomic.Uint64
}{}

// recordJobRun counts a job that started executing (post-jitter/gate).
func recordJobRun() { jobSummary.run.Add(1) }

// recordJobFailure counts a job that reported an error result.
func recordJobFailure() { jobSummary.failed.Add(1) }

// recordJobPartial counts a job whose result was flagged partial.
func recordJobPartial() { jobSummary.partial.Add(1) }

// recordJobDropped counts a result or job the agent could not deliver.
func recordJobDropped() { jobSummary.dropped.Add(1) }

// jobSummaryInterval is the A6 reporting cadence. It is a variable so tests
// can shrink the window.
var jobSummaryInterval = time.Minute

// startJobSummaryLogger emits one summary line per interval until ctx ends.
// The production agent loop starts it; tests call the record helpers and
// read the counters directly.
func startJobSummaryLogger(ctx context.Context) context.CancelFunc {
	summaryCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	go func() {
		// Capture once: tests shrink the variable and restore it, which must
		// not race the log line below.
		interval := jobSummaryInterval
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-summaryCtx.Done():
				return
			case <-ticker.C:
				run := jobSummary.run.Swap(0)
				failed := jobSummary.failed.Swap(0)
				partial := jobSummary.partial.Swap(0)
				dropped := jobSummary.dropped.Swap(0)
				if run|failed|partial|dropped == 0 {
					continue
				}
				slog.Info("job summary",
					"window", interval.String(),
					"run", run,
					"failed", failed,
					"partial", partial,
					"dropped", dropped)
			}
		}
	}()
	return cancel
}
