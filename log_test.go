// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLevelColor(t *testing.T) {
	tests := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelDebug, colorCyan},
		{slog.LevelInfo, colorGreen},
		{slog.LevelWarn, colorYellow},
		{slog.LevelError, colorRed},
	}
	for _, tt := range tests {
		got := levelColor(tt.level)
		if got != tt.want {
			t.Errorf("levelColor(%v) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestNewColorHandler(t *testing.T) {
	var buf bytes.Buffer
	h := newColorHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestNewColorHandlerNilOpts(t *testing.T) {
	var buf bytes.Buffer
	h := newColorHandler(&buf, nil)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	// Default level should be Info
	if h.level != slog.LevelInfo {
		t.Errorf("default level: got %v, want %v", h.level, slog.LevelInfo)
	}
}

func TestNewColorHandlerNilLevel(t *testing.T) {
	var buf bytes.Buffer
	h := newColorHandler(&buf, &slog.HandlerOptions{})
	if h.level != slog.LevelInfo {
		t.Errorf("default level: got %v, want %v", h.level, slog.LevelInfo)
	}
}

func TestColorHandlerEnabled(t *testing.T) {
	var buf bytes.Buffer
	h := newColorHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})

	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected Debug to be disabled with Warn level")
	}
	if !h.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("expected Warn to be enabled")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("expected Error to be enabled")
	}
}

func TestColorHandlerHandle(t *testing.T) {
	var buf bytes.Buffer
	h := newColorHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})

	r := slog.NewRecord(time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), slog.LevelInfo, "test message", 0)
	r.AddAttrs(slog.String("key", "value"))

	err := h.Handle(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("expected 'test message' in output, got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("expected 'key=value' in output, got: %s", output)
	}
	if strings.Contains(output, "\033[") {
		t.Errorf("buffer output contains ANSI escape sequence: %q", output)
	}
	if !strings.Contains(output, " INFO test message") {
		t.Errorf("expected plain INFO level in output, got: %s", output)
	}
}

func TestColorHandlerHandleWithColor(t *testing.T) {
	var buf bytes.Buffer
	h := newColorHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	h.color = true

	r := slog.NewRecord(time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), slog.LevelInfo, "colored", 0)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, colorGreen+"INFO"+colorReset) {
		t.Errorf("expected colored INFO level in output, got: %q", output)
	}
}

func TestColorHandlerWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := newColorHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})

	h2 := h.WithAttrs([]slog.Attr{slog.String("component", "test")})

	r := slog.NewRecord(time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), slog.LevelInfo, "msg", 0)
	err := h2.Handle(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "component=test") {
		t.Errorf("expected 'component=test' in output, got: %s", output)
	}
}

func TestColorHandlerWithGroup(t *testing.T) {
	var buf bytes.Buffer
	h := newColorHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})

	h2 := h.WithGroup("mygroup")

	r := slog.NewRecord(time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), slog.LevelInfo, "msg", 0)
	r.AddAttrs(slog.String("key", "val"))
	err := h2.Handle(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "mygroup.key=val") {
		t.Errorf("expected 'mygroup.key=val' in output, got: %s", output)
	}
}

func TestColorHandlerAttrsKeepOriginalGroup(t *testing.T) {
	var buf bytes.Buffer
	h := newColorHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	derived := h.
		WithAttrs([]slog.Attr{slog.String("a", "one")}).
		WithGroup("g").
		WithAttrs([]slog.Attr{slog.String("b", "two")})

	r := slog.NewRecord(time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), slog.LevelInfo, "msg", 0)
	if err := derived.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, " a=one g.b=two") {
		t.Errorf("expected attrs to retain their original groups, got: %q", output)
	}
	if strings.Contains(output, "g.a=one") {
		t.Errorf("attr added before WithGroup was retroactively qualified: %q", output)
	}
}

func TestDerivedColorHandlersShareWriteLock(t *testing.T) {
	h := newColorHandler(io.Discard, nil)
	withAttrs := h.WithAttrs([]slog.Attr{slog.String("a", "b")}).(*colorHandler)
	withGroup := h.WithGroup("group").(*colorHandler)
	if h.mu != withAttrs.mu || h.mu != withGroup.mu {
		t.Fatal("derived handlers do not share the writer mutex")
	}
}

func TestColorHandlerWithGroupNested(t *testing.T) {
	var buf bytes.Buffer
	h := newColorHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})

	h2 := h.WithGroup("outer").WithGroup("inner")

	r := slog.NewRecord(time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), slog.LevelInfo, "msg", 0)
	r.AddAttrs(slog.String("k", "v"))
	err := h2.Handle(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "outer.inner.k=v") {
		t.Errorf("expected 'outer.inner.k=v' in output, got: %s", output)
	}
}

func TestNewLogHandlerJSON(t *testing.T) {
	var buf bytes.Buffer
	h := newLogHandler(&buf, slog.LevelInfo, "json")
	r := slog.NewRecord(time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), slog.LevelWarn, "json message", 0)
	r.AddAttrs(slog.String("key", "value"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	if entry["level"] != "WARN" || entry["msg"] != "json message" || entry["key"] != "value" {
		t.Errorf("unexpected JSON entry: %#v", entry)
	}
}

func TestNewLogHandlerText(t *testing.T) {
	var buf bytes.Buffer
	h := newLogHandler(&buf, slog.LevelWarn, "text")
	color, ok := h.(*colorHandler)
	if !ok {
		t.Fatalf("newLogHandler text type = %T, want *colorHandler", h)
	}
	if color.level != slog.LevelWarn {
		t.Errorf("text handler level = %v, want %v", color.level, slog.LevelWarn)
	}
	if color.color {
		t.Error("buffer-backed text handler unexpectedly enabled ANSI color")
	}
}

func TestAppendAttr(t *testing.T) {
	t.Run("no group", func(t *testing.T) {
		buf := appendAttr(nil, "", slog.String("key", "value"))
		if string(buf) != "key=value" {
			t.Errorf("got %q, want %q", string(buf), "key=value")
		}
	})

	t.Run("with group", func(t *testing.T) {
		buf := appendAttr(nil, "grp", slog.String("key", "value"))
		if string(buf) != "grp.key=value" {
			t.Errorf("got %q, want %q", string(buf), "grp.key=value")
		}
	})
}
