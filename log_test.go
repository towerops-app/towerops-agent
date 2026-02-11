package main

import (
	"bytes"
	"context"
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
	if !strings.Contains(output, colorGreen) {
		t.Errorf("expected green color for INFO level in output")
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
