// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
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

func newColorHandler(w io.Writer, opts *slog.HandlerOptions) *colorHandler {
	level := slog.LevelInfo
	if opts != nil && opts.Level != nil {
		level = opts.Level.Level()
	}
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
	return newColorHandler(w, opts)
}

func writerSupportsColor(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
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
	h.mu.Lock()
	defer h.mu.Unlock()

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
		buf = append(buf, ' ')
		buf = appendAttr(buf, a.group, a.attr)
	}

	r.Attrs(func(a slog.Attr) bool {
		buf = append(buf, ' ')
		buf = appendAttr(buf, h.group, a)
		return true
	})

	buf = append(buf, '\n')
	_, err := h.w.Write(buf)
	return err
}

func appendAttr(buf []byte, group string, a slog.Attr) []byte {
	if group != "" {
		buf = append(buf, group...)
		buf = append(buf, '.')
	}
	buf = append(buf, a.Key...)
	buf = append(buf, '=')
	buf = append(buf, a.Value.String()...)
	return buf
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
	g := name
	if h.group != "" {
		g = h.group + "." + name
	}
	derived := *h
	derived.group = g
	return &derived
}
