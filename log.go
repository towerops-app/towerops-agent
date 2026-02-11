package main

import (
	"context"
	"io"
	"log/slog"
	"sync"
)

// colorHandler is a slog.Handler that colorizes the level label.
type colorHandler struct {
	w     io.Writer
	level slog.Level
	mu    sync.Mutex
	attrs []slog.Attr
	group string
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
	if opts != nil {
		level = opts.Level.Level()
	}
	return &colorHandler{w: w, level: level}
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
	color := levelColor(r.Level)
	levelStr := r.Level.String()

	h.mu.Lock()
	defer h.mu.Unlock()

	buf := make([]byte, 0, 256)
	buf = append(buf, r.Time.Format("2006/01/02 15:04:05")...)
	buf = append(buf, ' ')
	buf = append(buf, color...)
	buf = append(buf, levelStr...)
	buf = append(buf, colorReset...)
	buf = append(buf, ' ')
	buf = append(buf, r.Message...)

	for _, a := range h.attrs {
		buf = append(buf, ' ')
		buf = appendAttr(buf, h.group, a)
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
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &colorHandler{
		w:     h.w,
		level: h.level,
		attrs: newAttrs,
		group: h.group,
	}
}

func (h *colorHandler) WithGroup(name string) slog.Handler {
	g := name
	if h.group != "" {
		g = h.group + "." + name
	}
	return &colorHandler{
		w:     h.w,
		level: h.level,
		attrs: h.attrs,
		group: g,
	}
}
