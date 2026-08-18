// Package logging provides the human-readable log pipeline used by zephyrd.
//
// It deliberately keeps the log/slog API (Echo v5 integrates with slog
// natively) while replacing the default output with:
//
//   - TextHandler: one line per record, for example
//     [INFO][2026-08-13 14:30:05.123][router] 23 routes registered
//   - Fanout: sends every record to several handlers, so the terminal can
//     render colors while files stay plain text.
//   - RotatingWriter: merges the live log into a dated zip archive every few
//     days, mirroring MCDReforged's ZippingDayRotatingFileHandler.
//
// The package must stay free of Echo and config imports: it is the logging
// adapter used at the edges of the application (cmd, server).
package logging

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// timeFormat is the human-readable timestamp segment used by TextHandler.
// Milliseconds are included so lines from concurrent requests can be ordered;
// the timezone is the process-local one because archives are grouped by
// local calendar day.
const timeFormat = "2006-01-02 15:04:05.000"

// ANSI escape sequences for the [LEVEL] tag. They are constants so the
// handler never builds colors at runtime, and they are only emitted when
// the target really is a terminal.
const (
	ansiReset   = "\x1b[0m"
	ansiCyan    = "\x1b[36m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiRed     = "\x1b[31m"
	ansiMagenta = "\x1b[35m"
)

// colorAttr is a reserved attr for the human-readable format: when it holds
// one of the known color names, TextHandler wraps the message in that ANSI
// color on terminals and omits the attr from the trailing key=value list.
// It lets a specific log line (e.g. the startup chant) stand out without
// inventing a fake log level. Unknown names stay ordinary attrs.
const colorAttr = "color"

// attrColors maps color names to ANSI codes.
var attrColors = map[string]string{
	"cyan":    ansiCyan,
	"green":   ansiGreen,
	"yellow":  ansiYellow,
	"red":     ansiRed,
	"magenta": ansiMagenta,
}

// TextHandler renders slog records as single human-readable lines:
//
//	[LEVEL][TIME][module] message key=value
//
// The module segment comes from an attr named "module" and is omitted when
// absent. Only the level tag is colored; the rest of the line stays plain so
// it remains easy to grep even with colors enabled.
type TextHandler struct {
	writeMu *sync.Mutex // shared by derived handlers writing the same target
	w       io.Writer
	level   slog.Leveler
	attrs   []slog.Attr // accumulated by WithAttrs
	colors  bool        // render ANSI colors around the [LEVEL] tag
}

// NewTextHandler returns a handler writing to w. level controls the minimum
// level; colors are auto-enabled only when w is a terminal (never for files
// or pipes, so redirecting logs cannot leak escape sequences).
func NewTextHandler(w io.Writer, level slog.Leveler) *TextHandler {
	return NewTextHandlerWithColors(w, level, isTerminal(w))
}

// NewTextHandlerWithColors is NewTextHandler with an explicit color flag. It
// exists for tests and for callers that already know whether the target is a
// terminal.
func NewTextHandlerWithColors(w io.Writer, level slog.Leveler, colors bool) *TextHandler {
	if level == nil {
		// Match slog's convention: a nil Leveler means the default minimum,
		// which is Info.
		level = slog.LevelInfo
	}
	return &TextHandler{writeMu: &sync.Mutex{}, w: w, level: level, colors: colors}
}

// Enabled reports whether level passes the configured minimum.
func (h *TextHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

// WithAttrs returns a copy of the handler carrying extra attrs. The copy is
// shallow on purpose (the handler struct is immutable after construction).
// Derived handlers share the same write lock because their writer may not be
// concurrency-safe.
func (h *TextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := &TextHandler{
		writeMu: h.writeMu,
		w:       h.w,
		level:   h.level,
		colors:  h.colors,
	}
	cp.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return cp
}

// WithGroup is a no-op: the human-readable format has no group concept.
// Modules are expressed with a "module" attr instead.
func (h *TextHandler) WithGroup(string) slog.Handler { return h }

// Handle renders one record. The whole line is built in memory first and
// written under a single lock, so concurrent log calls never interleave.
func (h *TextHandler) Handle(ctx context.Context, r slog.Record) error {
	// Guard against callers that skip slog's normal Enabled pre-check
	// (Fanout, tests, direct handler use): a handler must never render a
	// record below its own minimum level.
	if !h.Enabled(ctx, r.Level) {
		return nil
	}
	var buf bytes.Buffer

	// [LEVEL]: the only colored segment.
	buf.WriteByte('[')
	buf.WriteString(levelTag(r.Level, h.colors))
	buf.WriteByte(']')

	// [TIME]: local time with milliseconds.
	fmt.Fprintf(&buf, "[%s]", r.Time.Format(timeFormat))

	// Merge handler-level attrs (from WithAttrs) with record attrs; the
	// module attr gets a dedicated segment below.
	attrs := make([]slog.Attr, 0, len(h.attrs)+r.NumAttrs())
	attrs = append(attrs, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	module := ""
	color := ""
	for _, a := range attrs {
		switch a.Key {
		case "module":
			module = a.Value.String()
		case colorAttr:
			color = a.Value.String()
		}
	}
	if module != "" {
		fmt.Fprintf(&buf, "[%s]", module)
	}

	msg := r.Message
	if h.colors && attrColors[color] != "" {
		msg = attrColors[color] + msg + ansiReset
	}
	fmt.Fprintf(&buf, " %s", msg)
	for _, a := range attrs {
		if a.Key == "module" || (a.Key == colorAttr && attrColors[a.Value.String()] != "") || a.Value.Kind() == slog.KindGroup {
			continue
		}
		fmt.Fprintf(&buf, " %s=%s", a.Key, a.Value.String())
	}
	buf.WriteByte('\n')

	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	_, err := h.w.Write(buf.Bytes())
	return err
}

// levelTag returns the level name, optionally wrapped in its color.
func levelTag(level slog.Level, colors bool) string {
	tag := level.String()
	if !colors {
		return tag
	}
	var color string
	switch level {
	case slog.LevelDebug:
		color = ansiCyan
	case slog.LevelInfo:
		color = ansiGreen
	case slog.LevelWarn:
		color = ansiYellow
	case slog.LevelError:
		color = ansiRed
	default:
		// Custom levels have no fixed color; keep them plain.
		return tag
	}
	return color + tag + ansiReset
}

// isTerminal reports whether w is a character device (a real terminal).
// Files and pipes fail the check and therefore stay colorless.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
