package logging

import (
	"context"
	"log/slog"
)

// Fanout dispatches every record to all handlers, mirroring io.MultiWriter
// at the slog level. It exists because the terminal and the log file need
// separate handlers: the terminal one renders ANSI colors, the file one must
// never contain escape sequences.
type Fanout struct {
	handlers []slog.Handler
}

// NewFanout returns a handler that fans records out to handlers. An empty
// list is allowed but useless; callers normally pass at least the console.
func NewFanout(handlers ...slog.Handler) *Fanout {
	return &Fanout{handlers: handlers}
}

// Enabled is the OR of all children: a record is enabled if any handler wants
// it, because Handle must still dispatch to the children that accept it.
func (f *Fanout) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle sends the record to every child that accepts its level and returns
// the first error. Disabled children are skipped here, not filtered later:
// with mixed minimum levels (say a debug console and an info file), a debug
// record must never reach the file sink. All enabled handlers are still
// invoked, so one failing sink cannot starve the others.
func (f *Fanout) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, h := range f.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// WithAttrs propagates attrs to every child handler.
func (f *Fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return &Fanout{handlers: hs}
}

// WithGroup propagates the group to every child handler.
func (f *Fanout) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		hs[i] = h.WithGroup(name)
	}
	return &Fanout{handlers: hs}
}
