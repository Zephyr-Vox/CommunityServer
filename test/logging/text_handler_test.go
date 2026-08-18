package logging_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/logging"
)

// fixedRecord returns a record with a deterministic timestamp so format tests
// can compare exact strings.
func fixedRecord(level slog.Level, msg string, attrs ...slog.Attr) slog.Record {
	r := slog.NewRecord(time.Date(2026, 8, 13, 14, 30, 5, 123_000_000, time.Local), level, msg, 0)
	for _, a := range attrs {
		r.AddAttrs(a)
	}
	return r
}

func TestTextHandlerFormat(t *testing.T) {
	var buf bytes.Buffer
	h := logging.NewTextHandler(&buf, nil)
	r := fixedRecord(slog.LevelInfo, "hello", slog.String("module", "router"), slog.String("k", "v"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	want := "[INFO][2026-08-13 14:30:05.123][router] hello k=v\n"
	if got := buf.String(); got != want {
		t.Fatalf("rendered = %q, want %q", got, want)
	}
}

func TestTextHandlerOmitsModuleWhenAbsent(t *testing.T) {
	var buf bytes.Buffer
	h := logging.NewTextHandler(&buf, nil)
	if err := h.Handle(context.Background(), fixedRecord(slog.LevelInfo, "plain")); err != nil {
		t.Fatal(err)
	}
	want := "[INFO][2026-08-13 14:30:05.123] plain\n"
	if got := buf.String(); got != want {
		t.Fatalf("rendered = %q, want %q", got, want)
	}
}

func TestTextHandlerModuleFromWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := logging.NewTextHandler(&buf, nil).WithAttrs([]slog.Attr{slog.String("module", "auth")})
	if err := h.Handle(context.Background(), fixedRecord(slog.LevelWarn, "slow")); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, "[auth]") {
		t.Fatalf("rendered = %q, want module segment [auth]", got)
	}
}

func TestTextHandlerColors(t *testing.T) {
	cases := []struct {
		level slog.Level
		tag   string
		color string
	}{
		{slog.LevelDebug, "DEBUG", "\x1b[36m"},
		{slog.LevelInfo, "INFO", "\x1b[32m"},
		{slog.LevelWarn, "WARN", "\x1b[33m"},
		{slog.LevelError, "ERROR", "\x1b[31m"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		// LevelDebug minimum so every level under test actually renders
		// (Handle now self-filters records below the handler minimum).
		h := logging.NewTextHandlerWithColors(&buf, slog.LevelDebug, true)
		if err := h.Handle(context.Background(), fixedRecord(c.level, "x")); err != nil {
			t.Fatal(err)
		}
		want := "[" + c.color + c.tag + "\x1b[0m]"
		if got := buf.String(); !strings.HasPrefix(got, want) {
			t.Fatalf("level %s: rendered = %q, want prefix %q", c.tag, got, want)
		}
	}
}

func TestTextHandlerNoColorsOnNonTerminal(t *testing.T) {
	var buf bytes.Buffer
	h := logging.NewTextHandler(&buf, nil)
	if err := h.Handle(context.Background(), fixedRecord(slog.LevelError, "x")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("buffer output contains ANSI escapes: %q", buf.String())
	}
}

func TestTextHandlerColorAttr(t *testing.T) {
	var buf bytes.Buffer
	h := logging.NewTextHandlerWithColors(&buf, nil, true)
	r := fixedRecord(slog.LevelInfo, "System initialization finished, LINK START!",
		slog.String("module", "server"), slog.String("color", "magenta"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "\x1b[35mSystem initialization finished, LINK START!\x1b[0m") {
		t.Fatalf("message not wrapped in magenta: %q", got)
	}
	if strings.Contains(got, "color=") {
		t.Fatalf("color attr leaked into the line: %q", got)
	}
}

func TestTextHandlerColorAttrPlainOffTerminal(t *testing.T) {
	var buf bytes.Buffer
	h := logging.NewTextHandler(&buf, nil) // buffer: not a terminal
	r := fixedRecord(slog.LevelInfo, "System initialization finished, LINK START!",
		slog.String("color", "magenta"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("ANSI escapes leaked into non-terminal output: %q", got)
	}
	if strings.Contains(got, "color=") {
		t.Fatalf("color attr leaked into the line: %q", got)
	}
}

func TestTextHandlerUnknownColorStaysAttr(t *testing.T) {
	var buf bytes.Buffer
	h := logging.NewTextHandlerWithColors(&buf, nil, true)
	r := fixedRecord(slog.LevelInfo, "x", slog.String("color", "neon"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if strings.Contains(got, "\x1b[35m") {
		t.Fatalf("unknown color must not wrap the message: %q", got)
	}
	if !strings.Contains(got, "x color=neon") {
		t.Fatalf("unknown color should remain a plain attr: %q", got)
	}
}

func TestTextHandlerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	h := logging.NewTextHandler(&buf, slog.LevelInfo)
	ctx := context.Background()
	if h.Enabled(ctx, slog.LevelDebug) {
		t.Fatal("debug enabled with info minimum")
	}
	if !h.Enabled(ctx, slog.LevelInfo) || !h.Enabled(ctx, slog.LevelError) {
		t.Fatal("info/error must pass with info minimum")
	}
	// Handle must honor the same minimum even when called directly.
	if err := h.Handle(ctx, fixedRecord(slog.LevelDebug, "hidden")); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("Handle rendered a below-minimum record: %q", buf.String())
	}

	// A LevelVar can raise or lower the threshold at runtime.
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelDebug)
	if !logging.NewTextHandler(&buf, lv).Enabled(ctx, slog.LevelDebug) {
		t.Fatal("debug must pass after LevelVar lowered the threshold")
	}
}

func TestTextHandlerConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(logging.NewTextHandler(&buf, nil))
	const n = 200
	wg := new(sync.WaitGroup)
	for i := range n {
		wg.Go(func() {
			logger.Info("concurrent", "i", i)
		})
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("line count = %d, want %d", len(lines), n)
	}
	for _, line := range lines {
		if !strings.Contains(line, "[INFO]") || !strings.Contains(line, "concurrent i=") {
			t.Fatalf("malformed or interleaved line: %q", line)
		}
	}
}

func TestTextHandlerDerivedHandlersShareWriteLock(t *testing.T) {
	var buf bytes.Buffer
	base := logging.NewTextHandler(&buf, nil)
	handlers := []slog.Handler{
		base.WithAttrs([]slog.Attr{slog.String("module", "auth")}),
		base.WithAttrs([]slog.Attr{slog.String("module", "server")}),
		base.WithAttrs([]slog.Attr{slog.String("module", "voice")}),
	}
	const writesPerHandler = 100
	var wg sync.WaitGroup
	for _, handler := range handlers {
		for range writesPerHandler {
			wg.Go(func() {
				if err := handler.Handle(context.Background(), fixedRecord(slog.LevelInfo, "derived")); err != nil {
					t.Errorf("Handle = %v", err)
				}
			})
		}
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != len(handlers)*writesPerHandler {
		t.Fatalf("line count = %d, want %d", len(lines), len(handlers)*writesPerHandler)
	}
	for _, line := range lines {
		if !strings.Contains(line, " derived") {
			t.Fatalf("malformed or interleaved derived line: %q", line)
		}
	}
}

func TestTextHandlerWithGroupPassthrough(t *testing.T) {
	var buf bytes.Buffer
	h := logging.NewTextHandler(&buf, nil).WithGroup("ignored")
	if err := h.Handle(context.Background(), fixedRecord(slog.LevelInfo, "x")); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, " x\n") {
		t.Fatalf("rendered = %q, want plain message line", got)
	}
}
