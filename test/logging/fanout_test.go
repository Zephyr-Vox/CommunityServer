package logging_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"zephyr.vox/server/ce/internal/logging"
)

func TestFanoutDeliversToAllHandlers(t *testing.T) {
	var a, b bytes.Buffer
	logger := slog.New(logging.NewFanout(
		logging.NewTextHandler(&a, nil),
		logging.NewTextHandler(&b, nil),
	))
	logger.Info("hello")
	for name, buf := range map[string]*bytes.Buffer{"a": &a, "b": &b} {
		if !strings.Contains(buf.String(), "hello") {
			t.Fatalf("handler %s did not receive the record: %q", name, buf.String())
		}
	}
}

func TestFanoutWithAttrsPropagates(t *testing.T) {
	var a, b bytes.Buffer
	f := logging.NewFanout(
		logging.NewTextHandler(&a, nil),
		logging.NewTextHandler(&b, nil),
	).WithAttrs([]slog.Attr{slog.String("module", "shared")})
	if err := f.Handle(context.Background(), fixedRecord(slog.LevelInfo, "x")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.String(), "[shared]") || !strings.Contains(b.String(), "[shared]") {
		t.Fatalf("attrs not propagated: a=%q b=%q", a.String(), b.String())
	}
}

// TestFanoutFiltersPerHandlerLevel locks down the mixed-level contract: a
// record only reaches the children whose minimum level accepts it.
func TestFanoutFiltersPerHandlerLevel(t *testing.T) {
	var console, file bytes.Buffer
	f := logging.NewFanout(
		logging.NewTextHandler(&console, slog.LevelDebug),
		logging.NewTextHandler(&file, slog.LevelInfo),
	)
	logger := slog.New(f)

	logger.Debug("debug line")
	logger.Info("info line")

	if !strings.Contains(console.String(), "debug line") {
		t.Fatalf("console missed debug line: %q", console.String())
	}
	if strings.Contains(file.String(), "debug line") {
		t.Fatalf("info-level file handler received debug line: %q", file.String())
	}
	if !strings.Contains(file.String(), "info line") {
		t.Fatalf("file missed info line: %q", file.String())
	}
}

// failingHandler always fails, to prove Fanout keeps invoking the others.
type failingHandler struct{}

func (failingHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (failingHandler) Handle(context.Context, slog.Record) error { return errors.New("boom") }
func (failingHandler) WithAttrs([]slog.Attr) slog.Handler        { return failingHandler{} }
func (failingHandler) WithGroup(string) slog.Handler             { return failingHandler{} }

func TestFanoutReturnsFirstErrorButCallsAll(t *testing.T) {
	var buf bytes.Buffer
	f := logging.NewFanout(failingHandler{}, logging.NewTextHandler(&buf, nil))
	err := f.Handle(context.Background(), fixedRecord(slog.LevelInfo, "still here"))
	if err == nil || err.Error() != "boom" {
		t.Fatalf("Handle error = %v, want boom", err)
	}
	if !strings.Contains(buf.String(), "still here") {
		t.Fatalf("healthy sibling not called: %q", buf.String())
	}
}
