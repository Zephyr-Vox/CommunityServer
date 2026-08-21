package server_test

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/logging"
	"zephyr.vox/server/ce/internal/server"
)

// TestServerLogsToConfiguredFile verifies the end-to-end wiring used by
// cmd/zephyrd: the injected logger fans out to a rotating file sink, and
// server.New's startup route table lands in the live log file.
func TestServerLogsToConfiguredFile(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")

	cfg := testConfigFull(dir, 8745, "open", 120)
	cfg.Log = config.LogConfig{Level: slog.LevelInfo, Path: logDir, ArchiveKeep: 7}
	rot, err := logging.NewRotatingWriter(logDir, logging.RotatingWriterConfig{Keep: cfg.Log.ArchiveKeep})
	if err != nil {
		t.Fatal(err)
	}
	defer rot.Close()

	// Mirror cmd/zephyrd.newLogger: console to io.Discard (tests must stay
	// quiet), file handler without colors.
	logger := slog.New(logging.NewFanout(
		logging.NewTextHandler(io.Discard, nil),
		logging.NewTextHandler(rot, nil),
	))

	app, err := server.New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	live := filepath.Join(logDir, "zephyr.log")
	data, err := os.ReadFile(live)
	if err != nil {
		t.Fatalf("live log missing after server.New: %v", err)
	}
	if !strings.Contains(string(data), "registered 37 routes") {
		t.Fatalf("live log does not contain the route summary:\n%s", data)
	}
}

// TestServerConsoleOnlyLogging verifies that an empty log path produces no
// files anywhere: the server itself must not create a log directory.
func TestServerConsoleOnlyLogging(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfigFull(dir, 8745, "open", 120)
	cfg.Log = config.LogConfig{Level: slog.LevelInfo, Path: "", ArchiveKeep: 7}
	logger := slog.New(logging.NewTextHandler(io.Discard, nil))
	app, err := server.New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "zephyr.log" || strings.HasPrefix(e.Name(), "zephyr-") {
			t.Fatalf("unexpected log artifact %q with empty log path", e.Name())
		}
	}
}

// TestRequestLogging verifies the [http] access log: successful requests are
// Info, client errors are Warn, and both carry method/path/status.
func TestRequestLogging(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfigFull(dir, 8745, "open", 120)
	var buf bytes.Buffer
	logger := slog.New(logging.NewTextHandler(&buf, slog.LevelDebug))
	app, err := server.New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	get(t, app, "/api/v0/auth/status")
	if !strings.Contains(buf.String(), "[http]") || !strings.Contains(buf.String(), "-> 200") {
		t.Fatalf("missing request log for 200: %q", buf.String())
	}

	buf.Reset()
	get(t, app, "/api/v0/nope")
	if !strings.Contains(buf.String(), "[WARN]") || !strings.Contains(buf.String(), "-> 404") {
		t.Fatalf("missing warn log for 404: %q", buf.String())
	}
}
