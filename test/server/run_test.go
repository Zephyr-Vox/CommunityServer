package server_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/logging"
	"zephyr.vox/server/ce/internal/server"
)

// freePort grabs a free TCP port by binding :0 and immediately closing it.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestRunServesAndShutsDownGracefully(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	roles, err := config.LoadRoles(filepath.Join(dir, "roles.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	app, err := server.New(testConfig(dir, port), roles, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx) }()

	addr := "127.0.0.1:" + strconv.Itoa(port)
	deadline := time.Now().Add(3 * time.Second)
	for {
		req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/api/v0/auth/status", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestRunBindFailureDoesNotClaimReady locks down the startup ordering: the
// "http listening" / "LINK START" lines must never appear when the port is
// already taken, otherwise operators would misread a failed start as a
// successful initialization.
func TestRunBindFailureDoesNotClaimReady(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	roles, err := config.LoadRoles(filepath.Join(dir, "roles.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := slog.New(logging.NewTextHandler(&buf, slog.LevelDebug))
	app, err := server.New(testConfig(dir, port), roles, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	err = app.Run(context.Background())
	if err == nil {
		t.Fatal("Run must fail when the port is already bound")
	}
	if strings.Contains(buf.String(), "http listening") || strings.Contains(buf.String(), "LINK START") {
		t.Fatalf("claimed readiness despite bind failure: %q", buf.String())
	}
}
