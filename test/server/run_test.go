package server_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
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

func startRun(t *testing.T, cfg *config.App) (string, func(), <-chan error) {
	t.Helper()
	return startRunWithOptions(t, cfg, server.RunOptions{})
}

func startRunWithOptions(t *testing.T, cfg *config.App, opts server.RunOptions) (string, func(), <-chan error) {
	t.Helper()
	roles, err := config.LoadRoles(filepath.Join(filepath.Dir(cfg.Server.DBPath), "roles.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	app, err := server.New(cfg, roles, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx, opts) }()
	return net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.HTTPPort)), cancel, done
}

func waitReady(t *testing.T, client *http.Client, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		req, _ := http.NewRequest(http.MethodGet, addr+"/api/v0/auth/status", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not become ready at %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func insecureHTTPSClient(timeout time.Duration) *http.Client {
	// Server integration tests only: verifying the pinned fingerprint is the
	// client implementation's job, so tests skip certificate verification.
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
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

func TestRunRequiredRejectsPlaintextAndServesHTTPS(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := testConfig(dir, port)
	cfg.Server.TLSMode = config.TLSModeRequired
	cfg.Server.TLSCertPath = filepath.Join(dir, "tls")

	addr, cancel, done := startRun(t, cfg)
	waitReady(t, insecureHTTPSClient(2*time.Second), "https://"+addr)

	plain := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := plain.Get("http://" + addr + "/api/v0/auth/status")
	if err == nil {
		// Go's TLS server answers a plaintext request with its own 400
		// "client sent an HTTP request to an HTTPS server"; the application
		// never sees it. Anything except a successful HTTP 200 is rejection.
		got := resp.StatusCode
		resp.Body.Close()
		if got == http.StatusOK {
			t.Fatalf("plaintext request must fail in required mode, got status %d", got)
		}
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error after cancel: %v", err)
	}
}

func TestRunOptionalServesPlaintextAndTLS(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := testConfig(dir, port)
	cfg.Server.TLSMode = config.TLSModeOptional
	cfg.Server.TLSCertPath = filepath.Join(dir, "tls")

	addr, cancel, done := startRun(t, cfg)
	waitReady(t, insecureHTTPSClient(2*time.Second), "https://"+addr)
	waitReady(t, &http.Client{Timeout: 2 * time.Second}, "http://"+addr)

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error after cancel: %v", err)
	}
}

func TestRunOffRejectsTLS(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := testConfig(dir, port) // testConfig defaults to TLSModeOff

	addr, cancel, done := startRun(t, cfg)
	waitReady(t, &http.Client{Timeout: 2 * time.Second}, "http://"+addr)

	https := insecureHTTPSClient(500 * time.Millisecond)
	resp, err := https.Get("https://" + addr + "/api/v0/auth/status")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("TLS request must fail in off mode, got status %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error after cancel: %v", err)
	}
}

func TestRunOptionalSurvivesEmptyAndIdleConnections(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := testConfig(dir, port)
	cfg.Server.TLSMode = config.TLSModeOptional
	cfg.Server.TLSCertPath = filepath.Join(dir, "tls")

	addr, cancel, done := startRun(t, cfg)

	// A client that connects and immediately closes must be dropped without
	// killing the listener.
	empty, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	empty.Close()

	// An idle client that never sends a byte must not block the accept loop;
	// classification happens concurrently and times out on its own.
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()

	waitReady(t, insecureHTTPSClient(2*time.Second), "https://"+addr)
	waitReady(t, &http.Client{Timeout: 2 * time.Second}, "http://"+addr)

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error after empty/idle connections: %v", err)
	}
}

func TestRunOffRejectsForceRegenerate(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := testConfig(dir, port) // testConfig defaults to TLSModeOff

	_, _, done := startRunWithOptions(t, cfg, server.RunOptions{ForceRegenerateCert: true})
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run with -force-regenerate-cert in off mode must fail")
		}
		if !strings.Contains(err.Error(), "force-regenerate-cert") {
			t.Fatalf("error = %v, want force-regenerate-cert mention", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run with -force-regenerate-cert in off mode must fail fast")
	}
}

func TestRunRequiredWildcardHostSkipsJoinURL(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := testConfig(dir, port)
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.TLSMode = config.TLSModeRequired
	cfg.Server.TLSCertPath = filepath.Join(dir, "tls")

	roles, err := config.LoadRoles(filepath.Join(dir, "roles.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := slog.New(logging.NewTextHandler(&buf, slog.LevelDebug))
	app, err := server.New(cfg, roles, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx) }()
	waitReady(t, insecureHTTPSClient(2*time.Second), "https://127.0.0.1:"+strconv.Itoa(port))
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	logs := buf.String()
	if !strings.Contains(logs, "self-signed certificate generated") {
		t.Fatalf("logs must report first-time certificate generation: %q", logs)
	}
	if !strings.Contains(logs, "cert="+filepath.Join(cfg.Server.TLSCertPath, "server.crt")) {
		t.Fatalf("generated log must carry the certificate path: %q", logs)
	}
	if strings.Contains(logs, "zephyrvoxs://0.0.0.0") {
		t.Fatalf("join url must not contain the wildcard listen address: %q", logs)
	}
	if !strings.Contains(logs, "join url unavailable") {
		t.Fatalf("logs must explain why join url was skipped: %q", logs)
	}
}

func TestRunFileModeLogsOnlyFingerprintAndJoinURL(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := testConfig(dir, port)
	cfg.Server.TLSMode = config.TLSModeRequired
	cfg.Server.TLSCertPath = filepath.Join(dir, "tls")

	// First run creates the auto-generated identity.
	addr, cancel, done := startRun(t, cfg)
	waitReady(t, insecureHTTPSClient(2*time.Second), "https://"+addr)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("first Run returned error: %v", err)
	}

	// Second run uses the same files in file mode; its log output must match
	// the spec: no "using file certificate" line, only fingerprint + join url.
	cfg.Server.TLSCert = filepath.Join(cfg.Server.TLSCertPath, "server.crt")
	cfg.Server.TLSKey = filepath.Join(cfg.Server.TLSCertPath, "server.key")
	roles, err := config.LoadRoles(filepath.Join(dir, "roles.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := slog.New(logging.NewTextHandler(&buf, slog.LevelDebug))
	app, err := server.New(cfg, roles, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan error, 1)
	go func() { doneCh <- app.Run(ctx) }()
	waitReady(t, insecureHTTPSClient(2*time.Second), "https://"+addr)
	cancel()
	if err := <-doneCh; err != nil {
		t.Fatalf("file mode Run returned error: %v", err)
	}

	logs := buf.String()
	if !strings.Contains(logs, "tls fingerprint:") || !strings.Contains(logs, "join url:") {
		t.Fatalf("file mode must log fingerprint and join url: %q", logs)
	}
	if strings.Contains(logs, "using file certificate") {
		t.Fatalf("file mode must not log an extra certificate line: %q", logs)
	}
}

func TestRunForceRegenerateCert(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := testConfig(dir, port)
	cfg.Server.TLSMode = config.TLSModeRequired
	cfg.Server.TLSCertPath = filepath.Join(dir, "tls")
	tlsPath := cfg.Server.TLSCertPath

	addr, cancel, done := startRun(t, cfg)
	waitReady(t, insecureHTTPSClient(2*time.Second), "https://"+addr)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("first Run returned error: %v", err)
	}
	fpPath := filepath.Join(tlsPath, "fingerprint.txt")
	before, err := os.ReadFile(fpPath)
	if err != nil {
		t.Fatal(err)
	}

	addr, cancel, done = startRunWithOptions(t, cfg, server.RunOptions{ForceRegenerateCert: true})
	waitReady(t, insecureHTTPSClient(2*time.Second), "https://"+addr)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("second Run returned error: %v", err)
	}
	after, err := os.ReadFile(fpPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("force regeneration did not change the fingerprint")
	}
	entries, err := os.ReadDir(tlsPath)
	if err != nil {
		t.Fatal(err)
	}
	foundBackup := false
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "backup-") {
			foundBackup = true
			break
		}
	}
	if !foundBackup {
		t.Fatal("force regeneration did not leave a backup directory")
	}
}

func TestRunForceRegenerateLogsWarning(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := testConfig(dir, port)
	cfg.Server.TLSMode = config.TLSModeRequired
	cfg.Server.TLSCertPath = filepath.Join(dir, "tls")

	// First run creates the identity with a discard logger.
	addr, cancel, done := startRun(t, cfg)
	waitReady(t, insecureHTTPSClient(2*time.Second), "https://"+addr)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("first Run returned error: %v", err)
	}

	// Second run forces regeneration and must WARN with the backup path.
	roles, err := config.LoadRoles(filepath.Join(dir, "roles.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := slog.New(logging.NewTextHandler(&buf, slog.LevelDebug))
	app, err := server.New(cfg, roles, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan error, 1)
	go func() { doneCh <- app.Run(ctx, server.RunOptions{ForceRegenerateCert: true}) }()
	waitReady(t, insecureHTTPSClient(2*time.Second), "https://"+addr)
	cancel()
	if err := <-doneCh; err != nil {
		t.Fatalf("second Run returned error: %v", err)
	}

	logs := buf.String()
	if !strings.Contains(logs, "private key regenerated") || !strings.Contains(logs, "fingerprint changed") {
		t.Fatalf("logs must warn about the new fingerprint: %q", logs)
	}
	if !strings.Contains(logs, "backup-") {
		t.Fatalf("logs must mention the backup path: %q", logs)
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
