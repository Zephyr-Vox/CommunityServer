package server_test

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/config"
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
	app, err := server.New(testConfig(dir, port), roles)
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
