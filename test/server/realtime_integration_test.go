package server_test

import (
	"context"
	"net"
	"net/http"
	"testing"
)

// TestRunLeavesIncompleteRealtimeSurfacesUnavailable proves that ordinary HTTP
// startup does not bind the configured UDP port or publish snapshot/WS routes
// until channel authority, relay, sequencer and EventBus are connected.
func TestRunLeavesIncompleteRealtimeSurfacesUnavailable(t *testing.T) {
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	cfg := testConfig(t.TempDir(), freePort(t))
	cfg.Server.VoicePort = occupied.LocalAddr().(*net.UDPAddr).Port
	addr, cancel, done := startRun(t, cfg)
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run after cancel = %v", err)
		}
	}()
	waitReady(t, http.DefaultClient, "http://"+addr)

	for _, path := range []string{"/api/v0/state/snapshot", "/api/v0/ws"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, resp.StatusCode)
		}
	}
}
