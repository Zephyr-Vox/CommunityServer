package realtime_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/realtime"
)

type closeRequest struct {
	status int
	reason string
}

type closeRecorder struct {
	mu       sync.Mutex
	requests []closeRequest
}

func (r *closeRecorder) RequestClose(statusCode int, reason string) {
	r.mu.Lock()
	r.requests = append(r.requests, closeRequest{status: statusCode, reason: reason})
	r.mu.Unlock()
}

func (r *closeRecorder) ForceClose() {}

func (r *closeRecorder) Requests() []closeRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]closeRequest(nil), r.requests...)
}

func TestConnectionCoordinatorLifecycle(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	ref := reservation.Ref()
	if state, ok := coordinator.State(ref); !ok || state != realtime.ConnectionOpening {
		t.Fatalf("opening state = (%v, %v), want opening", state, ok)
	}
	if coordinator.ActiveCount() != 1 {
		t.Fatalf("opening admission count = %d, want 1", coordinator.ActiveCount())
	}

	transport := &closeRecorder{}
	if _, _, err := reservation.Activate(transport, time.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if state, ok := coordinator.State(ref); !ok || state != realtime.ConnectionActive {
		t.Fatalf("active state = (%v, %v), want active", state, ok)
	}
	if !coordinator.BeginDisconnect(ref, 4000, "protocol error") {
		t.Fatal("first BeginDisconnect must own the close")
	}
	if coordinator.BeginDisconnect(ref, 4000, "duplicate") {
		t.Fatal("duplicate BeginDisconnect must be a no-op")
	}
	if state, ok := coordinator.State(ref); !ok || state != realtime.ConnectionClosing {
		t.Fatalf("closing state = (%v, %v), want closing", state, ok)
	}
	if coordinator.ActiveCount() != 0 {
		t.Fatalf("closing admission count = %d, want 0", coordinator.ActiveCount())
	}
	requests := transport.Requests()
	if len(requests) != 1 || requests[0] != (closeRequest{status: 4000, reason: "protocol error"}) {
		t.Fatalf("close requests = %+v, want one protocol close", requests)
	}
	coordinator.FinishDisconnect(ref)
	if _, ok := coordinator.State(ref); ok {
		t.Fatal("finished connection must be removed")
	}
}

func TestConnectionCoordinatorRevokesOpeningConnection(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	ref := reservation.Ref()
	coordinator.DisconnectLoginSession(7, 11, "logged_out")
	if state, ok := coordinator.State(ref); !ok || state != realtime.ConnectionClosing {
		t.Fatalf("revoked opening state = (%v, %v), want closing", state, ok)
	}
	if _, _, err := reservation.Activate(&closeRecorder{}, time.Now().Add(time.Hour).UnixMilli()); !errors.Is(err, realtime.ErrConnectionNotOpening) {
		t.Fatalf("Activate revoked opening = %v, want ErrConnectionNotOpening", err)
	}
	reservation.Abort()
	if _, ok := coordinator.State(ref); ok {
		t.Fatal("aborted revoked opening must be removed")
	}
}

func TestConnectionCoordinatorTargetsOnlyMatchingLoginSession(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	first, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	second, err := coordinator.ReserveConnect(7, 12)
	if err != nil {
		t.Fatal(err)
	}
	firstTransport := &closeRecorder{}
	secondTransport := &closeRecorder{}
	firstRef, _, err := first.Activate(firstTransport, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	secondRef, _, err := second.Activate(secondTransport, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}

	coordinator.DisconnectLoginSession(7, 11, "logged_out")
	if state, ok := coordinator.State(firstRef); !ok || state != realtime.ConnectionClosing {
		t.Fatalf("first state = (%v, %v), want closing", state, ok)
	}
	if state, ok := coordinator.State(secondRef); !ok || state != realtime.ConnectionActive {
		t.Fatalf("second state = (%v, %v), want active", state, ok)
	}
	if got := firstTransport.Requests(); len(got) != 1 || got[0].status != 4002 || got[0].reason != "logged_out" {
		t.Fatalf("first close request = %+v, want login-session revoke", got)
	}
	if got := secondTransport.Requests(); len(got) != 0 {
		t.Fatalf("second close requests = %+v, want none", got)
	}
}

func TestConnectionCoordinatorStaleRefCannotCloseLaterConnection(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	oldReservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	oldRef := oldReservation.Ref()
	oldReservation.Abort()
	currentReservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	currentRef := currentReservation.Ref()
	transport := &closeRecorder{}
	if _, _, err := currentReservation.Activate(transport, time.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if coordinator.BeginDisconnect(oldRef, 4000, "stale") {
		t.Fatal("stale ref must not claim a later connection")
	}
	if state, ok := coordinator.State(currentRef); !ok || state != realtime.ConnectionActive {
		t.Fatalf("current state = (%v, %v), want active", state, ok)
	}
	if got := transport.Requests(); len(got) != 0 {
		t.Fatalf("stale ref close requests = %+v, want none", got)
	}
}

func TestConnectionCoordinatorLeaseRevisionMakesOldTimerNoOp(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	transport := &closeRecorder{}
	now := time.Now().UnixMilli()
	ref, initial, err := reservation.Activate(transport, now+1_000)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := coordinator.RenewAuthLease(ref, now+2_000, now)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Revision != initial.Revision+1 {
		t.Fatalf("renewed revision = %d, want %d", renewed.Revision, initial.Revision+1)
	}
	if coordinator.ExpireAuthLease(ref, initial, now+1_000) {
		t.Fatal("old lease timer must not close a renewed connection")
	}
	if state, ok := coordinator.State(ref); !ok || state != realtime.ConnectionActive {
		t.Fatalf("state after stale expiry = (%v, %v), want active", state, ok)
	}
	if !coordinator.ExpireAuthLease(ref, renewed, now+2_000) {
		t.Fatal("current lease timer must close at expiry")
	}
	if got := transport.Requests(); len(got) != 1 || got[0] != (closeRequest{status: 4001, reason: "token expired"}) {
		t.Fatalf("lease expiry close = %+v, want 4001", got)
	}
}

func TestConnectionCoordinatorSourceAdmissionAndShutdownDrain(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	sourceIP := netip.MustParseAddr("192.0.2.1")
	reservations := make([]*realtime.ConnectionReservation, 0, realtime.MaxControlConnectionsPerSource)
	for userID := 1; userID <= realtime.MaxControlConnectionsPerSource; userID++ {
		reservation, err := coordinator.ReserveConnectFrom(int64(userID), 1, sourceIP)
		if err != nil {
			t.Fatalf("reserve %d: %v", userID, err)
		}
		reservations = append(reservations, reservation)
	}
	if _, err := coordinator.ReserveConnectFrom(1000, 1, sourceIP); !errors.Is(err, realtime.ErrSourceConnectionLimit) {
		t.Fatalf("source cap reserve = %v, want ErrSourceConnectionLimit", err)
	}
	if got := coordinator.SourceCount(sourceIP); got != realtime.MaxControlConnectionsPerSource {
		t.Fatalf("source count = %d, want %d", got, realtime.MaxControlConnectionsPerSource)
	}
	for _, reservation := range reservations {
		reservation.Abort()
	}
	if got := coordinator.SourceCount(sourceIP); got != 0 {
		t.Fatalf("source count after abort = %d, want 0", got)
	}

	reservation, err := coordinator.ReserveConnectFrom(7, 1, sourceIP)
	if err != nil {
		t.Fatal(err)
	}
	ref, _, err := reservation.Activate(&closeRecorder{}, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	coordinator.StopAdmission()
	if _, err := coordinator.ReserveConnectFrom(8, 1, sourceIP); !errors.Is(err, realtime.ErrConnectionAdmissionClosed) {
		t.Fatalf("reserve after stop = %v, want ErrConnectionAdmissionClosed", err)
	}
	coordinator.DisconnectAll(4005, "server shutdown")
	drained := make(chan error, 1)
	go func() { drained <- coordinator.Wait(context.Background()) }()
	select {
	case err := <-drained:
		t.Fatalf("Wait returned before the active handler finished: %v", err)
	default:
	}
	coordinator.FinishDisconnect(ref)
	select {
	case err := <-drained:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait did not finish after connection completion")
	}
}
