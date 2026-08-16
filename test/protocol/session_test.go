package protocol_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/protocol"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestManager(t *testing.T) (*protocol.Manager, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	return protocol.NewManager(clock.Now), clock
}

func TestManagerCreateUniqueSessionsAndKeys(t *testing.T) {
	m, _ := newTestManager(t)
	a, err := m.Create(10, "dev-a", true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Create(11, "dev-b", true)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Fatal("session ids must be unique")
	}
	if string(a.MasterKey) == string(b.MasterKey) {
		t.Fatal("master keys must be unique")
	}
	if !a.Encrypted || a.ExpiresAt == 0 || a.MasterKey == nil {
		t.Fatalf("create info = %+v", a)
	}
	if got, ok := m.Get(a.ID); !ok || got.UserID != 10 || got.DeviceID != "dev-a" {
		t.Fatalf("Get = (%+v,%v)", got, ok)
	}
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}
}

func TestManagerCreateRejectsInvalidUser(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(0, "", false); !errors.Is(err, protocol.ErrInvalidUserID) {
		t.Fatalf("err = %v, want ErrInvalidUserID", err)
	}
}

func TestManagerTouchSlidesExpiry(t *testing.T) {
	m, clock := newTestManager(t)
	info, err := m.Create(1, "", false)
	if err != nil {
		t.Fatal(err)
	}

	clock.Advance(80 * time.Second)
	m.Touch(info.ID)
	clock.Advance(89 * time.Second)
	if _, ok := m.Get(info.ID); !ok {
		t.Fatal("touched session expired before new deadline")
	}
	clock.Advance(2 * time.Second)
	if _, ok := m.Get(info.ID); ok {
		t.Fatal("touched session survived past 90s deadline")
	}
}

func TestManagerGetExpiresLazily(t *testing.T) {
	m, clock := newTestManager(t)
	info, err := m.Create(1, "", false)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(protocol.SessionTTL)
	if _, ok := m.Get(info.ID); ok {
		t.Fatal("expired session returned")
	}
	if m.Len() != 0 {
		t.Fatalf("expired session was not lazily deleted, Len=%d", m.Len())
	}
}

func TestManagerPurgeRemovesExpired(t *testing.T) {
	m, clock := newTestManager(t)
	_, err := m.Create(1, "", false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Create(2, "", false)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(protocol.SessionTTL + time.Millisecond)
	if n := m.Purge(); n != 2 {
		t.Fatalf("Purge = %d, want 2", n)
	}
	if m.Len() != 0 {
		t.Fatalf("Len after purge = %d", m.Len())
	}
}

func TestManagerCreatePreemptsOldSession(t *testing.T) {
	m, _ := newTestManager(t)
	oldInfo, err := m.Create(7, "old-device", false)
	if err != nil {
		t.Fatal(err)
	}

	type notification struct {
		reason protocol.RevocationReason
		snap   protocol.RevokedSessionSnapshot
	}
	got := make(chan notification, 1)
	m.SetRevocationHandler(func(reason protocol.RevocationReason, snap protocol.RevokedSessionSnapshot) {
		got <- notification{reason: reason, snap: snap}
	})

	newInfo, err := m.Create(7, "new-device", false)
	if err != nil {
		t.Fatal(err)
	}
	if !newInfo.ReplacedPrevious {
		t.Fatal("new session must report replaced_previous")
	}
	if _, ok := m.Get(oldInfo.ID); ok {
		t.Fatal("old session must be gone immediately")
	}
	if _, ok := m.Get(newInfo.ID); !ok {
		t.Fatal("new session missing")
	}
	select {
	case n := <-got:
		if n.reason != protocol.RevocationReplaced {
			t.Fatalf("reason = %d, want Replaced", n.reason)
		}
		if n.snap.ID != oldInfo.ID || n.snap.UserID != 7 || n.snap.SendSeq != 1 {
			t.Fatalf("snapshot = %+v", n.snap)
		}
	default:
		t.Fatal("RevocationReplaced handler was not called")
	}
}

func TestManagerRevocationHandlerRunsOutsideManagerLock(t *testing.T) {
	m, _ := newTestManager(t)
	called := make(chan struct{})
	m.SetRevocationHandler(func(reason protocol.RevocationReason, snap protocol.RevokedSessionSnapshot) {
		// If the callback still held the manager lock this Get would deadlock.
		if _, ok := m.Get([16]byte{}); ok {
			return
		}
		close(called)
	})
	if _, err := m.Create(7, "old", false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(7, "new", false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("revocation callback appears to run under the manager lock")
	}
}

func TestManagerInvalidateUserRevokes(t *testing.T) {
	m, _ := newTestManager(t)
	info, err := m.Create(7, "dev", true)
	if err != nil {
		t.Fatal(err)
	}
	type notification struct {
		reason protocol.RevocationReason
		snap   protocol.RevokedSessionSnapshot
	}
	got := make(chan notification, 1)
	m.SetRevocationHandler(func(reason protocol.RevocationReason, snap protocol.RevokedSessionSnapshot) {
		got <- notification{reason: reason, snap: snap}
	})

	if n := m.InvalidateUser(7); n != 1 {
		t.Fatalf("InvalidateUser = %d, want 1", n)
	}
	if _, ok := m.Get(info.ID); ok {
		t.Fatal("invalidated session still present")
	}
	select {
	case n := <-got:
		if n.reason != protocol.RevocationRevoked {
			t.Fatalf("reason = %d, want Revoked", n.reason)
		}
		if n.snap.ID != info.ID || n.snap.S2CAEAD == nil || n.snap.SendSeq != 1 {
			t.Fatalf("snapshot = %+v", n.snap)
		}
	default:
		t.Fatal("RevocationRevoked handler was not called")
	}
	if n := m.InvalidateUser(7); n != 0 {
		t.Fatalf("second InvalidateUser = %d, want 0", n)
	}
}

func TestManagerDeleteOwnershipAndNoRevocation(t *testing.T) {
	m, _ := newTestManager(t)
	info, err := m.Create(7, "", false)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	m.SetRevocationHandler(func(protocol.RevocationReason, protocol.RevokedSessionSnapshot) { called = true })

	if err := m.Delete(info.ID, 8); !errors.Is(err, protocol.ErrSessionNotOwned) {
		t.Fatalf("foreign delete err = %v, want ErrSessionNotOwned", err)
	}
	if err := m.Delete(info.ID, 7); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(info.ID, 7); !errors.Is(err, protocol.ErrSessionNotFound) {
		t.Fatalf("second delete err = %v, want ErrSessionNotFound", err)
	}
	if called {
		t.Fatal("voluntary DELETE must not emit a revocation notification")
	}
}

func TestManagerDeleteExpiredIsNotFound(t *testing.T) {
	m, clock := newTestManager(t)
	info, err := m.Create(7, "", false)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(protocol.SessionTTL)
	if err := m.Delete(info.ID, 7); !errors.Is(err, protocol.ErrSessionNotFound) {
		t.Fatalf("expired delete err = %v, want ErrSessionNotFound", err)
	}
}

func TestManagerPurgeDoesNotRevoke(t *testing.T) {
	m, clock := newTestManager(t)
	if _, err := m.Create(7, "", false); err != nil {
		t.Fatal(err)
	}
	called := false
	m.SetRevocationHandler(func(protocol.RevocationReason, protocol.RevokedSessionSnapshot) { called = true })
	clock.Advance(protocol.SessionTTL + time.Second)
	if n := m.Purge(); n != 1 {
		t.Fatalf("Purge = %d", n)
	}
	if called {
		t.Fatal("natural expiry must not emit a revocation notification")
	}
}

func TestManagerSessionIDByUser(t *testing.T) {
	m, clock := newTestManager(t)
	info, err := m.Create(7, "", false)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := m.SessionIDByUser(7)
	if !ok || id != info.ID {
		t.Fatalf("SessionIDByUser = (%x, %v), want (%x, true)", id, ok, info.ID)
	}
	if _, ok := m.SessionIDByUser(8); ok {
		t.Fatal("unknown user reported active")
	}
	clock.Advance(protocol.SessionTTL)
	if _, ok := m.SessionIDByUser(7); ok {
		t.Fatal("expired user session still reported active")
	}
	if m.Len() != 0 {
		t.Fatalf("expired session not lazily deleted, Len=%d", m.Len())
	}
}

func TestManagerExpiryHandlerOnLazyGetAndPurge(t *testing.T) {
	m, clock := newTestManager(t)
	info, err := m.Create(7, "", false)
	if err != nil {
		t.Fatal(err)
	}
	type expiredSession struct {
		userID    int64
		sessionID [16]byte
	}
	got := make(chan expiredSession, 2)
	m.SetExpiryHandler(func(userID int64, sessionID [16]byte) {
		got <- expiredSession{userID: userID, sessionID: sessionID}
	})

	clock.Advance(protocol.SessionTTL)
	if _, ok := m.Get(info.ID); ok {
		t.Fatal("expired session returned")
	}
	select {
	case e := <-got:
		if e.userID != 7 || e.sessionID != info.ID {
			t.Fatalf("expiry = %+v", e)
		}
	default:
		t.Fatal("lazy Get did not emit expiry callback")
	}

	_, err = m.Create(8, "", false)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(protocol.SessionTTL)
	if n := m.Purge(); n != 1 {
		t.Fatalf("Purge = %d, want 1", n)
	}
	select {
	case e := <-got:
		if e.userID != 8 {
			t.Fatalf("purge expiry = %+v", e)
		}
	default:
		t.Fatal("Purge did not emit expiry callback")
	}
}

func TestNewManagerWithLimitsRejectsInvalid(t *testing.T) {
	if _, err := protocol.NewManagerWithLimits(nil, protocol.Limits{}); err == nil {
		t.Fatal("zero limits accepted")
	}
	if _, err := protocol.NewManagerWithLimits(nil, protocol.Limits{SessionPacketsPerSec: -1, SessionBurst: 10}); err == nil {
		t.Fatal("negative rate accepted")
	}
	m, err := protocol.NewManagerWithLimits(nil, protocol.Limits{SessionPacketsPerSec: 10, SessionBurst: 20})
	if err != nil {
		t.Fatal(err)
	}
	if m.Len() != 0 {
		t.Fatalf("Len = %d", m.Len())
	}
}

func TestManagerConcurrentCreateKeepsOneSession(t *testing.T) {
	m, _ := newTestManager(t)
	const n = 16
	infos := make(chan protocol.SessionInfo, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			info, err := m.Create(7, "dev", false)
			if err != nil {
				t.Errorf("Create: %v", err)
				return
			}
			infos <- info
		})
	}
	wg.Wait()
	close(infos)

	if m.Len() != 1 {
		t.Fatalf("Len = %d, want exactly one active session", m.Len())
	}
	live := 0
	for info := range infos {
		if _, ok := m.Get(info.ID); ok {
			live++
		}
	}
	if live != 1 {
		t.Fatalf("live sessions = %d, want 1", live)
	}
}
