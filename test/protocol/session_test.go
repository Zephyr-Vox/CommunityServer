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

func activateSession(t *testing.T, m *protocol.Manager, userID int64, deviceID string, encrypted bool) (protocol.SessionInfo, error) {
	t.Helper()
	prepared, err := m.Prepare(userID, deviceID, encrypted)
	if err != nil {
		return protocol.SessionInfo{}, err
	}
	return m.ActivatePrepared(prepared, nil)
}

func TestManagerActivationCreatesUniqueSessionsAndKeys(t *testing.T) {
	m, _ := newTestManager(t)
	a, err := activateSession(t, m, 10, "dev-a", true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := activateSession(t, m, 11, "dev-b", true)
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

func TestManagerPrepareRejectsInvalidUser(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := activateSession(t, m, 0, "", false); !errors.Is(err, protocol.ErrInvalidUserID) {
		t.Fatalf("err = %v, want ErrInvalidUserID", err)
	}
}

func TestManagerGetExpiresLazily(t *testing.T) {
	m, clock := newTestManager(t)
	info, err := activateSession(t, m, 1, "", false)
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
	_, err := activateSession(t, m, 1, "", false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = activateSession(t, m, 2, "", false)
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

func TestManagerActivationPreemptsOldSession(t *testing.T) {
	m, _ := newTestManager(t)
	oldInfo, err := activateSession(t, m, 7, "old-device", false)
	if err != nil {
		t.Fatal(err)
	}

	newInfo, err := activateSession(t, m, 7, "new-device", false)
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
}

func TestManagerInvalidateUserRevokes(t *testing.T) {
	m, _ := newTestManager(t)
	info, err := activateSession(t, m, 7, "dev", true)
	if err != nil {
		t.Fatal(err)
	}
	if n := m.InvalidateUser(7); n != 1 {
		t.Fatalf("InvalidateUser = %d, want 1", n)
	}
	if _, ok := m.Get(info.ID); ok {
		t.Fatal("invalidated session still present")
	}
	if n := m.InvalidateUser(7); n != 0 {
		t.Fatalf("second InvalidateUser = %d, want 0", n)
	}
}

func TestManagerDeleteOwnershipAndNoRevocation(t *testing.T) {
	m, _ := newTestManager(t)
	info, err := activateSession(t, m, 7, "", false)
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
	info, err := activateSession(t, m, 7, "", false)
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
	if _, err := activateSession(t, m, 7, "", false); err != nil {
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
	info, err := activateSession(t, m, 7, "", false)
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
	info, err := activateSession(t, m, 7, "", false)
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

	_, err = activateSession(t, m, 8, "", false)
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

func TestManagerConcurrentActivationKeepsOneSession(t *testing.T) {
	m, _ := newTestManager(t)
	const n = 16
	infos := make(chan protocol.SessionInfo, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			info, err := activateSession(t, m, 7, "dev", false)
			if err != nil {
				t.Errorf("ActivatePrepared: %v", err)
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

func TestManagerActivatePreparedChecksExpectedSession(t *testing.T) {
	m, _ := newTestManager(t)
	old, err := activateSession(t, m, 7, "old", false)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := m.Prepare(7, "new", true)
	if err != nil {
		t.Fatal(err)
	}
	wrong := [16]byte{1}
	if _, err := m.ActivatePrepared(prepared, &wrong); !errors.Is(err, protocol.ErrSessionPrecondition) {
		t.Fatalf("wrong activation precondition = %v", err)
	}
	info, err := m.ActivatePrepared(prepared, &old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ReplacedPrevious || !info.Encrypted || info.MasterKey == nil {
		t.Fatalf("activation info = %+v", info)
	}
	if _, ok := m.Get(old.ID); ok {
		t.Fatal("old session remained active after prepared activation")
	}
	if _, err := m.ActivatePrepared(prepared, &old.ID); !errors.Is(err, protocol.ErrSessionPrecondition) {
		t.Fatalf("repeated activation = %v, want ErrSessionPrecondition", err)
	}
	snap, ok := m.Get(info.ID)
	if !ok || snap.ID != info.ID {
		t.Fatalf("active snapshot after repeated activation = (%+v, %v)", snap, ok)
	}
}

func TestManagerActivatePreparedRejectsForeignManager(t *testing.T) {
	owner, _ := newTestManager(t)
	other, _ := newTestManager(t)
	prepared, err := owner.Prepare(7, "dev", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.ActivatePrepared(prepared, nil); !errors.Is(err, protocol.ErrSessionPrecondition) {
		t.Fatalf("foreign activation = %v, want ErrSessionPrecondition", err)
	}
	if _, err := owner.ActivatePrepared(prepared, nil); err != nil {
		t.Fatalf("owner activation after foreign rejection = %v", err)
	}
}

func TestManagerConcurrentActivatePreparedUsesPreparedOnce(t *testing.T) {
	m, _ := newTestManager(t)
	prepared, err := m.Prepare(7, "dev", false)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			_, err := m.ActivatePrepared(prepared, nil)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, protocol.ErrSessionPrecondition) {
			t.Fatalf("ActivatePrepared error = %v", err)
		}
	}
	if successes != 1 || m.Len() != 1 {
		t.Fatalf("successful activations = %d, sessions = %d; want one each", successes, m.Len())
	}
}

func TestManagerInvalidateAndActivatePreparedLeaveNoStaleIndex(t *testing.T) {
	for range 32 {
		m, _ := newTestManager(t)
		old, err := activateSession(t, m, 7, "old", false)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := m.Prepare(7, "new", false)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			<-start
			_ = m.InvalidateUser(7)
		})
		wg.Go(func() {
			<-start
			_, _ = m.ActivatePrepared(prepared, &old.ID)
		})
		close(start)
		wg.Wait()
		if m.Len() != 0 {
			t.Fatalf("Invalidate/Activate left %d sessions", m.Len())
		}
		if _, ok := m.SessionIDByUser(7); ok {
			t.Fatal("Invalidate/Activate left a user index")
		}
	}
}

func TestManagerPurgeAndActivatePreparedKeepIndexesConsistent(t *testing.T) {
	for range 32 {
		m, clock := newTestManager(t)
		old, err := activateSession(t, m, 7, "old", false)
		if err != nil {
			t.Fatal(err)
		}
		clock.Advance(protocol.SessionTTL)
		prepared, err := m.Prepare(7, "new", false)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			<-start
			_ = m.Purge()
		})
		wg.Go(func() {
			<-start
			_, _ = m.ActivatePrepared(prepared, &old.ID)
		})
		close(start)
		wg.Wait()
		id, indexed := m.SessionIDByUser(7)
		if indexed {
			if _, ok := m.Get(id); !ok {
				t.Fatal("user index referenced a missing session")
			}
			if m.Len() != 1 {
				t.Fatalf("live index with Len = %d, want 1", m.Len())
			}
		} else if m.Len() != 0 {
			t.Fatalf("missing user index with Len = %d", m.Len())
		}
	}
}

func TestManagerConcurrentLazyGetAndPurgeExpireOnce(t *testing.T) {
	m, clock := newTestManager(t)
	info, err := activateSession(t, m, 7, "dev", false)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(protocol.SessionTTL)
	called := make(chan struct{}, 2)
	m.SetExpiryHandler(func(int64, [16]byte) { called <- struct{}{} })
	var wg sync.WaitGroup
	wg.Go(func() { _, _ = m.Get(info.ID) })
	wg.Go(func() { _ = m.Purge() })
	wg.Wait()
	select {
	case <-called:
	default:
		t.Fatal("expired session did not invoke handler")
	}
	select {
	case <-called:
		t.Fatal("expired session invoked handler more than once")
	default:
	}
}

// TestManagerRevokeStagedIsSynchronousInactive proves RevokeStaged removes the
// exact session from the Manager indexes before returning and defers only the
// sendMu/notification work to the returned cleanup.
func TestManagerRevokeStagedIsSynchronousInactive(t *testing.T) {
	m, _ := newTestManager(t)
	sess, err := activateSession(t, m, 7, "dev", false)
	if err != nil {
		t.Fatal(err)
	}

	cleanup, err := m.RevokeStaged(sess.ID, 7)
	if err != nil {
		t.Fatalf("staged revoke = %v", err)
	}
	if cleanup == nil {
		t.Fatal("staged revoke returned no cleanup")
	}
	if _, ok := m.Get(sess.ID); ok {
		t.Fatal("session remained in Manager indexes after staged revoke")
	}
	if _, err := m.RevokeStaged(sess.ID, 7); !errors.Is(err, protocol.ErrSessionNotFound) {
		t.Fatalf("repeated staged revoke = %v, want ErrSessionNotFound", err)
	}
	cleanup()

	foreign, err := activateSession(t, m, 8, "other", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.RevokeStaged(foreign.ID, 7); !errors.Is(err, protocol.ErrSessionNotOwned) {
		t.Fatalf("foreign staged revoke = %v, want ErrSessionNotOwned", err)
	}
}
