package realtime_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/protocol"
	"zephyr.vox/server/ce/internal/realtime"
)

type voiceStopRecorder struct {
	mu      sync.Mutex
	userID  int64
	session [16]byte
	reason  string
	calls   int
}

func (r *voiceStopRecorder) Stop(userID int64, sessionID [16]byte, reason string) {
	r.mu.Lock()
	r.userID = userID
	r.session = sessionID
	r.reason = reason
	r.calls++
	r.mu.Unlock()
}

func TestVoiceAuthorityStageReplacementAndStaleTeardown(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := reservation.Activate(&closeRecorder{}, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	manager := protocol.NewManager(time.Now)

	prepared, err := manager.Prepare(7, "desktop", true)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := coordinator.StageVoiceReplacement(owner, nil, 101, prepared, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	first, err := stage.Apply(manager)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Current.Valid() || first.Current.ChannelID != 101 || first.Current.ControlConnectionID != owner.ControlConnectionID || first.Current.ConnectionGeneration != owner.Generation || first.Current.VoiceAuthorityGeneration != 1 {
		t.Fatalf("first authority = %+v", first.Current)
	}
	if first.Previous != nil {
		t.Fatalf("first previous = %+v, want nil", first.Previous)
	}
	if first.Cleanup != nil {
		first.Cleanup()
	}

	move, err := coordinator.StageVoiceReplacement(owner, &first.Current, 202, nil, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	second, err := move.Apply(manager)
	if err != nil {
		t.Fatal(err)
	}
	if second.Current.ChannelID != 202 || second.Current.VoiceSessionID != first.Current.VoiceSessionID || second.Current.VoiceAuthorityGeneration != 2 {
		t.Fatalf("moved authority = %+v", second.Current)
	}
	if second.Previous == nil || *second.Previous != first.Current {
		t.Fatalf("move previous = %+v, want %+v", second.Previous, first.Current)
	}

	if _, removed, err := coordinator.BeginVoiceDisconnect(first.Current, manager); err != nil || removed {
		t.Fatalf("stale teardown = (_, %v, %v), want (_, false, nil)", removed, err)
	}
	if current, ok := coordinator.VoiceAuthority(7); !ok || current != second.Current {
		t.Fatalf("authority after stale teardown = (%+v, %v), want moved authority", current, ok)
	}
	removed, ok, err := coordinator.BeginVoiceDisconnect(second.Current, manager)
	if err != nil || !ok || removed != second.Current {
		t.Fatalf("current teardown = (%+v, %v, %v), want moved authority,true,nil", removed, ok, err)
	}
	if _, ok := coordinator.VoiceAuthority(7); ok {
		t.Fatal("voice authority remains after current teardown")
	}
	if _, ok := manager.Get(second.Current.VoiceSessionID); ok {
		t.Fatal("voice session remains after authority teardown")
	}
}

// TestVoiceAuthorityStageRecoversAfterNaturalSessionExpiry proves that a UDP
// expiry removing Manager's user index before coordinator teardown does not
// make a force-new replacement fail during runtime publication.
func TestVoiceAuthorityStageRecoversAfterNaturalSessionExpiry(t *testing.T) {
	now := time.Now()
	clock := now
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := reservation.Activate(&closeRecorder{}, now.Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	manager := protocol.NewManager(func() time.Time { return clock })
	prepared, err := manager.Prepare(7, "desktop", false)
	if err != nil {
		t.Fatal(err)
	}
	firstStage, err := coordinator.StageVoiceReplacement(owner, nil, 101, prepared, now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstStage.Apply(manager)
	if err != nil {
		t.Fatal(err)
	}

	clock = now.Add(protocol.SessionTTL + time.Second)
	if _, ok := manager.SessionIDByUser(7); ok {
		t.Fatal("expired session remained indexed")
	}
	replacement, err := manager.Prepare(7, "desktop-2", false)
	if err != nil {
		t.Fatal(err)
	}
	secondStage, err := coordinator.StageVoiceReplacement(owner, &first.Current, 202, replacement, clock.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	second, err := secondStage.Apply(manager)
	if err != nil {
		t.Fatalf("replacement after expiry = %v", err)
	}
	if second.Current.ChannelID != 202 || second.Current.VoiceSessionID == first.Current.VoiceSessionID {
		t.Fatalf("replacement authority = %+v", second.Current)
	}
}

// TestVoiceAuthorityTombstoneIsConsumedByReplacement proves a pending
// asynchronous teardown marker cannot survive a later successful rejoin.
func TestVoiceAuthorityTombstoneIsConsumedByReplacement(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := reservation.Activate(&closeRecorder{}, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	manager := protocol.NewManager(time.Now)
	prepared, err := manager.Prepare(7, "desktop", false)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := coordinator.StageVoiceReplacement(owner, nil, 101, prepared, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	first, err := stage.Apply(manager)
	if err != nil {
		t.Fatal(err)
	}
	if !coordinator.BeginDisconnect(owner, 4000, "eof") {
		t.Fatal("disconnect did not claim owner")
	}
	tombstone, reason, ok := coordinator.PendingVoiceAuthorityTombstone(7)
	if !ok || tombstone != first.Current || reason != "eof" {
		t.Fatalf("tombstone = (%+v, %q, %v)", tombstone, reason, ok)
	}

	newReservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	newOwner, _, err := newReservation.Activate(&closeRecorder{}, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	newPrepared, err := manager.Prepare(7, "desktop-2", false)
	if err != nil {
		t.Fatal(err)
	}
	newStage, err := coordinator.StageVoiceReplacement(newOwner, nil, 202, newPrepared, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newStage.Apply(manager); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := coordinator.PendingVoiceAuthorityTombstone(7); ok {
		t.Fatal("voice teardown tombstone survived replacement")
	}
}

func TestVoiceAuthorityStageRejectsOldConnectionGeneration(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	oldReservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	oldOwner, _, err := oldReservation.Activate(&closeRecorder{}, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	coordinator.BeginDisconnect(oldOwner, 4000, "old connection")
	coordinator.FinishDisconnect(oldOwner)
	newReservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	newOwner, _, err := newReservation.Activate(&closeRecorder{}, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	manager := protocol.NewManager(time.Now)
	prepared, err := manager.Prepare(7, "desktop", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.StageVoiceReplacement(oldOwner, nil, 101, prepared, time.Now().UnixMilli()); !errors.Is(err, realtime.ErrVoiceAuthorityPrecondition) {
		t.Fatalf("old owner stage = %v, want ErrVoiceAuthorityPrecondition", err)
	}
	if _, err := coordinator.StageVoiceReplacement(newOwner, nil, 101, prepared, time.Now().UnixMilli()); err != nil {
		t.Fatalf("new owner stage = %v", err)
	}
}

// TestVoiceAuthorityStageRejectsPreparedSessionForAnotherUser prevents one
// manager-owned prepared session from becoming authority for a different user.
func TestVoiceAuthorityStageRejectsPreparedSessionForAnotherUser(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := reservation.Activate(&closeRecorder{}, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	manager := protocol.NewManager(time.Now)
	prepared, err := manager.Prepare(8, "other-user", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.StageVoiceReplacement(owner, nil, 101, prepared, time.Now().UnixMilli()); !errors.Is(err, realtime.ErrVoiceAuthorityPrecondition) {
		t.Fatalf("cross-user prepared session = %v, want ErrVoiceAuthorityPrecondition", err)
	}
}

func TestVoiceOwnerConnectionCloseStopsOnlyCurrentAuthority(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	recorder := &voiceStopRecorder{}
	coordinator.SetVoiceAuthorityDeactivator(func(authority realtime.VoiceAuthority, reason string) {
		recorder.Stop(authority.UserID, authority.VoiceSessionID, reason)
	})
	reservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := reservation.Activate(&closeRecorder{}, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	manager := protocol.NewManager(time.Now)
	prepared, err := manager.Prepare(7, "desktop", false)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := coordinator.StageVoiceReplacement(owner, nil, 101, prepared, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	commit, err := stage.Apply(manager)
	if err != nil {
		t.Fatal(err)
	}
	if commit.Cleanup != nil {
		commit.Cleanup()
	}
	if !coordinator.BeginDisconnect(owner, 4000, "eof") {
		t.Fatal("voice owner close did not claim connection")
	}
	recorder.mu.Lock()
	gotUser, gotSession, gotReason, calls := recorder.userID, recorder.session, recorder.reason, recorder.calls
	recorder.mu.Unlock()
	if calls != 1 || gotUser != 7 || gotSession != commit.Current.VoiceSessionID || gotReason != "eof" {
		t.Fatalf("voice stop = user=%d session=%x reason=%q calls=%d", gotUser, gotSession, gotReason, calls)
	}
	if _, ok := coordinator.VoiceAuthority(7); ok {
		t.Fatal("voice authority remains after owner close")
	}
}
