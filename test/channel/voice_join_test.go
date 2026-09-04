package channel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/channel"
	"zephyr.vox/server/ce/internal/protocol"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/validation"
)

type voiceJoinTransport struct{}

func (voiceJoinTransport) RequestClose(int, string) {}

func (voiceJoinTransport) ForceClose() {}

// TestVoiceJoinPublishesAuthorityAndReplaysSensitiveResult verifies that one
// join allocates and activates exactly one Manager session at the publication
// boundary, while a retry returns the original response bytes and key.
func TestVoiceJoinPublishesAuthorityAndReplaysSensitiveResult(t *testing.T) {
	fixture := newFixture(t)
	channelSnapshot, _, err := fixture.service.CreateChannel(context.Background(), fixture.adminID, channel.CreateChannelInput{
		Name:       "Voice",
		Mode:       "voice",
		Visibility: "public",
		Capacity:   2,
		Position:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	channelID := mustID(t, channelSnapshot.ID)
	clock := func() time.Time { return time.UnixMilli(1_000) }
	manager := protocol.NewManager(clock)
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(fixture.adminID, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref, _, err := reservation.Activate(voiceJoinTransport{}, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.SetVoiceRuntime(manager, coordinator, true)
	signer, err := realtime.NewRequestIdentitySigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.SetVoiceIdempotency(realtime.NewRuntimeIdempotencyCache(), signer)
	fixture.service.SetVoiceClock(func() int64 { return 1_000 })

	e := echo.New()
	e.Validator = validation.New()
	e.HTTPErrorHandler = api.NewErrorHandler(slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.Use(rbacecho.AuthN(func(*echo.Context) (*rbac.Principal, error) {
		return &rbac.Principal{UserID: fixture.adminID}, nil
	}))
	e.POST("/api/v0/channels/:id/join", channel.VoiceJoinHandler(fixture.service))
	e.POST("/api/v0/channels/current/leave", channel.VoiceLeaveHandler(fixture.service))

	key := "voice-join-key-01"
	requestBody := []byte(`{"device_id":"desktop","force_new":false}`)
	record := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v0/channels/"+strconv.FormatInt(channelID, 10)+"/join", bytes.NewReader(requestBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set("X-Zephyr-Control-Connection", ref.IDHex())
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}

	first := record()
	if first.Code != http.StatusOK {
		t.Fatalf("first join status = %d, body = %s", first.Code, first.Body.String())
	}
	if first.Header().Get("Cache-Control") != "no-store" || first.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("join cache headers = %+v", first.Header())
	}
	var envelope struct {
		Code int `json:"code"`
		Data struct {
			Voice struct {
				Created   bool   `json:"created"`
				SessionID string `json:"session_id"`
				Key       string `json:"key"`
			} `json:"voice"`
		} `json:"data"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != 0 || !envelope.Data.Voice.Created || envelope.Data.Voice.Key == "" || len(envelope.Data.Voice.SessionID) != 32 {
		t.Fatalf("first join envelope = %+v", envelope)
	}
	authority, ok := coordinator.VoiceAuthority(fixture.adminID)
	if !ok || authority.ChannelID != channelID || authority.ControlConnectionID != ref.ControlConnectionID {
		t.Fatalf("authority = %+v, ok=%t", authority, ok)
	}
	if got, ok := manager.SessionIDByUser(fixture.adminID); !ok || got != authority.VoiceSessionID {
		t.Fatalf("manager session = %x, ok=%t; authority = %x", got, ok, authority.VoiceSessionID)
	}
	if got := fixture.state.Current().VoiceAuthorities(); len(got) != 1 || got[0] != authority {
		t.Fatalf("published authorities = %+v, want %+v", got, authority)
	}

	second := record()
	if second.Code != http.StatusOK || !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatalf("replay status/body = %d/%s, want exact first response %s", second.Code, second.Body.String(), first.Body.String())
	}

	leaveKey := "voice-leave-key-01"
	leaveBody := []byte(`{"voice_session_id":"` + envelope.Data.Voice.SessionID + `"}`)
	leave := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v0/channels/current/leave", bytes.NewReader(leaveBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set("X-Zephyr-Control-Connection", ref.IDHex())
		req.Header.Set("Idempotency-Key", leaveKey)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	leaveFirst := leave()
	if leaveFirst.Code != http.StatusNoContent || leaveFirst.Body.Len() != 0 {
		t.Fatalf("leave status/body = %d/%s", leaveFirst.Code, leaveFirst.Body.String())
	}
	if _, ok := coordinator.VoiceAuthority(fixture.adminID); ok {
		t.Fatal("voice authority remains after leave")
	}
	if _, ok := manager.SessionIDByUser(fixture.adminID); ok {
		t.Fatal("voice session remains after leave")
	}
	if _, ok := fixture.state.Current().VoiceAuthority(fixture.adminID); ok {
		t.Fatal("published voice authority remains after leave")
	}
	lastAuthority, lastMemberLeft := -1, -1
	for index, event := range fixture.publication.Capture().Events {
		switch event.EventType {
		case "voice.authority.updated":
			lastAuthority = index
		case "channel.member.left":
			lastMemberLeft = index
		}
	}
	if lastAuthority < 0 || lastMemberLeft < 0 || lastAuthority > lastMemberLeft {
		t.Fatalf("leave event order = authority %d, member.left %d", lastAuthority, lastMemberLeft)
	}
	leaveReplay := leave()
	if leaveReplay.Code != http.StatusNoContent || leaveReplay.Body.Len() != 0 {
		t.Fatalf("leave replay status/body = %d/%s", leaveReplay.Code, leaveReplay.Body.String())
	}
}

// TestVoiceJoinFoldsPendingOwnerTeardown proves a fast rejoin publishes the
// queued owner-WS teardown before the new membership and authority events.
func TestVoiceJoinFoldsPendingOwnerTeardown(t *testing.T) {
	fixture := newFixture(t)
	channelSnapshot, _, err := fixture.service.CreateChannel(context.Background(), fixture.adminID, channel.CreateChannelInput{
		Name:       "Voice",
		Mode:       "voice",
		Visibility: "public",
		Capacity:   2,
		Position:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	channelID := mustID(t, channelSnapshot.ID)
	manager := protocol.NewManager(func() time.Time { return time.UnixMilli(1_000) })
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(fixture.adminID, 1)
	if err != nil {
		t.Fatal(err)
	}
	oldRef, _, err := reservation.Activate(voiceJoinTransport{}, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.SetVoiceRuntime(manager, coordinator, false)
	fixture.service.SetVoiceClock(func() int64 { return 1_000 })
	signer, err := realtime.NewRequestIdentitySigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.SetVoiceIdempotency(realtime.NewRuntimeIdempotencyCache(), signer)
	if _, err := fixture.service.JoinVoice(context.Background(), fixture.adminID, channelID, oldRef.ControlConnectionID, "old-voice-key-01", channel.VoiceJoinInput{DeviceID: "desktop"}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if !coordinator.BeginDisconnect(oldRef, 4000, "eof") {
		t.Fatal("old owner disconnect did not claim connection")
	}
	newReservation, err := coordinator.ReserveConnect(fixture.adminID, 1)
	if err != nil {
		t.Fatal(err)
	}
	newRef, _, err := newReservation.Activate(voiceJoinTransport{}, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.JoinVoice(context.Background(), fixture.adminID, channelID, newRef.ControlConnectionID, "new-voice-key-01", channel.VoiceJoinInput{DeviceID: "desktop-2"}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}

	events := fixture.publication.Capture().Events
	if len(events) < 5 {
		t.Fatalf("published events = %+v", events)
	}
	got := make([]string, 0, 5)
	for _, event := range events[len(events)-5:] {
		got = append(got, event.EventType)
	}
	want := []string{"voice.revoked", "voice.authority.updated", "channel.member.left", "channel.member.joined", "voice.authority.updated"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("fast rejoin event order = %v, want %v", got, want)
	}
}

// TestVoiceJoinCancelsPriorTemporaryExpiryTimer proves invalidating a target
// channel's grace period removes the old scheduler entry after publication.
func TestVoiceJoinCancelsPriorTemporaryExpiryTimer(t *testing.T) {
	fixture := newFixture(t)
	channelSnapshot, _, err := fixture.service.CreateChannel(context.Background(), fixture.adminID, channel.CreateChannelInput{
		Name:       "Temporary voice",
		Mode:       "voice",
		Temporary:  true,
		Visibility: "public",
		Capacity:   2,
		Position:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	channelID := mustID(t, channelSnapshot.ID)
	callback := make(chan realtime.DeadlineTask, 1)
	scheduler := realtime.NewDeadlineScheduler(func(task realtime.DeadlineTask) { callback <- task })
	if scheduler == nil {
		t.Fatal("nil deadline scheduler")
	}
	t.Cleanup(func() { _ = scheduler.Close(context.Background()) })
	fixture.service.SetDeadlineScheduler(scheduler)
	candidate, err := fixture.state.BuildRuntimeCandidate()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(500 * time.Millisecond).UnixMilli()
	schedule, err := candidate.ScheduleTemporaryExpiry(channelID, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publication.Commit(realtime.PublicationRequest{Candidate: candidate}); err != nil {
		t.Fatal(err)
	}
	scheduler.Schedule(realtime.DeadlineTask{Kind: "temporary", ID: channelID, Generation: schedule.Generation, Deadline: schedule.Deadline})

	manager := protocol.NewManager(func() time.Time { return time.UnixMilli(1_000) })
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(fixture.adminID, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref, _, err := reservation.Activate(voiceJoinTransport{}, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.SetVoiceRuntime(manager, coordinator, false)
	fixture.service.SetVoiceClock(func() int64 { return 1_000 })
	signer, err := realtime.NewRequestIdentitySigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.SetVoiceIdempotency(realtime.NewRuntimeIdempotencyCache(), signer)
	if _, err := fixture.service.JoinVoice(context.Background(), fixture.adminID, channelID, ref.ControlConnectionID, "temporary-join-key", channel.VoiceJoinInput{DeviceID: "desktop"}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	select {
	case task := <-callback:
		t.Fatalf("invalidated temporary timer fired: %+v", task)
	case <-time.After(700 * time.Millisecond):
	}
}

// TestVoiceAccessLossRevokesManagerAndAuthority verifies that a persistent
// visibility mutation clears the ephemeral voice binding in the same
// StatePublication instead of leaving an inaccessible session alive.
func TestVoiceAccessLossRevokesManagerAndAuthority(t *testing.T) {
	fixture := newFixture(t)
	channelSnapshot, _, err := fixture.service.CreateChannel(context.Background(), fixture.adminID, channel.CreateChannelInput{
		Name:       "Private after revoke",
		Mode:       "voice",
		Visibility: "public",
		Capacity:   2,
		Position:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	channelID := mustID(t, channelSnapshot.ID)
	manager := protocol.NewManager(func() time.Time { return time.UnixMilli(1_000) })
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(fixture.adminID, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref, _, err := reservation.Activate(voiceJoinTransport{}, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.SetVoiceRuntime(manager, coordinator, true)
	signer, err := realtime.NewRequestIdentitySigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.SetVoiceIdempotency(realtime.NewRuntimeIdempotencyCache(), signer)
	fixture.service.SetVoiceClock(func() int64 { return 1_000 })
	if _, err := fixture.service.JoinVoice(context.Background(), fixture.adminID, channelID, ref.ControlConnectionID, "voice-access-key-01", channel.VoiceJoinInput{}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	_, etag, err := fixture.service.GetChannel(fixture.adminID, channelID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.service.UpdateChannel(context.Background(), fixture.adminID, channelID, etag, channel.UpdateChannelInput{Visibility: stringPtr("private")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := coordinator.VoiceAuthority(fixture.adminID); ok {
		t.Fatal("coordinator retained inaccessible voice authority")
	}
	if _, ok := manager.SessionIDByUser(fixture.adminID); ok {
		t.Fatal("manager retained inaccessible voice session")
	}
	if _, ok := fixture.state.Current().VoiceAuthority(fixture.adminID); ok {
		t.Fatal("StateStore retained inaccessible voice authority")
	}
	lastLifecycle, lastAuthority, lastMemberLeft := -1, -1, -1
	for index, event := range fixture.publication.Capture().Events {
		switch event.EventType {
		case "voice.revoked", "voice.disconnected":
			lastLifecycle = index
		case "voice.authority.updated":
			lastAuthority = index
		case "channel.member.left":
			lastMemberLeft = index
		}
	}
	if lastLifecycle < 0 || lastAuthority < 0 || lastMemberLeft < 0 || lastAuthority > lastMemberLeft || lastLifecycle > lastAuthority {
		t.Fatalf("access-loss event order = lifecycle %d, authority %d, member.left %d", lastLifecycle, lastAuthority, lastMemberLeft)
	}
}

// TestVoiceMoveArmsSourceTemporaryExpiry verifies that a cross-channel move
// invalidates the target timer and starts the same 30-second grace timer for a
// source temporary channel that became empty.
func TestVoiceMoveArmsSourceTemporaryExpiry(t *testing.T) {
	fixture := newFixture(t)
	ctx := context.Background()
	source, _, err := fixture.service.CreateChannel(ctx, fixture.adminID, channel.CreateChannelInput{
		Name:       "Temporary source",
		Mode:       "voice",
		Temporary:  true,
		Visibility: "public",
		Capacity:   2,
		Position:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, _, err := fixture.service.CreateChannel(ctx, fixture.adminID, channel.CreateChannelInput{
		Name:       "Temporary target",
		Mode:       "voice",
		Temporary:  true,
		Visibility: "public",
		Capacity:   2,
		Position:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceID := mustID(t, source.ID)
	targetID := mustID(t, target.ID)

	manager := protocol.NewManager(func() time.Time { return time.UnixMilli(1_000) })
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(fixture.adminID, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref, _, err := reservation.Activate(voiceJoinTransport{}, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.SetVoiceRuntime(manager, coordinator, false)
	fixture.service.SetVoiceClock(func() int64 { return 1_000 })
	signer, err := realtime.NewRequestIdentitySigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.SetVoiceIdempotency(realtime.NewRuntimeIdempotencyCache(), signer)

	if _, err := fixture.service.JoinVoice(ctx, fixture.adminID, sourceID, ref.ControlConnectionID, "temporary-source-key", channel.VoiceJoinInput{DeviceID: "desktop"}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	authority, ok := coordinator.VoiceAuthority(fixture.adminID)
	if !ok {
		t.Fatal("source join did not create voice authority")
	}
	if _, err := fixture.service.JoinVoice(ctx, fixture.adminID, targetID, ref.ControlConnectionID, "temporary-target-key", channel.VoiceJoinInput{
		ExpectedVoiceSessionID: fmt.Sprintf("%x", authority.VoiceSessionID),
	}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	sourceSchedule, sourceScheduled := fixture.state.Current().TemporaryExpiry(sourceID)
	if !sourceScheduled || sourceSchedule.Deadline != 31_000 || sourceSchedule.Generation == 0 {
		t.Fatalf("source temporary schedule = %+v, scheduled=%t", sourceSchedule, sourceScheduled)
	}
	targetSchedule, targetScheduled := fixture.state.Current().TemporaryExpiry(targetID)
	if !targetScheduled || targetSchedule.Deadline != 0 || targetSchedule.Generation == 0 {
		t.Fatalf("target temporary schedule = %+v, scheduled=%t", targetSchedule, targetScheduled)
	}
}
