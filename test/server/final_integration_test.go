package server_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/protocol"
	"zephyr.vox/server/ce/internal/server"
)

// liveRun owns one real HTTP/WS/UDP application process for an integration
// test. The cleanup is idempotent so a test can assert the shutdown result
// explicitly without making t.Cleanup wait on the already-consumed Run.
type liveRun struct {
	app            *server.App
	cfg            *config.App
	baseURL        string
	client         *http.Client
	activationCode string
	stop           func() error
}

type liveUser struct {
	id    int64
	token string
}

type liveVoiceSession struct {
	id        [16]byte
	idHex     string
	encrypted bool
}

type liveEnvelope[T any] struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    T      `json:"data"`
}

type liveWSFrame struct {
	Type      string          `json:"type"`
	RequestID string          `json:"request_id"`
	EventType string          `json:"event_type"`
	Data      json.RawMessage `json:"data"`
}

// startLiveRun starts the assembled application with real TCP and UDP
// listeners. TLS is intentionally off here so the test exercises the
// plaintext voice branch without introducing certificate trust into the data
// path; encrypted negotiation remains covered by channel/protocol tests.
func startLiveRun(t *testing.T) *liveRun {
	t.Helper()
	dir := t.TempDir()
	cfg := testConfig(dir, freePort(t))
	cfg.Server.VoicePort = freeUDPPort(t)
	app, err := server.New(cfg, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	activationCode, ok, err := app.EnsureActivationCode(context.Background())
	if err != nil || !ok {
		app.Close()
		t.Fatalf("EnsureActivationCode = (_, %v, %v)", ok, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx) }()
	run := &liveRun{
		app:            app,
		cfg:            cfg,
		baseURL:        "http://" + net.JoinHostPort(cfg.Server.Host, fmt.Sprint(cfg.Server.HTTPPort)),
		client:         &http.Client{Timeout: 3 * time.Second},
		activationCode: activationCode,
	}
	var stopOnce sync.Once
	var stopErr error
	run.stop = func() error {
		stopOnce.Do(func() {
			cancel()
			select {
			case runErr := <-done:
				stopErr = runErr
			case <-time.After(15 * time.Second):
				stopErr = errors.New("server Run did not stop within 15 seconds")
			}
			stopErr = errors.Join(stopErr, app.Close())
		})
		return stopErr
	}
	t.Cleanup(func() {
		if err := run.stop(); err != nil {
			t.Errorf("live server cleanup: %v", err)
		}
	})
	waitReady(t, run.client, run.baseURL)
	return run
}

// freeUDPPort reserves and releases one local UDP port for a real server
// listener. The test suite is serial by default, and the subsequent bind is
// guarded by the server startup fail-fast check.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// liveRequest sends one HTTP request to the real application listener and
// returns the complete response body for envelope or empty-body assertions.
func liveRequest(t *testing.T, run *liveRun, method, path, token, idempotencyKey, controlID, body string, extra http.Header) (int, http.Header, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, run.baseURL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if controlID != "" {
		req.Header.Set("X-Zephyr-Control-Connection", controlID)
	}
	for key, values := range extra {
		for index, value := range values {
			if index == 0 {
				req.Header.Set(key, value)
			} else {
				req.Header.Add(key, value)
			}
		}
	}
	resp, err := run.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, responseBody
}

// liveData decodes a successful API envelope and fails with the server body
// when a real integration request unexpectedly returns a business error.
func liveData[T any](t *testing.T, body []byte) T {
	t.Helper()
	var envelope liveEnvelope[T]
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode API envelope %q: %v", body, err)
	}
	if envelope.Code != 0 {
		t.Fatalf("API envelope = %+v", envelope)
	}
	return envelope.Data
}

// bootstrapLiveUsers activates the first owner and registers a normal member
// through the public HTTP API, then returns both live access-token identities.
func bootstrapLiveUsers(t *testing.T, run *liveRun) (liveUser, liveUser) {
	t.Helper()
	status, _, body := liveRequest(t, run, http.MethodPost, "/api/v0/admin/activate", "", "live-activate-0001", "", `{"code":"`+run.activationCode+`","username":"boss","password":"secret123"}`, nil)
	if status != http.StatusOK {
		t.Fatalf("activate status = %d, body = %s", status, body)
	}
	status, _, body = liveRequest(t, run, http.MethodPost, "/api/v0/auth/register", "", "live-register-0001", "", `{"username":"member","password":"secret123"}`, nil)
	if status != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", status, body)
	}
	owner := liveLogin(t, run, "boss", "secret123", "live-owner-device")
	member := liveLogin(t, run, "member", "secret123", "live-member-device")
	return owner, member
}

// liveLogin signs in one user through the real listener and returns its
// snowflake identity plus bearer token.
func liveLogin(t *testing.T, run *liveRun, username, password, deviceID string) liveUser {
	t.Helper()
	status, _, body := liveRequest(t, run, http.MethodPost, "/api/v0/auth/login", "", "", "", fmt.Sprintf(`{"username":%q,"password":%q,"device_id":%q}`, username, password, deviceID), nil)
	if status != http.StatusOK {
		t.Fatalf("login %s status = %d, body = %s", username, status, body)
	}
	data := liveData[liveLoginData](t, body)
	if data.AccessToken == "" || data.User.ID <= 0 {
		t.Fatalf("login %s data = %+v", username, data)
	}
	return liveUser{id: data.User.ID, token: data.AccessToken}
}

type liveLoginData struct {
	AccessToken string `json:"access_token"`
	User        struct {
		ID int64 `json:"id"`
	} `json:"user"`
}

// createLiveVoiceChannel creates one public voice channel using the same
// sequenced HTTP mutation path used by production clients.
func createLiveVoiceChannel(t *testing.T, run *liveRun, owner liveUser) string {
	t.Helper()
	status, _, body := liveRequest(t, run, http.MethodPost, "/api/v0/channels", owner.token, "live-channel-0001", "", `{"name":"live-voice","mode":"voice","temporary":false,"visibility":"public","capacity":2,"position":1,"pinned":false}`, nil)
	if status != http.StatusCreated {
		t.Fatalf("create channel status = %d, body = %s", status, body)
	}
	data := liveData[struct {
		ID string `json:"id"`
	}](t, body)
	if data.ID == "" {
		t.Fatalf("created channel has empty ID: %s", body)
	}
	return data.ID
}

// snapshotCursor captures a replacement snapshot cursor before the next
// mutation. The subsequent WebSocket hello must replay every event after it.
func snapshotCursor(t *testing.T, run *liveRun, user liveUser) string {
	t.Helper()
	status, _, body := liveRequest(t, run, http.MethodGet, "/api/v0/state/snapshot", user.token, "", "", "", nil)
	if status != http.StatusOK {
		t.Fatalf("snapshot status = %d, body = %s", status, body)
	}
	data := liveData[struct {
		Cursor string `json:"cursor"`
	}](t, body)
	if data.Cursor == "" {
		t.Fatalf("snapshot cursor is empty: %s", body)
	}
	return data.Cursor
}

// openLiveWS upgrades one real control connection and returns the server-
// assigned control ID required by voice HTTP mutations.
func openLiveWS(t *testing.T, run *liveRun, user liveUser) (*websocket.Conn, string) {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(run.baseURL, "http") + "/api/v0/ws"
	conn, response, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + user.token}})
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal(err)
	}
	frame, err := readLiveWSFrame(conn, 3*time.Second)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if frame.Type != "connection.ready" {
		conn.Close()
		t.Fatalf("first WS frame = %+v", frame)
	}
	var ready struct {
		ControlConnectionID string `json:"control_connection_id"`
	}
	if err := json.Unmarshal(frame.Data, &ready); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if len(ready.ControlConnectionID) != 32 {
		conn.Close()
		t.Fatalf("connection.ready = %+v", ready)
	}
	return conn, ready.ControlConnectionID
}

// readLiveWSFrame reads one text frame with a bounded deadline, keeping all
// socket reads in the test on one goroutine at a time like the production
// read pump contract.
func readLiveWSFrame(conn *websocket.Conn, timeout time.Duration) (liveWSFrame, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return liveWSFrame{}, err
	}
	messageType, payload, err := conn.ReadMessage()
	if err != nil {
		return liveWSFrame{}, err
	}
	if messageType != websocket.TextMessage {
		return liveWSFrame{}, fmt.Errorf("unexpected websocket message type %d", messageType)
	}
	var frame liveWSFrame
	if err := json.Unmarshal(payload, &frame); err != nil {
		return liveWSFrame{}, err
	}
	return frame, nil
}

// syncLiveWS performs the v1 hello/replay/complete handshake and returns all
// event types observed in replay frames during that atomic handoff.
func syncLiveWS(t *testing.T, conn *websocket.Conn, cursor string) []string {
	t.Helper()
	if err := conn.WriteJSON(map[string]any{
		"type": "sync.hello",
		"data": map[string]string{"cursor": cursor},
	}); err != nil {
		t.Fatal(err)
	}
	eventTypes := make([]string, 0)
	for {
		frame, err := readLiveWSFrame(conn, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "sync.replay":
			var replay struct {
				Events []struct {
					EventType string `json:"event_type"`
				} `json:"events"`
			}
			if err := json.Unmarshal(frame.Data, &replay); err != nil {
				t.Fatal(err)
			}
			for _, event := range replay.Events {
				eventTypes = append(eventTypes, event.EventType)
			}
		case "sync.complete":
			var complete struct {
				Cursor string `json:"cursor"`
			}
			if err := json.Unmarshal(frame.Data, &complete); err != nil {
				t.Fatal(err)
			}
			if complete.Cursor == "" {
				t.Fatal("sync.complete has empty cursor")
			}
			return eventTypes
		case "sync.required":
			t.Fatalf("unexpected sync replacement request: %s", frame.Data)
		default:
			t.Fatalf("unexpected handshake frame = %+v", frame)
		}
	}
}

// waitLiveEvent waits through unrelated ordered state events until one exact
// event type is observed on a live control connection.
func waitLiveEvent(t *testing.T, conn *websocket.Conn, want string) liveWSFrame {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		frame, err := readLiveWSFrame(conn, time.Until(deadline))
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type == "state.event" && frame.EventType == want {
			return frame
		}
		if frame.Type == "sync.replay" {
			var replay struct {
				Events []struct {
					EventType string `json:"event_type"`
				} `json:"events"`
			}
			if err := json.Unmarshal(frame.Data, &replay); err != nil {
				t.Fatal(err)
			}
			for _, event := range replay.Events {
				if event.EventType == want {
					return frame
				}
			}
		}
	}
	t.Fatalf("did not receive websocket event %q", want)
	return liveWSFrame{}
}

// joinLiveVoice performs one HTTP voice negotiation bound to a live WS
// control connection and returns the exact session tuple used by UDP.
func joinLiveVoice(t *testing.T, run *liveRun, user liveUser, channelID, controlID, key, deviceID string) liveVoiceSession {
	t.Helper()
	status, _, body := liveRequest(t, run, http.MethodPost, "/api/v0/channels/"+channelID+"/join", user.token, key, controlID, fmt.Sprintf(`{"device_id":%q,"force_new":false}`, deviceID), nil)
	if status != http.StatusOK {
		t.Fatalf("join user %d status = %d, body = %s", user.id, status, body)
	}
	data := liveData[struct {
		Voice struct {
			Created    bool   `json:"created"`
			SessionID  string `json:"session_id"`
			Encrypted  bool   `json:"encrypted"`
			MaxPayload int    `json:"max_payload"`
		} `json:"voice"`
	}](t, body)
	if !data.Voice.Created || len(data.Voice.SessionID) != 32 || data.Voice.MaxPayload <= 0 {
		t.Fatalf("join response = %+v", data)
	}
	var sessionID [16]byte
	decoded, err := hex.DecodeString(data.Voice.SessionID)
	if err != nil || len(decoded) != len(sessionID) {
		t.Fatalf("join session ID %q: %v", data.Voice.SessionID, err)
	}
	copy(sessionID[:], decoded)
	return liveVoiceSession{id: sessionID, idHex: data.Voice.SessionID, encrypted: data.Voice.Encrypted}
}

// openVoiceClient creates one real UDP peer for the process-wide voice port.
func openVoiceClient(t *testing.T, run *liveRun) *net.UDPConn {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: run.cfg.Server.VoicePort})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// sendVoiceHeartbeat teaches the server the peer address before a relay send.
func sendVoiceHeartbeat(t *testing.T, conn *net.UDPConn, session liveVoiceSession) {
	t.Helper()
	packet, err := protocol.EncodePacket(session.id, 1, session.encrypted, nil, protocol.ChannelHeader{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(packet); err != nil {
		t.Fatal(err)
	}
}

// waitForRelayedAudio retries one source frame over a bounded interval until
// the destination peer decodes the expected s2c packet. Sequence numbers stay
// strictly increasing even when the first packets race UDP read scheduling.
func waitForRelayedAudio(t *testing.T, source, destination *net.UDPConn, sourceSession, destinationSession liveVoiceSession, sourceUserID int64, payload []byte, nextTransportSeq *uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	channelSeq := uint16(1)
	buffer := make([]byte, protocol.MaxPacketSize+1)
	for time.Now().Before(deadline) {
		transportSeq := *nextTransportSeq
		*nextTransportSeq = transportSeq + 1
		packet, err := protocol.EncodePacket(sourceSession.id, transportSeq, sourceSession.encrypted, nil, protocol.ChannelHeader{ChannelType: 1, ChannelSeq: channelSeq}, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := source.Write(packet); err != nil {
			t.Fatal(err)
		}
		readDeadline := time.Now().Add(100 * time.Millisecond)
		if readDeadline.After(deadline) {
			readDeadline = deadline
		}
		if err := destination.SetReadDeadline(readDeadline); err != nil {
			t.Fatal(err)
		}
		n, err := destination.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			t.Fatal(err)
		}
		gotID, _, header, gotPayload, ok := protocol.DecodePacket(buffer[:n], destinationSession.encrypted, nil)
		if ok && gotID == destinationSession.id && header.ChannelType == 1 && header.ChannelSeq == channelSeq && header.SpeakerID == sourceUserID && bytes.Equal(gotPayload, payload) {
			return
		}
	}
	t.Fatalf("no relayed audio for source session %s", sourceSession.idHex)
}

// drainUDP removes retries already queued by the relay before a teardown
// assertion. It deliberately treats a read deadline as the normal result.
func drainUDP(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	deadline := time.Now().Add(100 * time.Millisecond)
	buffer := make([]byte, protocol.MaxPacketSize+1)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Read(buffer); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return
			}
			t.Fatal(err)
		}
	}
}

// expectNoUDPFrame verifies that a revoked or voluntarily left session no
// longer receives source media on its old UDP peer.
func expectNoUDPFrame(t *testing.T, conn *net.UDPConn, timeout time.Duration) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, protocol.MaxPacketSize+1)
	if _, err := conn.Read(buffer); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return
		}
		t.Fatal(err)
	}
	t.Fatalf("unexpected UDP frame after teardown")
}

// TestFinalIntegrationVoiceSnapshotReplayRelayLeaveAndRevoke covers the
// production process boundary: HTTP snapshot, WS replay and control identity,
// HTTP voice activation, real UDP relay fanout, voluntary leave, and channel
// visibility revocation stopping a stale source session.
func TestFinalIntegrationVoiceSnapshotReplayRelayLeaveAndRevoke(t *testing.T) {
	run := startLiveRun(t)
	owner, member := bootstrapLiveUsers(t, run)
	channelID := createLiveVoiceChannel(t, run, owner)

	ownerCursor := snapshotCursor(t, run, owner)
	memberCursor := snapshotCursor(t, run, member)
	ownerWS, ownerControlID := openLiveWS(t, run, owner)
	defer ownerWS.Close()
	if events := syncLiveWS(t, ownerWS, ownerCursor); len(events) == 0 {
		t.Fatal("owner handshake replay is empty; connection activation should be sequenced")
	}

	ownerSession := joinLiveVoice(t, run, owner, channelID, ownerControlID, "live-owner-join-0001", "live-owner-voice")
	memberWS, memberControlID := openLiveWS(t, run, member)
	defer memberWS.Close()
	memberReplay := syncLiveWS(t, memberWS, memberCursor)
	if !containsString(memberReplay, "channel.member.joined") {
		t.Fatalf("member replay = %v, want owner channel.member.joined", memberReplay)
	}
	memberSession := joinLiveVoice(t, run, member, channelID, memberControlID, "live-member-join-0001", "live-member-voice")

	ownerUDP := openVoiceClient(t, run)
	defer ownerUDP.Close()
	memberUDP := openVoiceClient(t, run)
	defer memberUDP.Close()
	sendVoiceHeartbeat(t, ownerUDP, ownerSession)
	sendVoiceHeartbeat(t, memberUDP, memberSession)
	ownerNextSeq := uint64(2)
	memberNextSeq := uint64(2)
	waitForRelayedAudio(t, ownerUDP, memberUDP, ownerSession, memberSession, owner.id, []byte("owner-audio"), &ownerNextSeq)
	drainUDP(t, memberUDP)

	status, _, body := liveRequest(t, run, http.MethodPost, "/api/v0/channels/current/leave", member.token, "live-member-leave-0001", memberControlID, fmt.Sprintf(`{"voice_session_id":%q}`, memberSession.idHex), nil)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("member leave status = %d, body = %s", status, body)
	}
	waitLiveEvent(t, ownerWS, "channel.member.left")
	for index := 0; index < 3; index++ {
		packet, err := protocol.EncodePacket(ownerSession.id, ownerNextSeq, false, nil, protocol.ChannelHeader{ChannelType: 1, ChannelSeq: uint16(index + 2)}, []byte("after-leave"))
		if err != nil {
			t.Fatal(err)
		}
		ownerNextSeq++
		if _, err := ownerUDP.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	expectNoUDPFrame(t, memberUDP, 250*time.Millisecond)

	// Rejoin on the still-live member WS so the same process test exercises both
	// voluntary leave and a later access-loss revoke with a real recipient.
	memberSession = joinLiveVoice(t, run, member, channelID, memberControlID, "live-member-join-0002", "live-member-voice-2")
	memberNextSeq = 2
	sendVoiceHeartbeat(t, memberUDP, memberSession)
	drainUDP(t, ownerUDP)
	waitForRelayedAudio(t, memberUDP, ownerUDP, memberSession, ownerSession, member.id, []byte("member-audio"), &memberNextSeq)
	drainUDP(t, ownerUDP)

	status, headers, body := liveRequest(t, run, http.MethodGet, "/api/v0/channels/"+channelID, owner.token, "", "", "", nil)
	if status != http.StatusOK {
		t.Fatalf("get channel status = %d, body = %s", status, body)
	}
	etag := headers.Get("ETag")
	if etag == "" {
		t.Fatal("get channel did not return ETag")
	}
	extra := make(http.Header)
	extra.Set("If-Match", etag)
	status, _, body = liveRequest(t, run, http.MethodPatch, "/api/v0/channels/"+channelID, owner.token, "live-channel-private-0001", "", `{"visibility":"private"}`, extra)
	if status != http.StatusOK {
		t.Fatalf("make channel private status = %d, body = %s", status, body)
	}
	waitLiveEvent(t, memberWS, "voice.revoked")
	for index := 0; index < 3; index++ {
		packet, err := protocol.EncodePacket(memberSession.id, memberNextSeq, false, nil, protocol.ChannelHeader{ChannelType: 1, ChannelSeq: uint16(index + 10)}, []byte("after-revoke"))
		if err != nil {
			t.Fatal(err)
		}
		memberNextSeq++
		if _, err := memberUDP.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	expectNoUDPFrame(t, ownerUDP, 250*time.Millisecond)
}

// containsString reports whether one replay batch includes an exact event
// type without coupling the test to unrelated presence events.
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// TestFinalIntegrationShutdownClosesActiveWebSocketAndUDP verifies the
// process lifecycle boundary with an authenticated control socket and an
// active UDP voice session, then confirms the UDP port is reusable.
func TestFinalIntegrationShutdownClosesActiveWebSocketAndUDP(t *testing.T) {
	run := startLiveRun(t)
	owner, _ := bootstrapLiveUsers(t, run)
	channelID := createLiveVoiceChannel(t, run, owner)
	cursor := snapshotCursor(t, run, owner)
	conn, controlID := openLiveWS(t, run, owner)
	defer conn.Close()
	syncLiveWS(t, conn, cursor)
	session := joinLiveVoice(t, run, owner, channelID, controlID, "live-shutdown-join-0001", "live-shutdown-voice")
	udp := openVoiceClient(t, run)
	defer udp.Close()
	sendVoiceHeartbeat(t, udp, session)

	readDone := make(chan error, 1)
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				readDone <- err
				return
			}
		}
	}()
	if err := run.stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("active websocket read returned without a close/error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("active websocket remained open after Run shutdown")
	}

	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: run.cfg.Server.VoicePort})
	if err != nil {
		t.Fatalf("UDP port %d remained bound after shutdown: %v", run.cfg.Server.VoicePort, err)
	}
	probe.Close()
}
