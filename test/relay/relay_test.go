package relay_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/protocol"
	"zephyr.vox/server/ce/internal/relay"
)

type relayGate struct {
	acquired chan struct{}
	release  chan struct{}
}

func (g *relayGate) AcquireVoiceRelayGate(int64) func() {
	select {
	case g.acquired <- struct{}{}:
	default:
	}
	<-g.release
	return func() {}
}

type relaySender struct {
	mu     sync.Mutex
	frames []relay.Frame
	done   chan struct{}
	closed bool
}

func (s *relaySender) Send(id [16]byte, channelType uint8, speakerID int64, channelSeq uint16, payload []byte) error {
	s.mu.Lock()
	s.frames = append(s.frames, relay.Frame{Source: relay.Source{UserID: speakerID, SessionID: id}, ChannelType: channelType, ChannelSeq: channelSeq, Payload: append([]byte(nil), payload...)})
	if !s.closed {
		s.closed = true
		close(s.done)
	}
	s.mu.Unlock()
	return nil
}

func (s *relaySender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.frames)
}

func testRegistry(t *testing.T) *protocol.ChannelTypeRegistry {
	t.Helper()
	registry := protocol.NewChannelTypeRegistry()
	if err := registry.Register(1, protocol.Capabilities{Name: "mic", MuteKind: "voice"}); err != nil {
		t.Fatal(err)
	}
	return registry
}

func testSource() relay.Source {
	var session, connection [16]byte
	session[0] = 1
	connection[0] = 2
	return relay.Source{UserID: 7, SessionID: session, ChannelID: 99, ControlConnectionID: connection, ConnectionGeneration: 1, VoiceAuthorityGeneration: 1}
}

func TestRelayCopiesAndFansOutValidatedFrame(t *testing.T) {
	source := testSource()
	target := source
	target.UserID = 8
	target.SessionID[0] = 3
	sender := &relaySender{done: make(chan struct{})}
	r, err := relay.New(relay.Config{
		Sender:         sender,
		SourceResolver: func(int64) (relay.Source, bool) { return source, true },
		MembershipResolver: func(channelID int64) relay.MembershipSnapshot {
			return relay.MembershipSnapshot{ChannelID: channelID, Members: []relay.Recipient{{UserID: source.UserID, SessionID: source.SessionID}, {UserID: target.UserID, SessionID: target.SessionID}}}
		},
		MuteResolver:         func(relay.Source, uint8) bool { return false },
		Gate:                 noopGate{},
		Capabilities:         testRegistry(t),
		GlobalPacketsPerSec:  100,
		SessionPacketsPerSec: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	payload := []byte{1, 2, 3}
	r.Handle(protocol.InboundFrame{UserID: source.UserID, SessionID: source.SessionID, ChannelType: 1, ChannelSeq: 17, TransportSeq: 42, Payload: payload})
	payload[0] = 9
	select {
	case <-sender.done:
	case <-time.After(time.Second):
		t.Fatal("relay did not fan out frame")
	}
	if got := sender.count(); got != 1 {
		t.Fatalf("send count = %d, want 1", got)
	}
	sender.mu.Lock()
	got := sender.frames[0].Payload
	sender.mu.Unlock()
	if got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("payload = %v, want copied original", got)
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRelayDropsQueuedFrameAfterAuthorityGenerationChanges(t *testing.T) {
	source := testSource()
	var currentMu sync.Mutex
	current := source
	target := source
	target.UserID = 8
	target.SessionID[0] = 3
	sender := &relaySender{done: make(chan struct{})}
	gate := &relayGate{acquired: make(chan struct{}, 1), release: make(chan struct{})}
	r, err := relay.New(relay.Config{
		Sender: sender,
		SourceResolver: func(int64) (relay.Source, bool) {
			currentMu.Lock()
			defer currentMu.Unlock()
			return current, true
		},
		MembershipResolver: func(channelID int64) relay.MembershipSnapshot {
			return relay.MembershipSnapshot{ChannelID: channelID, Members: []relay.Recipient{{UserID: source.UserID, SessionID: source.SessionID}, {UserID: target.UserID, SessionID: target.SessionID}}}
		},
		MuteResolver:         func(relay.Source, uint8) bool { return false },
		Gate:                 gate,
		Capabilities:         testRegistry(t),
		GlobalPacketsPerSec:  100,
		SessionPacketsPerSec: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.Handle(protocol.InboundFrame{UserID: source.UserID, SessionID: source.SessionID, ChannelType: 1, ChannelSeq: 1, TransportSeq: 1, Payload: []byte{1}})
	select {
	case <-gate.acquired:
	case <-time.After(time.Second):
		t.Fatal("relay worker did not reach gate")
	}
	currentMu.Lock()
	current.VoiceAuthorityGeneration++
	currentMu.Unlock()
	close(gate.release)
	select {
	case <-time.After(50 * time.Millisecond):
	}
	if got := sender.count(); got != 0 {
		t.Fatalf("stale frame sent %d times", got)
	}
	if got := r.Snapshot().DroppedStaleAuthority; got != 1 {
		t.Fatalf("stale drop count = %d, want 1", got)
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type noopGate struct{}

func (noopGate) AcquireVoiceRelayGate(int64) func() { return func() {} }
