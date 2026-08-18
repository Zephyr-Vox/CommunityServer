package protocol_test

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/protocol"
)

type blockingPacketConn struct {
	net.PacketConn
	mu        sync.Mutex
	blockNext bool
	started   chan struct{}
	release   chan struct{}
	writes    [][]byte
}

func (c *blockingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	block := c.blockNext
	if block {
		c.blockNext = false
		close(c.started)
	}
	c.mu.Unlock()
	if block {
		<-c.release
	}
	return len(p), nil
}

func (c *blockingPacketConn) BlockNextWrite() {
	c.mu.Lock()
	c.blockNext = true
	c.mu.Unlock()
}

func (c *blockingPacketConn) Writes() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.writes...)
}

const (
	testMicChannelType          uint8 = 1
	testDesktopAudioChannelType uint8 = 2
)

type udpEnv struct {
	t        *testing.T
	mgr      *protocol.Manager
	srv      *protocol.UDPServer
	pc       *net.UDPConn
	client   *net.UDPConn
	info     protocol.SessionInfo
	c2s, s2c []byte
	frames   chan protocol.InboundFrame
}

func newUDPEnv(t *testing.T, encrypted bool) *udpEnv {
	t.Helper()
	frames := make(chan protocol.InboundFrame, 2048)
	env := newUDPEnvWithHandler(t, encrypted, func(f protocol.InboundFrame) {
		frames <- f
	})
	env.frames = frames
	return env
}

func newUDPEnvWithHandler(t *testing.T, encrypted bool, onFrame protocol.FrameHandler, opts ...protocol.UDPOption) *udpEnv {
	t.Helper()
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	mgr := protocol.NewManager(clock.Now)
	registry := protocol.NewChannelTypeRegistry()
	if err := registry.Register(testMicChannelType, protocol.Capabilities{Name: "mic"}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(testDesktopAudioChannelType, protocol.Capabilities{Name: "desktop_audio"}); err != nil {
		t.Fatal(err)
	}
	srv, err := protocol.NewUDPServer(mgr, registry, onFrame, protocol.DefaultIngressLimits(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetRevocationHandler(srv.HandleRevocation)

	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(pc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	client, err := net.DialUDP("udp4", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	info, err := mgr.Create(42, "dev-udp", encrypted)
	if err != nil {
		t.Fatal(err)
	}
	var c2s, s2c []byte
	if encrypted {
		c2s, s2c, err = protocol.DeriveDirectionKeys(info.ID, info.MasterKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	return &udpEnv{
		t:      t,
		mgr:    mgr,
		srv:    srv,
		pc:     pc,
		client: client,
		info:   info,
		c2s:    c2s,
		s2c:    s2c,
	}
}

func (e *udpEnv) sendC2S(seq uint64, ch protocol.ChannelHeader, payload []byte) {
	e.t.Helper()
	packet, err := protocol.EncodePacket(e.info.ID, seq, e.info.Encrypted, e.c2s, ch, payload)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.client.Write(packet); err != nil {
		e.t.Fatal(err)
	}
}

func (e *udpEnv) waitFrame(timeout time.Duration) protocol.InboundFrame {
	e.t.Helper()
	select {
	case f := <-e.frames:
		return f
	case <-time.After(timeout):
		e.t.Fatal("timed out waiting for onFrame")
		return protocol.InboundFrame{}
	}
}

func (e *udpEnv) expectNoFrame(wait time.Duration) {
	e.t.Helper()
	select {
	case f := <-e.frames:
		e.t.Fatalf("unexpected frame: %+v", f)
	case <-time.After(wait):
	}
}

func (e *udpEnv) readClient(timeout time.Duration) (protocol.ChannelHeader, uint64, []byte) {
	e.t.Helper()
	_ = e.client.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, protocol.MaxPacketSize)
	n, err := e.client.Read(buf)
	if err != nil {
		e.t.Fatalf("client read: %v", err)
	}
	_, seq, ch, payload, ok := protocol.DecodePacket(buf[:n], e.info.Encrypted, e.s2c)
	if !ok {
		e.t.Fatalf("decode s2c packet failed: %x", buf[:n])
	}
	return ch, seq, payload
}

// waitRemote blocks until the server has learned the client's UDP address. It
// polls with Send; Send reserves a sequence per attempt by design, so callers
// must not assert an exact subsequent SendSeq.
func (e *udpEnv) waitRemote(timeout time.Duration) {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := e.srv.Send(e.info.ID, 1, 1, 0, nil)
		if err == nil {
			_, _, _ = e.readClient(2 * time.Second)
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("remote was not learned within %s: %v", timeout, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUDPEncryptedFrameAndSendRoundTrip(t *testing.T) {
	e := newUDPEnv(t, true)

	e.sendC2S(1, protocol.ChannelHeader{ChannelType: 1, ChannelSeq: 11}, []byte("hello"))
	frame := e.waitFrame(2 * time.Second)
	if frame.UserID != 42 || frame.SessionID != e.info.ID || frame.ChannelType != 1 || frame.ChannelSeq != 11 || frame.TransportSeq != 1 || !bytes.Equal(frame.Payload, []byte("hello")) {
		t.Fatalf("frame = %+v", frame)
	}

	if err := e.srv.Send(e.info.ID, 2, 99, 0x4242, []byte("desktop")); err != nil {
		t.Fatal(err)
	}
	ch, seq, payload := e.readClient(2 * time.Second)
	if ch.ChannelType != 2 || ch.ChannelSeq != 0x4242 || ch.SpeakerID != 99 || seq != 1 || !bytes.Equal(payload, []byte("desktop")) {
		t.Fatalf("s2c = ch %+v seq %d payload %q", ch, seq, payload)
	}
}

func TestUDPEncryptedDropsTamperedAndInvalidChannelPackets(t *testing.T) {
	e := newUDPEnv(t, true)

	// Tampered ciphertext never reaches onFrame; the following valid seq
	// proves the loop is still healthy.
	packet, err := protocol.EncodePacket(e.info.ID, 2, true, e.c2s, protocol.ChannelHeader{ChannelType: 1}, []byte("tamper"))
	if err != nil {
		t.Fatal(err)
	}
	packet[protocol.HeaderSize] ^= 1
	if _, err := e.client.Write(packet); err != nil {
		t.Fatal(err)
	}
	e.expectNoFrame(150 * time.Millisecond)

	e.sendC2S(3, protocol.ChannelHeader{ChannelType: 1}, []byte("ok"))
	if f := e.waitFrame(2 * time.Second); f.TransportSeq != 3 {
		t.Fatalf("frame after tamper = %+v", f)
	}

	// c2s speaker_id must be zero; channel flags must be zero; unknown
	// channel types are dropped.
	e.sendC2S(4, protocol.ChannelHeader{ChannelType: 1, SpeakerID: 1}, []byte("bad-speaker"))
	e.sendC2S(5, protocol.ChannelHeader{ChannelType: 1, Flags: 1}, []byte("bad-flags"))
	e.sendC2S(6, protocol.ChannelHeader{ChannelType: 9}, []byte("unknown"))
	e.expectNoFrame(150 * time.Millisecond)

	e.sendC2S(7, protocol.ChannelHeader{ChannelType: 2, ChannelSeq: 77}, []byte("desktop"))
	if f := e.waitFrame(2 * time.Second); f.ChannelType != 2 || f.ChannelSeq != 77 {
		t.Fatalf("valid multichannel frame = %+v", f)
	}
}

func TestUDPPlaintextFrameAndSend(t *testing.T) {
	e := newUDPEnv(t, false)
	e.sendC2S(1, protocol.ChannelHeader{ChannelType: 1, ChannelSeq: 5}, []byte("plain"))
	frame := e.waitFrame(2 * time.Second)
	if frame.UserID != 42 || frame.ChannelType != 1 || frame.ChannelSeq != 5 || !bytes.Equal(frame.Payload, []byte("plain")) {
		t.Fatalf("plaintext frame = %+v", frame)
	}
	if err := e.srv.Send(e.info.ID, 1, 7, 9, []byte("back")); err != nil {
		t.Fatal(err)
	}
	ch, seq, payload := e.readClient(2 * time.Second)
	if ch.SpeakerID != 7 || ch.ChannelSeq != 9 || seq != 1 || !bytes.Equal(payload, []byte("back")) {
		t.Fatalf("plaintext s2c = %+v %d %q", ch, seq, payload)
	}
}

func TestUDPHeartbeatSemantics(t *testing.T) {
	e := newUDPEnv(t, false)

	// Valid empty heartbeat passes replay, learns remote, but never reaches
	// onFrame.
	e.sendC2S(1, protocol.ChannelHeader{}, nil)
	e.expectNoFrame(150 * time.Millisecond)
	if err := e.srv.Send(e.info.ID, 1, 1, 0, []byte("after-heartbeat")); err != nil {
		t.Fatalf("Send after heartbeat: %v", err)
	}
	_, _, _ = e.readClient(2 * time.Second)

	// Duplicate and non-empty type 0 are both illegal.
	e.sendC2S(1, protocol.ChannelHeader{}, nil)
	e.sendC2S(2, protocol.ChannelHeader{}, []byte("non-empty"))
	e.expectNoFrame(150 * time.Millisecond)

	// seq=0 heartbeat is rejected by the replay window. EncodePacket refuses
	// seq=0 by design, so craft the raw plaintext datagram here.
	raw := make([]byte, protocol.HeaderSize+protocol.ChannelHeaderSize)
	copy(raw[:4], protocol.Magic)
	raw[4] = protocol.ProtocolVersion
	copy(raw[6:22], e.info.ID[:])
	if _, err := e.client.Write(raw); err != nil {
		t.Fatal(err)
	}
	e.expectNoFrame(150 * time.Millisecond)
}

func TestUDPRevocationNotifications(t *testing.T) {
	e := newUDPEnv(t, true)

	// Learn the old session's remote with a heartbeat, then wait until the
	// read loop has actually consumed it.
	e.sendC2S(1, protocol.ChannelHeader{}, nil)
	e.waitRemote(2 * time.Second)

	newInfo, err := e.mgr.Create(42, "new-device", true)
	if err != nil {
		t.Fatal(err)
	}
	ch, seq, payload := e.readClient(2 * time.Second)
	if ch.ChannelType != 0 || ch.ChannelSeq != 0 || ch.Flags != 0 || ch.SpeakerID != 0 || seq == 0 || len(payload) != 1 || payload[0] != byte(protocol.RevocationReplaced) {
		t.Fatalf("replaced notification = ch %+v seq %d payload %v", ch, seq, payload)
	}

	// The new session can also be revoked by user-id invalidation.
	newC2s, newS2c, err := protocol.DeriveDirectionKeys(newInfo.ID, newInfo.MasterKey)
	if err != nil {
		t.Fatal(err)
	}
	oldInfo := e.info
	oldS2C := e.s2c
	e.info = newInfo
	e.c2s = newC2s
	e.s2c = newS2c
	e.sendC2S(1, protocol.ChannelHeader{}, nil)
	e.waitRemote(2 * time.Second)
	if n := e.mgr.InvalidateUser(42); n != 1 {
		t.Fatalf("InvalidateUser = %d", n)
	}
	ch, seq, payload = e.readClient(2 * time.Second)
	if ch.ChannelType != 0 || seq == 0 || len(payload) != 1 || payload[0] != byte(protocol.RevocationRevoked) {
		t.Fatalf("revoked notification = ch %+v seq %d payload %v", ch, seq, payload)
	}
	if oldInfo.ID == newInfo.ID || bytes.Equal(oldS2C, newS2c) {
		t.Fatal("preemption must replace both id and key")
	}
}

func TestUDPRemoteMigratesOnlyOnReplayAdvance(t *testing.T) {
	e := newUDPEnv(t, false)
	client2, err := net.DialUDP("udp4", nil, e.pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	e.sendC2S(1, protocol.ChannelHeader{ChannelType: 1}, []byte("from-1"))
	e.waitFrame(2 * time.Second)

	// The second address advances the window and migrates remote.
	packet, err := protocol.EncodePacket(e.info.ID, 5, false, nil, protocol.ChannelHeader{ChannelType: 1}, []byte("from-2"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client2.Write(packet); err != nil {
		t.Fatal(err)
	}
	e.waitFrame(2 * time.Second)

	// A late but previously-unseen in-window packet from the old address is
	// accepted; it must NOT roll the learned remote back.
	e.sendC2S(4, protocol.ChannelHeader{ChannelType: 1}, []byte("late"))
	e.waitFrame(2 * time.Second)

	if err := e.srv.Send(e.info.ID, 1, 77, 7, []byte("to-new")); err != nil {
		t.Fatal(err)
	}
	_ = client2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, protocol.MaxPacketSize)
	n, err := client2.Read(buf)
	if err != nil {
		t.Fatalf("new remote did not receive Send: %v", err)
	}
	if _, _, ch, payload, ok := protocol.DecodePacket(buf[:n], false, nil); !ok || ch.SpeakerID != 77 || !bytes.Equal(payload, []byte("to-new")) {
		t.Fatalf("new remote s2c = %+v %q", ch, payload)
	}

	_ = e.client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := e.client.Read(buf); err == nil {
		t.Fatal("old remote received a Send after migration")
	}
}

func TestUDPRateLimitDropsBurstOverflow(t *testing.T) {
	e := newUDPEnv(t, false)
	for i := range protocol.SessionBurst + 1 {
		e.sendC2S(uint64(i+1), protocol.ChannelHeader{ChannelType: 1}, []byte("x"))
	}

	deadline := time.Now().Add(3 * time.Second)
	count := 0
	for count < protocol.SessionBurst {
		select {
		case <-e.frames:
			count++
		case <-time.After(time.Until(deadline)):
			t.Fatalf("frames = %d, want %d", count, protocol.SessionBurst)
		}
	}
	e.expectNoFrame(200 * time.Millisecond)
}

func TestUDPSendValidation(t *testing.T) {
	e := newUDPEnv(t, false)
	if err := e.srv.Send(e.info.ID, 0, 1, 0, nil); !errors.Is(err, protocol.ErrChannelTypeReserved) {
		t.Fatalf("type 0 err = %v", err)
	}
	if err := e.srv.Send(e.info.ID, 1, 0, 0, nil); !errors.Is(err, protocol.ErrInvalidSpeakerID) {
		t.Fatalf("speaker 0 err = %v", err)
	}
	if err := e.srv.Send(e.info.ID, 1, -1, 0, nil); !errors.Is(err, protocol.ErrInvalidSpeakerID) {
		t.Fatalf("negative speaker err = %v", err)
	}
	if err := e.srv.Send(e.info.ID, 9, 1, 0, nil); !errors.Is(err, protocol.ErrChannelNotRegistered) {
		t.Fatalf("unregistered channel err = %v", err)
	}
	if err := e.srv.Send([16]byte{9}, 1, 1, 0, nil); !errors.Is(err, protocol.ErrSessionNotFound) {
		t.Fatalf("unknown session err = %v", err)
	}
	if err := e.srv.Send(e.info.ID, 1, 1, 0, nil); !errors.Is(err, protocol.ErrNoPeer) {
		t.Fatalf("no peer err = %v", err)
	}

	e.sendC2S(1, protocol.ChannelHeader{}, nil)
	e.waitRemote(2 * time.Second)
	if err := e.srv.Send(e.info.ID, 1, 1, 0, make([]byte, protocol.MaxPayloadPlaintext+1)); !errors.Is(err, protocol.ErrPayloadTooLarge) {
		t.Fatalf("oversize err = %v", err)
	}
}

func TestUDPUnknownAndGarbagePacketsAreSilent(t *testing.T) {
	e := newUDPEnv(t, false)
	serverAddr := e.pc.LocalAddr().(*net.UDPAddr)
	noise, err := net.DialUDP("udp4", nil, serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer noise.Close()
	if _, err := noise.Write(make([]byte, protocol.MaxPacketSize)); err != nil {
		t.Fatal(err)
	}
	if _, err := noise.Write(make([]byte, protocol.MaxPacketSize+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := noise.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	unknown, err := protocol.EncodePacket([16]byte{77}, 1, false, nil, protocol.ChannelHeader{ChannelType: 1}, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noise.Write(unknown); err != nil {
		t.Fatal(err)
	}
	e.expectNoFrame(150 * time.Millisecond)

	e.sendC2S(1, protocol.ChannelHeader{ChannelType: 1}, []byte("alive"))
	if f := e.waitFrame(2 * time.Second); !bytes.Equal(f.Payload, []byte("alive")) {
		t.Fatalf("frame after garbage = %+v", f)
	}
}

func TestUDPCloseIsIdempotentAndWaitsForReadLoop(t *testing.T) {
	e := newUDPEnv(t, false)
	e.sendC2S(1, protocol.ChannelHeader{ChannelType: 1}, []byte("before-close"))
	e.waitFrame(2 * time.Second)

	if err := e.srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Close(); err != nil {
		t.Fatal(err)
	}
	// The read loop must have exited: Close only returns after the read goroutine
	// stopped. Sending after close is simply ignored by the OS.
}

func TestUDPPlaintextMaxPayloadReachesOnFrame(t *testing.T) {
	e := newUDPEnv(t, false)
	payload := bytes.Repeat([]byte{0x5a}, protocol.MaxPayloadPlaintext)
	e.sendC2S(1, protocol.ChannelHeader{ChannelType: 1}, payload)
	frame := e.waitFrame(2 * time.Second)
	if len(frame.Payload) != protocol.MaxPayloadPlaintext {
		t.Fatalf("payload len = %d, want %d", len(frame.Payload), protocol.MaxPayloadPlaintext)
	}
}

func TestUDPOnFramePayloadMustBeCopiedForAsyncUse(t *testing.T) {
	copied := make(chan []byte, 1)
	frames := make(chan protocol.InboundFrame, 2)
	e := newUDPEnvWithHandler(t, false, func(f protocol.InboundFrame) {
		frames <- f
		// Simulate an asynchronous relay that outlives the callback: without
		// this copy, the read buffer would be overwritten by the next frame.
		select {
		case copied <- append([]byte(nil), f.Payload...):
		default:
		}
	})
	e.frames = frames

	e.sendC2S(1, protocol.ChannelHeader{ChannelType: 1}, []byte("first"))
	var first []byte
	select {
	case first = <-copied:
	case <-time.After(2 * time.Second):
		t.Fatal("first frame was not delivered")
	}
	e.sendC2S(2, protocol.ChannelHeader{ChannelType: 1}, []byte("second"))
	e.waitFrame(2 * time.Second) // ensure the read loop consumed seq=2
	if !bytes.Equal(first, []byte("first")) {
		t.Fatalf("async payload changed after buffer reuse: %q", first)
	}
}

func TestPurgeLoopRunsOnInjectedTicks(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	mgr := protocol.NewManager(clock.Now)
	if _, err := mgr.Create(1, "", false); err != nil {
		t.Fatal(err)
	}
	srv, err := protocol.NewUDPServer(mgr, protocol.NewChannelTypeRegistry(), nil, protocol.DefaultIngressLimits())
	if err != nil {
		t.Fatal(err)
	}
	ticks := make(chan time.Time, 1)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.PurgeLoop(protocol.PurgeInterval, ticks, stop)
	}()

	clock.Advance(protocol.SessionTTL + time.Second)
	ticks <- clock.Now()
	deadline := time.Now().Add(2 * time.Second)
	for mgr.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("purge loop did not remove the expired session")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("purge loop did not stop")
	}
}

func TestUDPStartThenImmediateCloseReleasesPort(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr)
	srv, err := protocol.NewUDPServer(protocol.NewManager(time.Now), protocol.NewChannelTypeRegistry(), nil, protocol.DefaultIngressLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(pc); err != nil {
		t.Fatal(err)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}

	probe, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("UDP port was not released after Close: %v", err)
	}
	_ = probe.Close()
}

func TestUDPStartAfterCloseReleasesRejectedConn(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr)
	srv, err := protocol.NewUDPServer(protocol.NewManager(time.Now), protocol.NewChannelTypeRegistry(), nil, protocol.DefaultIngressLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(pc); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Start after Close error = %v, want net.ErrClosed", err)
	}

	probe, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("rejected conn was not closed: %v", err)
	}
	_ = probe.Close()
}

func TestUDPStatsHandlerReceivesLifecycleSamples(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	mgr := protocol.NewManager(clock.Now)
	registry := protocol.NewChannelTypeRegistry()
	if err := registry.Register(testMicChannelType, protocol.Capabilities{Name: "mic"}); err != nil {
		t.Fatal(err)
	}

	frames := make(chan protocol.InboundFrame, 16)
	stats := make(chan protocol.StatsSample, 128)
	srv, err := protocol.NewUDPServer(mgr, registry, func(f protocol.InboundFrame) {
		frames <- f
	}, protocol.DefaultIngressLimits(), protocol.WithStatsHandler(func(s protocol.StatsSample) {
		stats <- s
	}))
	if err != nil {
		t.Fatal(err)
	}

	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(pc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	client, err := net.DialUDP("udp4", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	info, err := mgr.Create(42, "dev-stats", false)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := protocol.EncodePacket(info.ID, 1, false, nil, protocol.ChannelHeader{ChannelType: testMicChannelType}, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
	waitForStatsKind(t, stats, protocol.StatsFrameDelivered)
	if _, err := client.Write([]byte("garbage")); err != nil {
		t.Fatal(err)
	}
	waitForStatsKind(t, stats, protocol.StatsDroppedMalformed)

	select {
	case <-frames:
	default:
		t.Fatal("valid frame did not reach onFrame")
	}
}

func waitForStatsKind(t *testing.T, stats <-chan protocol.StatsSample, want protocol.StatsKind) protocol.StatsSample {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case s := <-stats:
			if s.Kind == want {
				return s
			}
		case <-deadline:
			t.Fatalf("timed out waiting for stats kind %d", want)
		}
	}
}

func TestUDPServerHonorsCustomManagerLimits(t *testing.T) {
	mgr, err := protocol.NewManagerWithLimits(time.Now, protocol.Limits{SessionPacketsPerSec: 1, SessionBurst: 1})
	if err != nil {
		t.Fatal(err)
	}
	registry := protocol.NewChannelTypeRegistry()
	if err := registry.Register(testMicChannelType, protocol.Capabilities{Name: "mic"}); err != nil {
		t.Fatal(err)
	}
	frames := make(chan protocol.InboundFrame, 16)
	srv, err := protocol.NewUDPServer(mgr, registry, func(f protocol.InboundFrame) { frames <- f }, protocol.DefaultIngressLimits())
	if err != nil {
		t.Fatal(err)
	}

	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(pc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	client, err := net.DialUDP("udp4", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	info, err := mgr.Create(42, "dev-limit", false)
	if err != nil {
		t.Fatal(err)
	}
	send := func(seq uint64) {
		t.Helper()
		packet, err := protocol.EncodePacket(info.ID, seq, false, nil, protocol.ChannelHeader{ChannelType: testMicChannelType}, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	send(1)
	select {
	case <-frames:
	case <-time.After(2 * time.Second):
		t.Fatal("first frame did not arrive")
	}
	send(2)
	select {
	case f := <-frames:
		t.Fatalf("custom burst=1 allowed second frame: %+v", f)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestUDPReplacementWaitsForSendAndDeactivatesOldSession(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	mgr := protocol.NewManager(clock.Now)
	registry := protocol.NewChannelTypeRegistry()
	if err := registry.Register(testMicChannelType, protocol.Capabilities{Name: "mic"}); err != nil {
		t.Fatal(err)
	}
	frames := make(chan protocol.InboundFrame, 2)
	srv, err := protocol.NewUDPServer(mgr, registry, func(frame protocol.InboundFrame) { frames <- frame }, protocol.DefaultIngressLimits())
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetRevocationHandler(srv.HandleRevocation)
	underlying, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	pc := &blockingPacketConn{PacketConn: underlying, started: make(chan struct{}), release: make(chan struct{})}
	if _, err := srv.Start(pc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	client, err := net.DialUDP("udp4", nil, underlying.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	old, err := mgr.Create(42, "old", false)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat, err := protocol.EncodePacket(old.ID, 1, false, nil, protocol.ChannelHeader{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(heartbeat); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if err := srv.Send(old.ID, testMicChannelType, 7, 0, nil); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not learn client address")
		}
		time.Sleep(time.Millisecond)
	}
	baseline := len(pc.Writes())
	pc.BlockNextWrite()
	sendDone := make(chan error, 1)
	go func() { sendDone <- srv.Send(old.ID, testMicChannelType, 7, 1, []byte("audio")) }()
	<-pc.started

	replaceDone := make(chan error, 1)
	go func() {
		_, err := mgr.Create(42, "new", false)
		replaceDone <- err
	}()
	select {
	case err := <-replaceDone:
		t.Fatalf("Create returned while Send was blocked: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(pc.release)
	if err := <-sendDone; err != nil {
		t.Fatalf("blocked Send = %v", err)
	}
	if err := <-replaceDone; err != nil {
		t.Fatalf("replacement Create = %v", err)
	}

	writes := pc.Writes()[baseline:]
	if len(writes) != 2 {
		t.Fatalf("writes after replacement = %d, want audio then revocation", len(writes))
	}
	_, audioSeq, audioHeader, _, ok := protocol.DecodePacket(writes[0], false, nil)
	if !ok || audioHeader.ChannelType != testMicChannelType {
		t.Fatalf("first post-replacement write is not audio: ok=%v header=%+v", ok, audioHeader)
	}
	_, revokeSeq, revokeHeader, payload, ok := protocol.DecodePacket(writes[1], false, nil)
	if !ok || revokeHeader.ChannelType != protocol.HeartbeatChannelType || len(payload) != 1 {
		t.Fatalf("second post-replacement write is not revocation: ok=%v header=%+v payload=%x", ok, revokeHeader, payload)
	}
	if revokeSeq <= audioSeq {
		t.Fatalf("revocation sequence %d must follow audio sequence %d", revokeSeq, audioSeq)
	}
	if err := srv.Send(old.ID, testMicChannelType, 7, 2, nil); !errors.Is(err, protocol.ErrSessionNotFound) {
		t.Fatalf("Send on replaced session = %v, want ErrSessionNotFound", err)
	}
	oldFrame, err := protocol.EncodePacket(old.ID, 2, false, nil, protocol.ChannelHeader{ChannelType: testMicChannelType}, []byte("stale"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(oldFrame); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-frames:
		t.Fatalf("replaced session delivered frame: %+v", frame)
	case <-time.After(50 * time.Millisecond):
	}
}
