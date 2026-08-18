package protocol

import (
	"crypto/cipher"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// InboundFrame is one validated c2s audio frame handed to the relay callback.
// Payload aliases the read-loop buffer (or the decrypted buffer): it is only
// valid for the duration of the callback, and an asynchronous consumer must
// copy it first.
//
// ChannelSeq is the source's per-channel uint16 modular counter. Relays pass
// it through unchanged instead of renumbering, so receivers can keep their
// own jitter buffer / loss statistics per (speaker_id, channel_type). Loss
// statistics are only meaningful within a 32768-packet window and callers
// must compare values modulo 2^16.
type InboundFrame struct {
	UserID       int64
	SessionID    [16]byte
	ChannelType  uint8
	ChannelSeq   uint16
	TransportSeq uint64
	Payload      []byte
}

// FrameHandler receives validated c2s audio frames. It runs on the UDP read
// goroutine, outside every lock, and must return promptly: UDP backpressure
// is packet loss, so a slow callback simply lets the kernel socket buffer
// drop datagrams.
type FrameHandler func(frame InboundFrame)

// StatsKind classifies one transport observability sample.
type StatsKind uint8

const (
	StatsPacketReceived StatsKind = iota + 1
	StatsDroppedMalformed
	StatsDroppedUnknownSession
	StatsDroppedRateLimit
	StatsDroppedGlobalIngress
	StatsDroppedSourceIngress
	StatsDroppedSourceTableFull
	StatsDroppedAuthentication
	StatsDroppedChannel
	StatsDroppedReplay
	StatsDroppedSessionRateLimit
	StatsHeartbeatReceived
	StatsFrameDelivered
	StatsSendSuccess
	StatsSendError
	StatsRevocationSent
	StatsRevocationError
)

// StatsSample is one transport observability sample. The handler runs on the
// UDP read loop for received packets and must be non-blocking and allocation
// free if possible; metrics layers aggregate these samples.
type StatsSample struct {
	Kind        StatsKind
	SessionID   [16]byte
	UserID      int64
	ChannelType uint8
	Bytes       int
}

// StatsHandler receives transport observability samples.
type StatsHandler func(sample StatsSample)

// UDPServer owns the datagram read loop, s2c Send path and best-effort
// revocation notifications. It never logs: every packet-level failure is
// silent by design (garbage datagrams must not be able to flood the log), and
// lifecycle errors are returned to the server boundary.
type UDPServer struct {
	manager      *Manager
	registry     *ChannelTypeRegistry
	onFrame      FrameHandler
	statsHandler StatsHandler
	ingress      *IngressLimiter

	connMu  sync.Mutex
	conn    net.PacketConn
	serving bool
	closed  bool

	wg sync.WaitGroup
}

// UDPOption configures a UDPServer.
type UDPOption func(*UDPServer)

// WithStatsHandler installs a non-blocking transport observability callback.
func WithStatsHandler(handler StatsHandler) UDPOption {
	return func(s *UDPServer) {
		s.statsHandler = handler
	}
}

// NewUDPServer returns a UDP server bound to manager and registry. ingress
// limits are enforced before header parsing and AEAD work. onFrame may be nil,
// in which case validated frames are counted nowhere and simply dropped.
func NewUDPServer(manager *Manager, registry *ChannelTypeRegistry, onFrame FrameHandler, limits IngressLimits, opts ...UDPOption) (*UDPServer, error) {
	if manager == nil || registry == nil {
		return nil, errors.New("protocol: nil manager or registry")
	}
	ingress, err := NewIngressLimiter(limits, manager.now)
	if err != nil {
		return nil, err
	}
	s := &UDPServer{
		manager:  manager,
		registry: registry,
		onFrame:  onFrame,
		ingress:  ingress,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Start registers pc synchronously and starts the datagram read loop on a new
// goroutine. The returned channel receives the final serve result and is never
// closed; it is buffered so a caller that only uses Close can ignore it.
// Blocking callers can simply read the returned channel.
//
// Registration happens before Start returns, so a subsequent Close can always
// find and close pc. Start is the only way to begin serving: this removes the
// "Close raced with an unregistered goroutine" failure mode by construction.
func (s *UDPServer) Start(pc net.PacketConn) (<-chan error, error) {
	if pc == nil {
		return nil, errors.New("protocol: nil packet conn")
	}
	if s.manager == nil || s.registry == nil {
		_ = pc.Close()
		return nil, errors.New("protocol: nil manager or registry")
	}

	s.connMu.Lock()
	if s.closed {
		s.connMu.Unlock()
		_ = pc.Close()
		return nil, net.ErrClosed
	}
	if s.serving {
		s.connMu.Unlock()
		_ = pc.Close()
		return nil, errors.New("protocol: udp server already serving")
	}
	// Seal before publishing the serving state: callers that observe Start's
	// successful return can no longer race a late channel registration.
	s.registry.Seal()
	s.serving = true
	s.conn = pc
	s.wg.Add(1)
	s.connMu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.serve(pc)
	}()
	return errCh, nil
}

// serve owns the registered read loop and its defer cleanup.
func (s *UDPServer) serve(pc net.PacketConn) error {
	defer func() {
		s.connMu.Lock()
		if s.conn == pc {
			s.conn = nil
		}
		s.serving = false
		s.connMu.Unlock()
		s.wg.Done()
	}()

	// Read into MaxPacketSize+1 so a datagram longer than the limit is
	// detectable: UDP ReadFrom truncates silently, and with a 1200-byte
	// buffer an oversized datagram would otherwise look exactly 1200 bytes
	// long. parseOuterHeader rejects the oversized copy.
	buf := make([]byte, MaxPacketSize+1)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.isClosed() {
				return nil
			}
			return err
		}
		s.handleDatagram(buf[:n], addr)
	}
}

// Close idempotently closes the served PacketConn and waits for the read
// goroutine to exit. It is safe to call before Start and repeatedly. Close is
// terminal: a closed UDPServer must not be restarted; construct a new one.
func (s *UDPServer) Close() error {
	s.connMu.Lock()
	s.closed = true
	pc := s.conn
	s.connMu.Unlock()

	if pc != nil {
		_ = pc.Close()
	}
	s.wg.Wait()
	return nil
}

// isClosed reports whether Close has made the server terminal.
func (s *UDPServer) isClosed() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.closed
}

// reportStats delivers a transport sample when observability is configured.
func (s *UDPServer) reportStats(sample StatsSample) {
	if s.statsHandler != nil {
		s.statsHandler(sample)
	}
}

// HandleRevocation adapts the UDPServer to RevocationHandler. The callback is
// invoked by the Manager after the session has already been removed from the
// table, which is exactly why this path never goes through public Send.
func (s *UDPServer) HandleRevocation(reason RevocationReason, snap RevokedSessionSnapshot) {
	_ = s.sendRevoked(reason, snap)
}

// Send encrypts and writes one s2c audio frame for the target session. The
// caller (the future relay) supplies the speaker's snowflake user id and the
// source channel_seq verbatim; the server never renumbers channel sequences.
//
// The public API refuses channel_type 0: heartbeat / revocation frames have
// their own private sendRevoked path and must never be sent as audio.
func (s *UDPServer) Send(id [16]byte, channelType uint8, speakerID int64, channelSeq uint16, payload []byte) error {
	fail := func(err error) error {
		s.reportStats(StatsSample{
			Kind:        StatsSendError,
			SessionID:   id,
			ChannelType: channelType,
			Bytes:       len(payload),
		})
		return err
	}

	if channelType == HeartbeatChannelType {
		return fail(ErrChannelTypeReserved)
	}
	if speakerID <= 0 {
		return fail(ErrInvalidSpeakerID)
	}
	if !s.registry.Registered(channelType) {
		return fail(ErrChannelNotRegistered)
	}

	sess, ok := s.manager.Get(id)
	if !ok {
		return fail(ErrSessionNotFound)
	}
	sess.sendMu.Lock()
	defer sess.sendMu.Unlock()
	seq, encrypted, aead, remote, err := sess.reserveSendSeq()
	if err != nil {
		return fail(err)
	}
	if remote == nil {
		return fail(ErrNoPeer)
	}
	if len(payload) > MaxPayload(encrypted) {
		return fail(ErrPayloadTooLarge)
	}

	packet, err := buildPacket(id, seq, encrypted, aead, ChannelHeader{
		ChannelType: channelType,
		ChannelSeq:  channelSeq,
		SpeakerID:   speakerID,
	}, payload)
	if err != nil {
		return fail(err)
	}
	pc := s.packetConn()
	if pc == nil {
		return fail(net.ErrClosed)
	}
	if _, err = pc.WriteTo(packet, remote); err != nil {
		return fail(err)
	}
	s.reportStats(StatsSample{
		Kind:        StatsSendSuccess,
		SessionID:   id,
		UserID:      sess.UserID,
		ChannelType: channelType,
		Bytes:       len(packet),
	})
	return nil
}

// sendRevoked sends one best-effort type 0 revocation notification using the
// deleted session's snapshot. There is no retry and no logging on failure:
// UDP may drop it anyway, and clients treat it only as UX, never as a
// security decision.
func (s *UDPServer) sendRevoked(reason RevocationReason, snap RevokedSessionSnapshot) error {
	fail := func(err error) error {
		s.reportStats(StatsSample{
			Kind:      StatsRevocationError,
			SessionID: snap.ID,
			UserID:    snap.UserID,
		})
		return err
	}
	if snap.Remote == nil {
		return fail(ErrNoPeer)
	}
	if snap.SendSeq == 0 {
		return fail(ErrSequenceExhausted)
	}
	packet, err := buildPacket(snap.ID, snap.SendSeq, snap.Encrypted, snap.S2CAEAD, ChannelHeader{}, []byte{byte(reason)})
	if err != nil {
		return fail(err)
	}
	pc := s.packetConn()
	if pc == nil {
		return fail(net.ErrClosed)
	}
	if _, err = pc.WriteTo(packet, snap.Remote); err != nil {
		return fail(err)
	}
	s.reportStats(StatsSample{
		Kind:      StatsRevocationSent,
		SessionID: snap.ID,
		UserID:    snap.UserID,
		Bytes:     len(packet),
	})
	return nil
}

// StartPurge starts the 30s background sweep and returns a stop function.
// Purge is the only full table scan; the datagram hot path never calls it.
// The stop function blocks until the sweep goroutine has exited, so shutdown
// can deterministically wait for it.
func (s *UDPServer) StartPurge(interval time.Duration) (stop func()) {
	if interval <= 0 {
		interval = PurgeInterval
	}
	ticker := time.NewTicker(interval)
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.PurgeLoop(interval, ticker.C, stopCh)
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			close(stopCh)
			ticker.Stop()
			<-done
		})
	}
}

// PurgeLoop consumes ticks until stop is closed. It is unexported so tests can
// inject a chan time.Time and drive expiry deterministically without a real
// ticker.
func (s *UDPServer) PurgeLoop(interval time.Duration, ticks <-chan time.Time, stop <-chan struct{}) {
	for {
		select {
		case <-ticks:
			s.manager.Purge()
			s.ingress.Sweep(s.manager.now())
		case <-stop:
			return
		}
	}
}

// packetConn snapshots the currently served connection under connMu.
func (s *UDPServer) packetConn() net.PacketConn {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.conn
}

// handleDatagram implements the ordered read pipeline:
//
//	parse outer header -> manager.Get -> rate limit -> lock-free decrypt /
//	plaintext parse -> channel semantics -> replay + touch + remote learning
//	-> callback (audio) or consume (heartbeat).
//
// Encryption, parsing, WriteTo and callbacks all happen outside locks; the
// session mutex is only used for short snapshots and state updates.
func (s *UDPServer) handleDatagram(p []byte, addr net.Addr) {
	s.reportStats(StatsSample{Bytes: len(p), Kind: StatsPacketReceived})

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		s.reportStats(StatsSample{Bytes: len(p), Kind: StatsDroppedMalformed})
		return
	}
	addrIP, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		s.reportStats(StatsSample{Bytes: len(p), Kind: StatsDroppedMalformed})
		return
	}
	now := s.manager.now()
	switch s.ingress.Allow(addrIP, now) {
	case IngressDroppedGlobal:
		s.reportStats(StatsSample{Bytes: len(p), Kind: StatsDroppedGlobalIngress})
		return
	case IngressDroppedSource:
		s.reportStats(StatsSample{Bytes: len(p), Kind: StatsDroppedSourceIngress})
		return
	case IngressDroppedTableFull:
		s.reportStats(StatsSample{Bytes: len(p), Kind: StatsDroppedSourceTableFull})
		return
	}

	sessionID, seq, ok := parseOuterHeader(p)
	if !ok {
		s.reportStats(StatsSample{Bytes: len(p), Kind: StatsDroppedMalformed})
		return
	}

	sess, ok := s.manager.Get(sessionID)
	if !ok {
		s.reportStats(StatsSample{
			Kind:      StatsDroppedUnknownSession,
			SessionID: sessionID,
			Bytes:     len(p),
		})
		return
	}

	encrypted, aead := sess.cryptoSnapshot()
	var ch ChannelHeader
	var payload []byte

	if encrypted {
		if aead == nil || len(p) < MinPacketSize(true) {
			s.reportStats(StatsSample{
				Kind:      StatsDroppedAuthentication,
				SessionID: sessionID,
				UserID:    sess.UserID,
				Bytes:     len(p),
			})
			return
		}
		plaintext, err := openWithAEAD(aead, seq, p[:HeaderSize], p[HeaderSize:])
		if err != nil {
			s.reportStats(StatsSample{
				Kind:      StatsDroppedAuthentication,
				SessionID: sessionID,
				UserID:    sess.UserID,
				Bytes:     len(p),
			})
			return
		}
		if ch, ok = parseChannelHeader(plaintext[:ChannelHeaderSize]); !ok {
			s.reportStats(StatsSample{
				Kind:      StatsDroppedChannel,
				SessionID: sessionID,
				UserID:    sess.UserID,
				Bytes:     len(p),
			})
			return
		}
		payload = plaintext[ChannelHeaderSize:]
	} else {
		if len(p) < MinPacketSize(false) {
			s.reportStats(StatsSample{
				Kind:      StatsDroppedMalformed,
				SessionID: sessionID,
				UserID:    sess.UserID,
				Bytes:     len(p),
			})
			return
		}
		body := p[HeaderSize:]
		if ch, ok = parseChannelHeader(body[:ChannelHeaderSize]); !ok {
			s.reportStats(StatsSample{
				Kind:      StatsDroppedChannel,
				SessionID: sessionID,
				UserID:    sess.UserID,
				Bytes:     len(p),
			})
			return
		}
		payload = body[ChannelHeaderSize:]
	}

	if !s.validInboundChannel(ch, payload, encrypted) {
		s.reportStats(StatsSample{
			Kind:        StatsDroppedChannel,
			SessionID:   sessionID,
			UserID:      sess.UserID,
			ChannelType: ch.ChannelType,
			Bytes:       len(p),
		})
		return
	}

	switch sess.acceptPacket(seq, now, udpAddr) {
	case receiveDroppedReplay:
		s.reportStats(StatsSample{
			Kind:        StatsDroppedReplay,
			SessionID:   sessionID,
			UserID:      sess.UserID,
			ChannelType: ch.ChannelType,
			Bytes:       len(p),
		})
		return
	case receiveDroppedRateLimit:
		s.reportStats(StatsSample{Kind: StatsDroppedSessionRateLimit, SessionID: sessionID, UserID: sess.UserID, ChannelType: ch.ChannelType, Bytes: len(p)})
		return
	case receiveDroppedInactive:
		return
	}
	if ch.ChannelType == HeartbeatChannelType {
		s.reportStats(StatsSample{
			Kind:      StatsHeartbeatReceived,
			SessionID: sessionID,
			UserID:    sess.UserID,
			Bytes:     len(p),
		})
		return
	}

	if s.onFrame != nil {
		s.onFrame(InboundFrame{
			UserID:       sess.UserID,
			SessionID:    sessionID,
			ChannelType:  ch.ChannelType,
			ChannelSeq:   ch.ChannelSeq,
			TransportSeq: seq,
			Payload:      payload,
		})
	}
	s.reportStats(StatsSample{
		Kind:        StatsFrameDelivered,
		SessionID:   sessionID,
		UserID:      sess.UserID,
		ChannelType: ch.ChannelType,
		Bytes:       len(p),
	})
}

// validInboundChannel enforces the c2s half of the legal-value table before
// replay/TTL/remote updates. Invalid packets never extend TTL and never move
// the learned remote address.
//
//   - type 0: channel_seq/flags/speaker_id all 0 and payload empty
//     (heartbeat; a non-empty type 0 is dropped)
//   - type 1..255: flags 0, speaker_id 0, type registered
//
// Channel flags are dropped unconditionally in v1 even when the registry
// declares Fragmentable: fragment parsing is a future batch and v1 must never
// let an undefined structure through.
func (s *UDPServer) validInboundChannel(ch ChannelHeader, payload []byte, encrypted bool) bool {
	if ch.Flags != 0 {
		return false
	}
	if ch.ChannelType == HeartbeatChannelType {
		return ch.ChannelSeq == 0 && ch.SpeakerID == 0 && len(payload) == 0
	}
	if ch.SpeakerID != 0 {
		return false
	}
	if !s.registry.Registered(ch.ChannelType) {
		return false
	}
	return len(payload) <= MaxPayload(encrypted)
}

// buildPacket assembles a full datagram: fixed outer header plus either
// channel subheader + raw payload (plaintext) or their AEAD ciphertext
// (encrypted). The complete outer header is authenticated as AAD in encrypted
// mode. Encrypted callers must pass an already-constructed cipher.AEAD for
// the direction key so the UDP hot path does not rebuild GCM per packet.
func buildPacket(sessionID [16]byte, seq uint64, encrypted bool, aead cipher.AEAD, ch ChannelHeader, payload []byte) ([]byte, error) {
	if seq == 0 {
		return nil, ErrSequenceZero
	}
	if len(payload) > MaxPayload(encrypted) {
		return nil, ErrPayloadTooLarge
	}

	header := make([]byte, HeaderSize)
	putOuterHeader(header, sessionID, seq)

	body := make([]byte, ChannelHeaderSize+len(payload))
	putChannelHeader(body[:ChannelHeaderSize], ch)
	copy(body[ChannelHeaderSize:], payload)

	if !encrypted {
		packet := make([]byte, HeaderSize+len(body))
		copy(packet, header)
		copy(packet[HeaderSize:], body)
		return packet, nil
	}

	ciphertext, err := sealWithAEAD(aead, seq, header, body)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, HeaderSize+len(ciphertext))
	copy(packet, header)
	copy(packet[HeaderSize:], ciphertext)
	return packet, nil
}
