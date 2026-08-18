package protocol

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"math"
	"net"
	"sync"
	"time"
)

const (
	// SessionTTL is the heartbeat timeout. Clients send a type 0 heartbeat
	// every 15s when silent (six intervals inside this window, so five
	// consecutive lost heartbeats are tolerated); any authenticated packet,
	// audio or heartbeat, slides the deadline forward. The constants are
	// intentionally not configurable: they are protocol-level timing, not
	// deployment tuning.
	SessionTTL = 90 * time.Second

	// PurgeInterval is the background sweep period. Purge is the only full
	// table scan; the UDP hot path uses Get for a single session id. Worst
	// case a dead session is reclaimed after SessionTTL + PurgeInterval
	// (120s with these values).
	PurgeInterval = 30 * time.Second
)

var (
	// ErrSequenceExhausted is returned when a session's s2c send sequence
	// reached math.MaxUint64. The sequence must never wrap: a reused seq
	// would reuse a GCM nonce under the same direction key. Reading keeps
	// working; only sending is disabled until the session expires.
	ErrSequenceExhausted = errors.New("protocol: sequence exhausted")
	// ErrInvalidUserID is returned by Create for a non-positive user id.
	ErrInvalidUserID = errors.New("protocol: user id must be positive")
	// ErrSessionNotFound is returned when a session id is unknown or expired.
	ErrSessionNotFound = errors.New("protocol: session not found")
	// ErrSessionNotOwned is returned when Delete names another user's session.
	ErrSessionNotOwned = errors.New("protocol: session belongs to another user")
	// ErrNoKey is returned when an encrypted session lacks its direction key,
	// which indicates a programming or state-construction error.
	ErrNoKey = errors.New("protocol: encrypted session has no key")
	// ErrNoPeer is returned by Send before the client's first valid packet
	// has taught the server its UDP address.
	ErrNoPeer = errors.New("protocol: client address unknown")
	// ErrChannelNotRegistered is returned by Send for an unknown stream type.
	ErrChannelNotRegistered = errors.New("protocol: channel type is not registered")
	// ErrInvalidSpeakerID is returned by Send when speaker_id <= 0. The s2c
	// channel subheader must carry the speaker's positive snowflake user id;
	// c2s traffic is always speaker_id 0.
	ErrInvalidSpeakerID = errors.New("protocol: speaker_id must be positive")
	// ErrPayloadTooLarge is returned by Send when audio data exceeds the
	// negotiated per-packet maximum for the session's mode.
	ErrPayloadTooLarge = errors.New("protocol: payload exceeds maximum packet size")
)

// Limits controls per-session transport budgets. SessionPacketsPerSec is the
// c2s token-bucket refill rate; SessionBurst is the initial bucket capacity.
// Use DefaultLimits for protocol defaults; explicit limits must be positive.
type Limits struct {
	SessionPacketsPerSec int
	SessionBurst         int
}

// DefaultLimits returns the protocol default session budgets.
func DefaultLimits() Limits {
	return Limits{
		SessionPacketsPerSec: SessionPacketsPerSec,
		SessionBurst:         SessionBurst,
	}
}

// RevocationReason tells a best-effort UDP revocation notification why the
// old session died.
type RevocationReason uint8

const (
	// RevocationReplaced means a newer session for the same user preempted
	// this one (single-session-per-user semantics).
	RevocationReplaced RevocationReason = 0x01
	// RevocationRevoked means an admin action (kick/ban/delete) or losing
	// voice:join revoked this session.
	RevocationRevoked RevocationReason = 0x02
)

// RevokedSessionSnapshot is the only state handed to RevocationHandler. It
// deliberately never contains the live Session: Session holds a sync.Mutex,
// replay window and token bucket, so copying it would trigger copylocks and
// would be semantically wrong.
type RevokedSessionSnapshot struct {
	ID        [16]byte
	UserID    int64
	Encrypted bool
	S2CAEAD   cipher.AEAD  // immutable AEAD instance shared with the deleted session
	Remote    *net.UDPAddr // deep copy of the learned client address
	SendSeq   uint64       // reserved inside Session.mu before deletion; 0 = exhausted
}

// RevocationHandler receives snapshots for preempted and revoked sessions.
// The callback runs outside Manager and Session locks.
type RevocationHandler func(reason RevocationReason, snap RevokedSessionSnapshot)

// ExpiryHandler receives sessions that expired naturally and were removed by
// Get or Purge. It runs outside Manager and Session locks, but on the UDP read
// loop for lazy Get, so it must be non-blocking. Explicit Delete,
// InvalidateUser and preemption do not emit expiry callbacks.
type ExpiryHandler func(userID int64, sessionID [16]byte)

// SessionInfo is the result of a successful Create call: the session id and,
// in encrypted mode, the one-time master key for the caller's negotiation
// response.
type SessionInfo struct {
	ID               [16]byte
	Encrypted        bool
	MasterKey        []byte // nil in plaintext mode
	ExpiresAt        int64  // Unix milliseconds at creation time; slides with traffic
	ReplacedPrevious bool   // whether Create preempted an active session
}

// Session is one user's active voice session. Mutable state (ExpiresAt,
// remote, rxReplay, rxBudget, sendSeq) is guarded by mu; the UDP server keeps
// every critical section short and never performs encryption, packet
// assembly, WriteTo or callbacks while holding it.
type Session struct {
	ID        [16]byte
	UserID    int64
	DeviceID  string
	CreatedAt int64 // Unix milliseconds
	ExpiresAt int64 // last valid packet time + SessionTTL, sliding
	encrypted bool
	c2sAEAD   cipher.AEAD
	s2cAEAD   cipher.AEAD
	rxBudget  *TokenBucket
	remote    *net.UDPAddr
	rxReplay  *ReplayWindow
	sendSeq   uint64
	mu        sync.Mutex
}

// Manager is the in-memory session registry. mu protects only the table
// structure (the id map plus the user -> active-session index); per-session
// mutable state is protected by Session.mu. Lock order is always
// Manager -> Session; code holding Session.mu must never acquire Manager.mu.
type Manager struct {
	mu       sync.Mutex
	sessions map[[16]byte]*Session
	byUser   map[int64][16]byte
	now      func() time.Time
	limits   Limits
	onRevoke RevocationHandler
	onExpire ExpiryHandler
}

// NewManager returns an empty Manager with default limits. The clock is
// injectable for deterministic tests; production callers pass time.Now.
func NewManager(now func() time.Time) *Manager {
	m, _ := NewManagerWithLimits(now, DefaultLimits())
	return m
}

// NewManagerWithLimits returns an empty Manager with explicit transport
// budgets. SessionPacketsPerSec and SessionBurst must be positive.
func NewManagerWithLimits(now func() time.Time, limits Limits) (*Manager, error) {
	if now == nil {
		now = time.Now
	}
	if limits.SessionPacketsPerSec <= 0 || limits.SessionBurst <= 0 {
		return nil, errors.New("protocol: session limits must be positive")
	}
	return &Manager{
		sessions: make(map[[16]byte]*Session),
		byUser:   make(map[int64][16]byte),
		now:      now,
		limits:   limits,
	}, nil
}

// SetRevocationHandler installs the handler that receives best-effort UDP
// revocation notifications. It must be installed before the manager is
// exposed to requests; it may be nil when notifications are not wired.
func (m *Manager) SetRevocationHandler(handler RevocationHandler) {
	m.mu.Lock()
	m.onRevoke = handler
	m.mu.Unlock()
}

// SetExpiryHandler installs the callback for naturally expired sessions. It
// must be installed before the manager is exposed to requests; it may be nil.
func (m *Manager) SetExpiryHandler(handler ExpiryHandler) {
	m.mu.Lock()
	m.onExpire = handler
	m.mu.Unlock()
}

// nowMillis samples the manager clock as a Unix millisecond timestamp.
func (m *Manager) nowMillis() int64 {
	return m.now().UnixMilli()
}

// Create registers a new active session for userID. One user has at most one
// active session: creating a new session preempts the old one immediately.
// Only an actually-active old session triggers RevocationReplaced; an
// already-expired leftover is removed silently and does not count as
// "replaced". The returned master key (encrypted mode only) is a one-time
// secret and is not stored in the Manager.
func (m *Manager) Create(userID int64, deviceID string, encrypted bool) (SessionInfo, error) {
	if userID <= 0 {
		return SessionInfo{}, ErrInvalidUserID
	}

	id, err := randomSessionID()
	if err != nil {
		return SessionInfo{}, err
	}

	var masterKey, c2s, s2c []byte
	var c2sAEAD, s2cAEAD cipher.AEAD
	if encrypted {
		masterKey, err = GenerateMasterKey()
		if err != nil {
			return SessionInfo{}, err
		}
		c2s, s2c, err = DeriveDirectionKeys(id, masterKey)
		if err != nil {
			return SessionInfo{}, err
		}
		if c2sAEAD, err = newGCM(c2s); err != nil {
			return SessionInfo{}, err
		}
		if s2cAEAD, err = newGCM(s2c); err != nil {
			return SessionInfo{}, err
		}
	}

	nowMS := m.nowMillis()
	sess := newSession(id, userID, deviceID, encrypted, nowMS, c2sAEAD, s2cAEAD, m.limits, m.now)
	// ExpiresAt is mutable after the session is published, so snapshot it
	// under Session.mu before insertion. This also orders the response read
	// before any future UDP Touch.
	sess.mu.Lock()
	expiresAt := sess.ExpiresAt
	sess.mu.Unlock()

	m.mu.Lock()
	replaced := false
	var snapshot *RevokedSessionSnapshot
	var revokeHandler RevocationHandler
	if oldID, exists := m.byUser[userID]; exists {
		if old, ok := m.sessions[oldID]; ok {
			old.mu.Lock()
			if !old.expiredLocked(nowMS) {
				snap := newRevokedSnapshotLocked(old)
				snapshot = &snap
				replaced = true
			}
			old.mu.Unlock()
			delete(m.sessions, oldID)
		}
		delete(m.byUser, userID)
	}
	m.sessions[id] = sess
	m.byUser[userID] = id
	revokeHandler = m.onRevoke
	m.mu.Unlock()

	if snapshot != nil && revokeHandler != nil {
		revokeHandler(RevocationReplaced, *snapshot)
	}

	return SessionInfo{
		ID:               id,
		Encrypted:        encrypted,
		MasterKey:        masterKey,
		ExpiresAt:        expiresAt,
		ReplacedPrevious: replaced,
	}, nil
}

// newSession initializes a session with a fresh replay window and rate budget.
func newSession(id [16]byte, userID int64, deviceID string, encrypted bool, nowMS int64, c2sAEAD, s2cAEAD cipher.AEAD, limits Limits, now func() time.Time) *Session {
	return &Session{
		ID:        id,
		UserID:    userID,
		DeviceID:  deviceID,
		CreatedAt: nowMS,
		ExpiresAt: nowMS + SessionTTL.Milliseconds(),
		encrypted: encrypted,
		c2sAEAD:   c2sAEAD,
		s2cAEAD:   s2cAEAD,
		rxBudget:  NewTokenBucket(float64(limits.SessionPacketsPerSec), limits.SessionBurst, now),
		rxReplay:  &ReplayWindow{},
	}
}

// Get returns the session with exactly this id, or false if it is unknown or
// already expired. Expired entries are deleted lazily here; the UDP hot path
// must never run a full table scan, so it only calls Get.
func (m *Manager) Get(id [16]byte) (*Session, bool) {
	m.mu.Lock()

	sess, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return nil, false
	}
	nowMS := m.nowMillis()
	sess.mu.Lock()
	expired := sess.expiredLocked(nowMS)
	sess.mu.Unlock()
	if !expired {
		m.mu.Unlock()
		return sess, true
	}

	m.deleteLocked(id, sess.UserID)
	handler := m.onExpire
	m.mu.Unlock()
	if handler != nil {
		handler(sess.UserID, id)
	}
	return nil, false
}

// SessionIDByUser returns the active session id for userID. It shares Get's
// lazy-expiry behavior: an expired entry is deleted and an ExpiryHandler, if
// installed, runs outside Manager/Session locks.
func (m *Manager) SessionIDByUser(userID int64) ([16]byte, bool) {
	m.mu.Lock()

	id, ok := m.byUser[userID]
	if !ok {
		m.mu.Unlock()
		return [16]byte{}, false
	}
	sess, ok := m.sessions[id]
	if !ok {
		delete(m.byUser, userID)
		m.mu.Unlock()
		return [16]byte{}, false
	}

	nowMS := m.nowMillis()
	sess.mu.Lock()
	expired := sess.expiredLocked(nowMS)
	sess.mu.Unlock()
	if !expired {
		m.mu.Unlock()
		return id, true
	}

	m.deleteLocked(id, sess.UserID)
	handler := m.onExpire
	m.mu.Unlock()
	if handler != nil {
		handler(sess.UserID, id)
	}
	return [16]byte{}, false
}

// Touch slides the session deadline to now + SessionTTL. The UDP server calls
// this (via Session.acceptPacket) for every packet that passes decryption and
// replay, audio and heartbeat alike.
func (m *Manager) Touch(id [16]byte) {
	sess, ok := m.Get(id)
	if !ok {
		return
	}
	sess.mu.Lock()
	sess.touchLocked(m.nowMillis())
	sess.mu.Unlock()
}

// InvalidateUser deletes every session registered to userID and returns how
// many table entries were removed. Active sessions produce one
// RevocationRevoked snapshot each; expired leftovers are removed silently.
// Kick, ban, account deletion and losing voice:join all call this.
func (m *Manager) InvalidateUser(userID int64) int {
	m.mu.Lock()

	id, exists := m.byUser[userID]
	if !exists {
		m.mu.Unlock()
		return 0
	}
	sess, ok := m.sessions[id]
	delete(m.sessions, id)
	delete(m.byUser, userID)
	if !ok {
		m.mu.Unlock()
		return 0
	}

	nowMS := m.nowMillis()
	sess.mu.Lock()
	snap := newRevokedSnapshotLocked(sess)
	active := !sess.expiredLocked(nowMS)
	sess.mu.Unlock()

	handler := m.onRevoke
	m.mu.Unlock()

	if active && handler != nil {
		// Run outside the manager lock: the handler may send a UDP packet.
		handler(RevocationRevoked, snap)
	}
	return 1
}

// Delete removes the session named by id when it belongs to userID. A missing
// or expired session reports ErrSessionNotFound; a session owned by another
// user reports ErrSessionNotOwned. Voluntary deletion never emits a
// revocation notification.
func (m *Manager) Delete(id [16]byte, userID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[id]
	if !ok {
		return ErrSessionNotFound
	}
	if sess.UserID != userID {
		return ErrSessionNotOwned
	}
	nowMS := m.nowMillis()
	sess.mu.Lock()
	expired := sess.expiredLocked(nowMS)
	sess.mu.Unlock()
	m.deleteLocked(id, userID)
	if expired {
		return ErrSessionNotFound
	}
	return nil
}

// Purge is the only full-table scan entry point. It deletes every expired
// session without revocation notifications; the UDP server drives it from a
// 30s ticker. The UDP hot path never calls Purge.
func (m *Manager) Purge() int {
	type expiredSession struct {
		id     [16]byte
		userID int64
	}

	m.mu.Lock()
	nowMS := m.nowMillis()
	var expired []expiredSession
	for id, sess := range m.sessions {
		sess.mu.Lock()
		isExpired := sess.expiredLocked(nowMS)
		sess.mu.Unlock()
		if isExpired {
			m.deleteLocked(id, sess.UserID)
			expired = append(expired, expiredSession{id: id, userID: sess.UserID})
		}
	}
	handler := m.onExpire
	m.mu.Unlock()

	if handler != nil {
		for _, sess := range expired {
			handler(sess.userID, sess.id)
		}
	}
	return len(expired)
}

// Len returns the current number of table entries, including not-yet-purged
// expired sessions. It is intended for diagnostics and tests.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// deleteLocked removes id from the table and the user index. Callers must
// hold m.mu and must not hold Session.mu.
func (m *Manager) deleteLocked(id [16]byte, userID int64) {
	delete(m.sessions, id)
	if current, ok := m.byUser[userID]; ok && current == id {
		delete(m.byUser, userID)
	}
}

// expiredLocked reports whether the session deadline has passed. Callers must
// hold Session.mu.
func (s *Session) expiredLocked(nowMS int64) bool {
	return nowMS >= s.ExpiresAt
}

// touchLocked slides the deadline to now + SessionTTL. Callers must hold
// Session.mu.
func (s *Session) touchLocked(nowMS int64) {
	s.ExpiresAt = nowMS + SessionTTL.Milliseconds()
}

// allowPacketAt consumes one token-bucket token. It runs before decryption so
// an attacker spraying cheap garbage cannot force expensive AEAD work. The
// caller passes the same clock sample used for the rest of the datagram.
func (s *Session) allowPacketAt(now time.Time) bool {
	return s.rxBudget.TakeAt(now)
}

// cryptoSnapshot copies the c2s AEAD handle and mode out of the session. The
// AEAD instance is immutable after session creation, so no key bytes are
// copied; the UDP read loop uses it outside Session.mu for decryption.
func (s *Session) cryptoSnapshot() (encrypted bool, c2sAEAD cipher.AEAD) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.encrypted, s.c2sAEAD
}

// acceptPacket runs replay, TTL slide and remote learning in one short
// critical section. Semantic validation (heartbeat shape, speaker_id,
// registered channel, flags) happens before this call, so invalid packets can
// never extend TTL or move the remote address.
func (s *Session) acceptPacket(seq uint64, now time.Time, remote *net.UDPAddr) (accepted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	accepted, advanced := s.rxReplay.Accept(seq)
	if !accepted {
		return false
	}
	s.touchLocked(now.UnixMilli())
	// remote follows only high-water advancement: a late in-window packet
	// from an old NAT mapping must never roll the address back.
	if advanced && remote != nil {
		s.remote = cloneUDPAddr(remote)
	}
	return true
}

// reserveSendSeq allocates the next s2c sequence inside Session.mu, then
// snapshots the s2c AEAD handle and remote for use outside the lock. The
// reservation is never rolled back, even if the subsequent WriteTo fails:
// reusing a seq would reuse a GCM nonce under the same key.
func (s *Session) reserveSendSeq() (seq uint64, encrypted bool, s2cAEAD cipher.AEAD, remote *net.UDPAddr, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sendSeq == math.MaxUint64 {
		return 0, false, nil, nil, ErrSequenceExhausted
	}
	s.sendSeq++
	if s.encrypted && s.s2cAEAD == nil {
		return 0, false, nil, nil, ErrNoKey
	}
	return s.sendSeq, s.encrypted, s.s2cAEAD, cloneUDPAddr(s.remote), nil
}

// newRevokedSnapshotLocked captures everything needed for a best-effort
// revocation notification. Callers must hold Session.mu. The SendSeq is
// reserved here (before deletion) and, like public Send reservations, is
// never rolled back. If the sequence is already exhausted, SendSeq is 0 and
// the UDP server skips the notification.
func newRevokedSnapshotLocked(s *Session) RevokedSessionSnapshot {
	snap := RevokedSessionSnapshot{
		ID:        s.ID,
		UserID:    s.UserID,
		Encrypted: s.encrypted,
		S2CAEAD:   s.s2cAEAD,
		Remote:    cloneUDPAddr(s.remote),
	}
	if s.sendSeq < math.MaxUint64 {
		s.sendSeq++
		snap.SendSeq = s.sendSeq
	}
	return snap
}

// randomSessionID returns a cryptographically random protocol session ID.
func randomSessionID() ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	return id, nil
}

// cloneUDPAddr deep-copies a UDP address. ReadFrom's addr may alias kernel
// buffer memory, and snapshots must outlive the read buffer, so the IP slice
// is always copied.
func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}
