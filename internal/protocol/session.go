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
	// ErrInvalidUserID is returned by Prepare for a non-positive user id.
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
	// ErrSessionPrecondition is returned when activation's expected old session
	// does not match the user's current session.
	ErrSessionPrecondition = errors.New("protocol: session activation precondition failed")
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
	// the application revoked this session.
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

// RevocationCleanup is the best-effort work that must run after the session
// has already been made inactive and removed from the Manager indexes. Calling
// it may wait for an in-flight UDP Send and perform a UDP notification; callers
// must keep it outside control-plane locks and may dispatch it to a bounded
// worker.
type RevocationCleanup func()

// ExpiryHandler receives sessions that expired naturally and were removed by
// Get, Send, SessionIDByUser or Purge. It runs outside Manager and Session
// locks on the goroutine that discovered the expiry, so it must be
// non-blocking. Natural expiry rejects new Sends through active=false but does
// not wait for pre-reserved writes because it has no notification ordering.
// Explicit Delete, InvalidateUser and preemption do not emit expiry callbacks.
type ExpiryHandler func(userID int64, sessionID [16]byte)

// SessionInfo is the result of a successful ActivatePrepared call: the session
// id and, in encrypted mode, the one-time master key for the caller's
// negotiation response.
type SessionInfo struct {
	ID               [16]byte
	UserID           int64
	Encrypted        bool
	MasterKey        []byte // nil in plaintext mode
	ExpiresAt        int64  // Unix milliseconds at creation time; slides with traffic
	ReplacedPrevious bool   // whether activation preempted an active session
}

// SessionSnapshot is immutable diagnostic state for one session. It never
// exposes transport keys, budgets, replay state, mutexes, or a live Session.
type SessionSnapshot struct {
	ID            [16]byte
	UserID        int64
	DeviceID      string
	CreatedAt     int64
	ExpiresAt     int64
	Encrypted     bool
	RemotePresent bool
}

// PreparedSession owns a fully allocated but unpublished session for exactly
// one Manager. It is safe to discard on any control-plane failure because it
// has not changed indexes; successful ActivatePrepared consumes it, and a
// different Manager always rejects it to preserve clock and limit ownership.
type PreparedSession struct {
	mu      sync.Mutex
	owner   *Manager
	session *Session
	info    SessionInfo
	used    bool
}

// Info returns the unpublished session negotiation result. The returned master
// key slice is copied so callers cannot mutate the one-time response material
// retained by PreparedSession before activation.
func (p *PreparedSession) Info() SessionInfo {
	if p == nil {
		return SessionInfo{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	info := p.info
	info.MasterKey = append([]byte(nil), p.info.MasterKey...)
	return info
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
	active    bool
	mu        sync.Mutex
	sendMu    sync.Mutex
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

// Prepare performs every fallible session allocation without publishing it to
// the Manager. The caller must later pass the result to ActivatePrepared.
func (m *Manager) Prepare(userID int64, deviceID string, encrypted bool) (*PreparedSession, error) {
	if userID <= 0 {
		return nil, ErrInvalidUserID
	}

	id, err := randomSessionID()
	if err != nil {
		return nil, err
	}

	var masterKey, c2s, s2c []byte
	var c2sAEAD, s2cAEAD cipher.AEAD
	if encrypted {
		masterKey, err = GenerateMasterKey()
		if err != nil {
			return nil, err
		}
		c2s, s2c, err = DeriveDirectionKeys(id, masterKey)
		if err != nil {
			return nil, err
		}
		if c2sAEAD, err = newGCM(c2s); err != nil {
			return nil, err
		}
		if s2cAEAD, err = newGCM(s2c); err != nil {
			return nil, err
		}
	}

	nowMS := m.nowMillis()
	sess := newSession(id, userID, deviceID, encrypted, nowMS, c2sAEAD, s2cAEAD, m.limits, m.now)
	// ExpiresAt is mutable after the session is published, so snapshot it
	// under Session.mu before insertion. This also orders the response read
	// before any future UDP traffic updates it.
	sess.mu.Lock()
	expiresAt := sess.ExpiresAt
	sess.mu.Unlock()

	return &PreparedSession{owner: m, session: sess, info: SessionInfo{ID: id, UserID: userID, Encrypted: encrypted, MasterKey: masterKey, ExpiresAt: expiresAt}}, nil
}

// ActivationCleanup performs the old-session best-effort UDP notification after
// an application staging lock has been released. It is safe to call once; a nil
// function represents a successful activation that replaced no live session.
type ActivationCleanup func()

// ActivatePreparedStaged publishes prepared when the user's current session
// matches expectedOldID. A nil expectation permits unconditional preemption. It
// returns cleanup work instead of executing UDP notification while a caller may
// still hold an application coordinator/publication lock.
func (m *Manager) ActivatePreparedStaged(prepared *PreparedSession, expectedOldID *[16]byte) (SessionInfo, ActivationCleanup, error) {
	if prepared == nil || prepared.session == nil || prepared.owner != m {
		return SessionInfo{}, nil, ErrSessionPrecondition
	}
	prepared.mu.Lock()
	if prepared.used {
		prepared.mu.Unlock()
		return SessionInfo{}, nil, ErrSessionPrecondition
	}
	userID := prepared.session.UserID
	nowMS := m.nowMillis()
	m.mu.Lock()
	currentID, exists := m.byUser[userID]
	if expectedOldID != nil && (!exists || currentID != *expectedOldID) {
		m.mu.Unlock()
		prepared.mu.Unlock()
		return SessionInfo{}, nil, ErrSessionPrecondition
	}
	// Mark used before publishing indexes. Every successful activation has one
	// linearization point, so a repeated call cannot deactivate and reinsert the
	// same live session.
	prepared.used = true
	replaced := false
	var removedSession *Session
	var revokeHandler RevocationHandler
	if oldID, exists := m.byUser[userID]; exists {
		if old, ok := m.sessions[oldID]; ok {
			old.mu.Lock()
			if !old.expiredLocked(nowMS) {
				replaced = true
			}
			old.deactivateLocked()
			old.mu.Unlock()
			delete(m.sessions, oldID)
			removedSession = old
		}
		delete(m.byUser, userID)
	}
	m.sessions[prepared.session.ID] = prepared.session
	m.byUser[userID] = prepared.session.ID
	revokeHandler = m.onRevoke
	m.mu.Unlock()
	prepared.mu.Unlock()

	info := prepared.info
	info.ReplacedPrevious = replaced
	info.MasterKey = append([]byte(nil), info.MasterKey...)
	cleanup := ActivationCleanup(func() {
		// Explicit replacement must drain an already-reserved Send even when the
		// session expired while that syscall was blocked. Expiry only suppresses
		// notification; it cannot release the write-order barrier.
		runRevocation(revocationWork{session: removedSession, reason: RevocationReplaced, handler: revokeHandler, notify: replaced})
	})
	return info, cleanup, nil
}

// ActivatePrepared publishes prepared and immediately performs its old-session
// cleanup. Application code that holds a coordinator or StatePublication lock
// must use ActivatePreparedStaged and run the returned cleanup after unlocking.
func (m *Manager) ActivatePrepared(prepared *PreparedSession, expectedOldID *[16]byte) (SessionInfo, error) {
	info, cleanup, err := m.ActivatePreparedStaged(prepared, expectedOldID)
	if err != nil {
		return SessionInfo{}, err
	}
	if cleanup != nil {
		cleanup()
	}
	return info, nil
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
		active:    true,
	}
}

// Get returns an immutable snapshot for id, or false if it is unknown or
// expired. It never exposes a live Session to callers outside this package.
func (m *Manager) Get(id [16]byte) (SessionSnapshot, bool) {
	sess, ok := m.getSession(id)
	if !ok {
		return SessionSnapshot{}, false
	}
	sess.mu.Lock()
	snap := SessionSnapshot{ID: sess.ID, UserID: sess.UserID, DeviceID: sess.DeviceID, CreatedAt: sess.CreatedAt, ExpiresAt: sess.ExpiresAt, Encrypted: sess.encrypted, RemotePresent: sess.remote != nil}
	sess.mu.Unlock()
	return snap, true
}

// getSession returns the live internal session for UDP operations. Expired
// entries are removed lazily; callers must not retain the result across an
// operation without checking Session.active under Session.mu.
func (m *Manager) getSession(id [16]byte) (*Session, bool) {
	m.mu.Lock()

	sess, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return nil, false
	}
	nowMS := m.nowMillis()
	sess.mu.Lock()
	expired := sess.expiredLocked(nowMS)
	if expired {
		sess.deactivateLocked()
	}
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
	if expired {
		sess.deactivateLocked()
	}
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

// InvalidateUser deletes every session registered to userID and returns how
// many table entries were removed. Active sessions produce one
// RevocationRevoked snapshot each; expired leftovers are removed silently.
// Kick, ban, account deletion and losing channel access all call this.
func (m *Manager) InvalidateUser(userID int64) int {
	m.mu.Lock()

	id, exists := m.byUser[userID]
	if !exists {
		m.mu.Unlock()
		return 0
	}
	sess, ok := m.sessions[id]
	if !ok {
		delete(m.byUser, userID)
		m.mu.Unlock()
		return 0
	}

	nowMS := m.nowMillis()
	sess.mu.Lock()
	active := !sess.expiredLocked(nowMS)
	sess.deactivateLocked()
	sess.mu.Unlock()

	delete(m.sessions, id)
	delete(m.byUser, userID)
	handler := m.onRevoke
	m.mu.Unlock()

	// This always drains sendMu, including when the session expired or no UDP
	// callback is wired. Otherwise an already-blocked Send could write old audio
	// after this method returned. Only a still-active session may notify peers.
	runRevocation(revocationWork{session: sess, reason: RevocationRevoked, handler: handler, notify: active})
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
	sess.deactivateLocked()
	sess.mu.Unlock()
	m.deleteLocked(id, userID)
	if expired {
		return ErrSessionNotFound
	}
	return nil
}

// Revoke removes exactly id when it belongs to userID and drains its send
// barrier before issuing the best-effort revocation notification. It is used
// when control-plane authority is lost; voluntary leave continues to use Delete
// and intentionally emits no revocation frame.
func (m *Manager) Revoke(id [16]byte, userID int64) error {
	cleanup, err := m.RevokeStaged(id, userID)
	if err != nil {
		return err
	}
	if cleanup != nil {
		cleanup()
	}
	return nil
}

// RevokeStaged makes the exact session inactive and removes it from the
// Manager indexes synchronously, then returns the sendMu/UDP notification work
// for execution outside caller locks. This keeps auth and coordinator teardown
// non-blocking while preserving audio-before-revocation ordering.
func (m *Manager) RevokeStaged(id [16]byte, userID int64) (RevocationCleanup, error) {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return nil, ErrSessionNotFound
	}
	if sess.UserID != userID {
		m.mu.Unlock()
		return nil, ErrSessionNotOwned
	}
	nowMS := m.nowMillis()
	sess.mu.Lock()
	active := !sess.expiredLocked(nowMS)
	sess.deactivateLocked()
	sess.mu.Unlock()
	m.deleteLocked(id, userID)
	handler := m.onRevoke
	m.mu.Unlock()
	cleanup := RevocationCleanup(func() {
		runRevocation(revocationWork{session: sess, reason: RevocationRevoked, handler: handler, notify: active})
	})
	if !active {
		return cleanup, ErrSessionNotFound
	}
	return cleanup, nil
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
		if isExpired {
			sess.deactivateLocked()
		}
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

// deactivateLocked makes a removed session reject every future receive and
// send reservation. Callers hold s.mu before removing it from Manager indexes.
func (s *Session) deactivateLocked() {
	s.active = false
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
type receiveDecision uint8

const (
	receiveAccepted receiveDecision = iota
	receiveDroppedReplay
	receiveDroppedRateLimit
	receiveDroppedInactive
)

// acceptPacket atomically validates liveness, replay and authenticated rate
// budget before advancing the replay window or learning a remote address.
func (s *Session) acceptPacket(seq uint64, now time.Time, remote *net.UDPAddr) receiveDecision {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return receiveDroppedInactive
	}
	if !s.rxReplay.WouldAccept(seq) {
		return receiveDroppedReplay
	}
	if !s.rxBudget.TakeAt(now) {
		return receiveDroppedRateLimit
	}
	accepted, advanced := s.rxReplay.Accept(seq)
	if !accepted {
		panic("protocol: replay window changed while session lock held")
	}
	s.touchLocked(now.UnixMilli())
	// remote follows only high-water advancement: a late in-window packet
	// from an old NAT mapping must never roll the address back.
	if advanced && remote != nil {
		s.remote = cloneUDPAddr(remote)
	}
	return receiveAccepted
}

// reserveSendSeq allocates the next s2c sequence inside Session.mu, then
// snapshots the s2c AEAD handle and remote for use outside the lock. The
// reservation is never rolled back, even if the subsequent WriteTo fails:
// reusing a seq would reuse a GCM nonce under the same key.
func (s *Session) reserveSendSeq() (seq uint64, encrypted bool, s2cAEAD cipher.AEAD, remote *net.UDPAddr, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return 0, false, nil, nil, ErrSessionNotFound
	}
	if s.sendSeq == math.MaxUint64 {
		return 0, false, nil, nil, ErrSequenceExhausted
	}
	s.sendSeq++
	if s.encrypted && s.s2cAEAD == nil {
		return 0, false, nil, nil, ErrNoKey
	}
	return s.sendSeq, s.encrypted, s.s2cAEAD, cloneUDPAddr(s.remote), nil
}

// revocationWork retains a removed session until its in-flight Send operation
// has drained and any eligible UDP notification has been reserved.
type revocationWork struct {
	session *Session
	reason  RevocationReason
	handler RevocationHandler
	notify  bool
}

// runRevocation serializes explicit revocation behind old audio writes without
// holding Manager.mu. It drains sendMu even without a notification handler so
// removal is a Send barrier. A missing peer or exhausted sequence skips the
// best-effort callback because no valid UDP notification can be built.
func runRevocation(work revocationWork) {
	if work.session == nil {
		return
	}

	work.session.sendMu.Lock()
	var snapshot *RevokedSessionSnapshot
	if work.notify && work.handler != nil {
		work.session.mu.Lock()
		if work.session.remote != nil && work.session.sendSeq < math.MaxUint64 {
			snap := newRevokedSnapshotLocked(work.session)
			snapshot = &snap
		}
		work.session.mu.Unlock()
	}
	work.session.sendMu.Unlock()

	if snapshot != nil {
		work.handler(work.reason, *snapshot)
	}
}

// newRevokedSnapshotLocked captures everything needed for a best-effort
// revocation notification. Callers must hold Session.mu after sendMu has
// drained. The SendSeq reservation is never rolled back.
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
