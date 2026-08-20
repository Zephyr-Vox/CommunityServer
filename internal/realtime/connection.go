package realtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"zephyr.vox/server/ce/internal/protocol"
)

const (
	// MaxActiveControlConnections is the fixed v1 process-wide cap covering
	// both opening reservations and active WebSocket control connections.
	MaxActiveControlConnections = 4096
	// MaxControlConnectionsPerUser is the fixed v1 cap for one user's opening
	// and active WebSocket control connections.
	MaxControlConnectionsPerUser = 8
	// MaxControlConnectionsPerSource is the fixed v1 cap for one source IP's
	// opening and active WebSocket control connections.
	MaxControlConnectionsPerSource = 64
)

var (
	// ErrInvalidConnection is returned when a caller supplies an invalid user,
	// login session, connection reference, lease, or connection transport.
	ErrInvalidConnection = errors.New("realtime: invalid control connection")
	// ErrControlConnectionLimit is returned before a connection becomes visible
	// when its global or per-user admission cap would be exceeded.
	ErrControlConnectionLimit = errors.New("realtime: control connection limit reached")
	// ErrSourceConnectionLimit is returned before a connection becomes visible
	// when the source IP has already reached its fixed active connection cap.
	ErrSourceConnectionLimit = errors.New("realtime: source control connection limit reached")
	// ErrConnectionAdmissionClosed is returned after shutdown begins and no new
	// opening control connection may be reserved.
	ErrConnectionAdmissionClosed = errors.New("realtime: control connection admission closed")
	// ErrConnectionNotOpening is returned when an opening reservation lost a
	// concurrent revocation race before it could become active.
	ErrConnectionNotOpening = errors.New("realtime: control connection is not opening")
	// ErrConnectionNotActive is returned when a lease operation names a closing
	// or missing connection generation.
	ErrConnectionNotActive = errors.New("realtime: control connection is not active")
	// ErrVoiceAuthorityPrecondition is returned when a staged voice transition
	// names an authority or control generation that is no longer current.
	ErrVoiceAuthorityPrecondition = errors.New("realtime: voice authority precondition failed")
)

// ConnectionState is the lifecycle state of one control connection.
type ConnectionState uint8

const (
	// ConnectionOpening is reserved by an authenticated handshake but does not
	// participate in presence or receive business frames.
	ConnectionOpening ConnectionState = iota + 1
	// ConnectionActive has completed the WebSocket upgrade and can receive its
	// first server frame through its write pump.
	ConnectionActive
	// ConnectionClosing has exactly one teardown owner and accepts no new work.
	ConnectionClosing
)

// ControlConnectionRef is the immutable identity used by all conditional
// teardown paths. Generation distinguishes a stale callback from a later
// connection, even if a future coordinator implementation reuses an ID.
type ControlConnectionRef struct {
	ControlConnectionID [16]byte
	UserID              int64
	Generation          uint64
	LoginSessionID      int64
}

// IDHex returns the protocol representation of ControlConnectionID.
func (r ControlConnectionRef) IDHex() string {
	return hex.EncodeToString(r.ControlConnectionID[:])
}

// AuthLease is one active control connection's authenticated access-token
// expiry. Revision changes on every valid auth.update, making old timers no-op.
type AuthLease struct {
	Revision  uint64
	ExpiresAt int64
}

// VoiceAuthority is the complete ephemeral authority tuple for a user's one
// voice membership. Every teardown must match all fields, including both
// generations, so a stale WS/UDP callback cannot remove a newer replacement or
// move.
type VoiceAuthority struct {
	UserID                   int64
	ChannelID                int64
	ControlConnectionID      [16]byte
	ConnectionGeneration     uint64
	VoiceSessionID           [16]byte
	VoiceAuthorityGeneration uint64
	JoinedAt                 int64
}

// Valid reports whether a voice authority has every required identity field.
func (a VoiceAuthority) Valid() bool {
	return a.UserID > 0 && a.ChannelID > 0 && a.ControlConnectionID != [16]byte{} && a.ConnectionGeneration > 0 && a.VoiceSessionID != [16]byte{} && a.VoiceAuthorityGeneration > 0 && a.JoinedAt >= 0
}

// VoiceAuthorityStage is an unpublished replacement or move. Stage creation
// validates only against a snapshot; Apply rechecks its exact preconditions
// while holding the coordinator user lock and is the sole runtime commit point.
type VoiceAuthorityStage struct {
	coordinator *ConnectionCoordinator
	owner       ControlConnectionRef
	expected    *VoiceAuthority
	channelID   int64
	prepared    *protocol.PreparedSession
	joinedAt    int64
}

// VoiceAuthorityCommit is the immutable work returned by a successful staged
// transition. Cleanup must run after the caller releases publication and
// coordinator locks because it may wait for old UDP sends before notification.
type VoiceAuthorityCommit struct {
	Previous *VoiceAuthority
	Current  VoiceAuthority
	Cleanup  protocol.ActivationCleanup
}

// ConnectionTransport accepts non-blocking terminal-close and forced-close
// requests. Its implementation owns normal socket writes; ForceClose exists
// only for a shutdown deadline that has already exhausted graceful delivery.
type ConnectionTransport interface {
	RequestClose(statusCode int, reason string)
	ForceClose()
}

// VoiceSessionDeactivator immediately makes a UDP session reject future media.
// It is invoked after the coordinator user lock is released on WS owner close;
// membership/event cleanup remains the caller's sequenced responsibility.
type VoiceSessionDeactivator func(userID int64, sessionID [16]byte, reason string)

// ConnectionReservation represents one opening control connection. It is safe
// to discard on an unsuccessful HTTP upgrade; Activate and Abort are both
// conditional and stale calls do not affect another connection.
type ConnectionReservation struct {
	coordinator *ConnectionCoordinator
	ref         ControlConnectionRef
}

// Ref returns the immutable connection identity allocated by ReserveConnect.
func (r *ConnectionReservation) Ref() ControlConnectionRef {
	if r == nil {
		return ControlConnectionRef{}
	}
	return r.ref
}

// Activate changes this reservation from opening to active, assigns its socket
// transport, and starts auth lease revision one at accessExpiresAt. A concurrent
// session/account revocation wins by making the reservation closing.
func (r *ConnectionReservation) Activate(transport ConnectionTransport, accessExpiresAt int64) (ControlConnectionRef, AuthLease, error) {
	if r == nil || r.coordinator == nil || transport == nil || accessExpiresAt <= 0 {
		return ControlConnectionRef{}, AuthLease{}, ErrInvalidConnection
	}
	return r.coordinator.activate(r.ref, transport, accessExpiresAt)
}

// Abort removes an opening reservation when the WebSocket upgrade fails. A
// reservation already marked closing is also removed because no transport was
// ever attached for a write-pump close request.
func (r *ConnectionReservation) Abort() {
	if r == nil || r.coordinator == nil {
		return
	}
	r.coordinator.abort(r.ref)
}

// ConnectionCoordinator is the sole owner of control-connection lifecycle
// state. It permits several active connections for one user while making every
// close source converge on one conditional opening/active -> closing transition.
// It never performs database work, socket I/O, or waits while holding a user
// lock.
type ConnectionCoordinator struct {
	indexMu sync.Mutex
	users   map[int64]*connectionUser

	admissionMu sync.Mutex
	accepting   bool
	admitted    int
	sources     map[netip.Addr]int
	wg          sync.WaitGroup
	voiceStop   atomic.Pointer[voiceStopValue]
}

type voiceStopValue struct {
	stop VoiceSessionDeactivator
}

type connectionUser struct {
	userID      int64
	mu          sync.Mutex
	refs        int
	connections map[[16]byte]*connectionRecord
	nextGen     uint64
	admitted    int
	live        atomic.Int64
	voice       *VoiceAuthority
	nextVoice   uint64
}

type connectionRecord struct {
	ref       ControlConnectionRef
	state     ConnectionState
	admitted  bool
	sourceIP  netip.Addr
	lease     AuthLease
	transport ConnectionTransport
}

type connectionClosePlan struct {
	transport ConnectionTransport
	status    int
	reason    string
	voiceStop VoiceSessionDeactivator
	voiceID   [16]byte
	voiceUser int64
}

// NewConnectionCoordinator returns an empty connection lifecycle owner with
// admission enabled.
func NewConnectionCoordinator() *ConnectionCoordinator {
	return &ConnectionCoordinator{
		accepting: true,
		users:     make(map[int64]*connectionUser),
		sources:   make(map[netip.Addr]int),
	}
}

// SetVoiceSessionDeactivator installs the transport-side immediate voice stop
// callback. It must be configured before connections are admitted; the callback
// is never invoked while a coordinator lock is held.
func (c *ConnectionCoordinator) SetVoiceSessionDeactivator(stop VoiceSessionDeactivator) {
	if c == nil {
		return
	}
	if stop == nil {
		c.voiceStop.Store(nil)
		return
	}
	c.voiceStop.Store(&voiceStopValue{stop: stop})
}

// ReserveConnect creates an opening connection reservation without source-IP
// accounting. It exists for internal deterministic tests; WebSocket handlers
// must call ReserveConnectFrom after parsing the actual peer address.
func (c *ConnectionCoordinator) ReserveConnect(userID, loginSessionID int64) (*ConnectionReservation, error) {
	return c.ReserveConnectFrom(userID, loginSessionID, netip.Addr{})
}

// ReserveConnectFrom creates an opening connection reservation under userID
// and sourceIP. The caller invokes it inside the authenticated principal read
// barrier, ensuring an account/session revoke either precedes the reservation
// or sees it in the opening set and marks it closing.
func (c *ConnectionCoordinator) ReserveConnectFrom(userID, loginSessionID int64, sourceIP netip.Addr) (*ConnectionReservation, error) {
	if c == nil || userID <= 0 || loginSessionID <= 0 {
		return nil, ErrInvalidConnection
	}
	if sourceIP.IsValid() {
		sourceIP = sourceIP.Unmap()
	}
	id, err := randomControlConnectionID()
	if err != nil {
		return nil, err
	}
	user := c.acquireUser(userID)
	defer c.releaseUser(userID, user)

	user.mu.Lock()
	defer user.mu.Unlock()
	if user.admitted >= MaxControlConnectionsPerUser {
		return nil, ErrControlConnectionLimit
	}
	if err := c.reserveAdmission(sourceIP); err != nil {
		return nil, err
	}
	user.admitted++
	user.nextGen++
	ref := ControlConnectionRef{
		ControlConnectionID: id,
		UserID:              userID,
		Generation:          user.nextGen,
		LoginSessionID:      loginSessionID,
	}
	user.connections[id] = &connectionRecord{
		ref:      ref,
		state:    ConnectionOpening,
		admitted: true,
		sourceIP: sourceIP,
	}
	user.live.Add(1)
	return &ConnectionReservation{coordinator: c, ref: ref}, nil
}

// AdmissionOpen reports whether shutdown has stopped new connection
// reservations. It lets the HTTP upgrade handler reject early before it spends
// authentication or WebSocket handshake work.
func (c *ConnectionCoordinator) AdmissionOpen() bool {
	if c == nil {
		return false
	}
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	return c.accepting
}

// StopAdmission prevents every later ReserveConnectFrom call from allocating
// an opening connection. It is idempotent and linearizes with reservation Add
// calls, so Wait can safely begin after it returns.
func (c *ConnectionCoordinator) StopAdmission() {
	if c == nil {
		return
	}
	c.admissionMu.Lock()
	c.accepting = false
	c.admissionMu.Unlock()
}

// Wait waits for every reservation admitted before StopAdmission to finish its
// read and write goroutines. Callers must stop admission first; otherwise a
// concurrent reservation could be added while Wait is in progress.
func (c *ConnectionCoordinator) Wait(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrInvalidConnection
	}
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ForceCloseAll closes all remaining transports without a close-frame wait.
// It is only used after graceful shutdown's deadline expires and therefore is
// intentionally outside the normal single write-pump path.
func (c *ConnectionCoordinator) ForceCloseAll() {
	if c == nil {
		return
	}
	users := c.acquireAllUsers()
	for _, user := range users {
		transports := make([]ConnectionTransport, 0)
		user.mu.Lock()
		for _, record := range user.connections {
			if record.transport != nil {
				transports = append(transports, record.transport)
			}
		}
		user.mu.Unlock()
		for _, transport := range transports {
			transport.ForceClose()
		}
		c.releaseUser(user.userID, user)
	}
}

// activate assigns transport, makes ref active, and records its initial access
// lease only when the opening record still exactly matches.
func (c *ConnectionCoordinator) activate(ref ControlConnectionRef, transport ConnectionTransport, accessExpiresAt int64) (ControlConnectionRef, AuthLease, error) {
	if c == nil || !validConnectionRef(ref) || transport == nil || accessExpiresAt <= 0 {
		return ControlConnectionRef{}, AuthLease{}, ErrInvalidConnection
	}
	user := c.acquireUser(ref.UserID)
	defer c.releaseUser(ref.UserID, user)
	user.mu.Lock()
	defer user.mu.Unlock()
	record := user.connections[ref.ControlConnectionID]
	if record == nil || record.ref != ref || record.state != ConnectionOpening {
		return ControlConnectionRef{}, AuthLease{}, ErrConnectionNotOpening
	}
	record.transport = transport
	record.state = ConnectionActive
	record.lease = AuthLease{Revision: 1, ExpiresAt: accessExpiresAt}
	return ref, record.lease, nil
}

// AuthLease returns ref's current lease while it is active.
func (c *ConnectionCoordinator) AuthLease(ref ControlConnectionRef) (AuthLease, bool) {
	if c == nil || !validConnectionRef(ref) {
		return AuthLease{}, false
	}
	user := c.acquireUser(ref.UserID)
	defer c.releaseUser(ref.UserID, user)
	user.mu.Lock()
	defer user.mu.Unlock()
	record := user.connections[ref.ControlConnectionID]
	if record == nil || record.ref != ref || record.state != ConnectionActive {
		return AuthLease{}, false
	}
	return record.lease, true
}

// RenewAuthLease replaces ref's expiry after auth.update revalidated the same
// user and login session. It rejects an already expired current lease, then
// increments the revision so every older timer becomes a harmless mismatch.
func (c *ConnectionCoordinator) RenewAuthLease(ref ControlConnectionRef, accessExpiresAt, nowMillis int64) (AuthLease, error) {
	if c == nil || !validConnectionRef(ref) || accessExpiresAt <= 0 || nowMillis <= 0 {
		return AuthLease{}, ErrInvalidConnection
	}
	user := c.acquireUser(ref.UserID)
	defer c.releaseUser(ref.UserID, user)
	user.mu.Lock()
	defer user.mu.Unlock()
	record := user.connections[ref.ControlConnectionID]
	if record == nil || record.ref != ref || record.state != ConnectionActive || record.lease.ExpiresAt <= nowMillis {
		return AuthLease{}, ErrConnectionNotActive
	}
	record.lease.Revision++
	record.lease.ExpiresAt = accessExpiresAt
	return record.lease, nil
}

// VoiceAuthority returns userID's current voice authority as an independent
// copy. It is intended for HTTP join/leave adapters and relay validation;
// callers must use a staged transition or BeginVoiceDisconnect to mutate it.
func (c *ConnectionCoordinator) VoiceAuthority(userID int64) (VoiceAuthority, bool) {
	if c == nil || userID <= 0 {
		return VoiceAuthority{}, false
	}
	user := c.acquireUser(userID)
	defer c.releaseUser(userID, user)
	user.mu.Lock()
	defer user.mu.Unlock()
	if user.voice == nil {
		return VoiceAuthority{}, false
	}
	return *user.voice, true
}

// ActiveConnection returns the current generation for controlConnectionID only
// when it belongs to userID and is active. HTTP join/leave adapters use this to
// resolve X-Zephyr-Control-Connection without trusting a client generation.
func (c *ConnectionCoordinator) ActiveConnection(userID int64, controlConnectionID [16]byte) (ControlConnectionRef, bool) {
	if c == nil || userID <= 0 || controlConnectionID == [16]byte{} {
		return ControlConnectionRef{}, false
	}
	user := c.acquireUser(userID)
	defer c.releaseUser(userID, user)
	user.mu.Lock()
	defer user.mu.Unlock()
	record := user.connections[controlConnectionID]
	if record == nil || record.state != ConnectionActive {
		return ControlConnectionRef{}, false
	}
	return record.ref, true
}

// StageVoiceReplacement validates a proposed voice replacement or same-owner
// channel move without changing runtime state. expected must be nil only when
// no current authority exists. prepared creates/replaces a UDP session; nil
// reuses the exact expected session and changes only channel authority.
func (c *ConnectionCoordinator) StageVoiceReplacement(owner ControlConnectionRef, expected *VoiceAuthority, channelID int64, prepared *protocol.PreparedSession, joinedAt int64) (*VoiceAuthorityStage, error) {
	if c == nil || !validConnectionRef(owner) || channelID <= 0 || joinedAt < 0 {
		return nil, ErrVoiceAuthorityPrecondition
	}
	if expected != nil && (!expected.Valid() || expected.UserID != owner.UserID) {
		return nil, ErrVoiceAuthorityPrecondition
	}
	if prepared == nil && expected == nil {
		return nil, ErrVoiceAuthorityPrecondition
	}
	if prepared != nil {
		info := prepared.Info()
		if info.ID == [16]byte{} {
			return nil, ErrVoiceAuthorityPrecondition
		}
	}
	user := c.acquireUser(owner.UserID)
	defer c.releaseUser(owner.UserID, user)
	user.mu.Lock()
	defer user.mu.Unlock()
	if !user.connectionActiveLocked(owner) || !sameVoiceAuthority(user.voice, expected) {
		return nil, ErrVoiceAuthorityPrecondition
	}
	if prepared == nil && (expected.ControlConnectionID != owner.ControlConnectionID || expected.ConnectionGeneration != owner.Generation) {
		return nil, ErrVoiceAuthorityPrecondition
	}
	return &VoiceAuthorityStage{
		coordinator: c,
		owner:       owner,
		expected:    cloneVoiceAuthority(expected),
		channelID:   channelID,
		prepared:    prepared,
		joinedAt:    joinedAt,
	}, nil
}

// Apply commits the staged authority under the coordinator user lock. When a
// prepared session is supplied, protocol activation occurs while that lock is
// held but its UDP cleanup is returned for the caller to execute later. This
// preserves the required publication -> coordinator -> Manager lock order
// without allowing network I/O or sendMu waiting under coordinator ownership.
func (s *VoiceAuthorityStage) Apply(manager *protocol.Manager) (VoiceAuthorityCommit, error) {
	if s == nil || s.coordinator == nil || !validConnectionRef(s.owner) {
		return VoiceAuthorityCommit{}, ErrVoiceAuthorityPrecondition
	}
	if s.prepared != nil && manager == nil {
		return VoiceAuthorityCommit{}, ErrVoiceAuthorityPrecondition
	}
	user := s.coordinator.acquireUser(s.owner.UserID)
	defer s.coordinator.releaseUser(s.owner.UserID, user)
	user.mu.Lock()
	defer user.mu.Unlock()
	if !user.connectionActiveLocked(s.owner) || !sameVoiceAuthority(user.voice, s.expected) {
		return VoiceAuthorityCommit{}, ErrVoiceAuthorityPrecondition
	}

	previous := cloneVoiceAuthority(user.voice)
	var sessionID [16]byte
	var cleanup protocol.ActivationCleanup
	if s.prepared != nil {
		var expectedSessionID *[16]byte
		if s.expected != nil {
			id := s.expected.VoiceSessionID
			expectedSessionID = &id
		}
		info, stagedCleanup, err := manager.ActivatePreparedStaged(s.prepared, expectedSessionID)
		if err != nil {
			return VoiceAuthorityCommit{}, err
		}
		sessionID = info.ID
		cleanup = stagedCleanup
	} else {
		sessionID = s.expected.VoiceSessionID
	}
	user.nextVoice++
	current := VoiceAuthority{
		UserID:                   s.owner.UserID,
		ChannelID:                s.channelID,
		ControlConnectionID:      s.owner.ControlConnectionID,
		ConnectionGeneration:     s.owner.Generation,
		VoiceSessionID:           sessionID,
		VoiceAuthorityGeneration: user.nextVoice,
		JoinedAt:                 s.joinedAt,
	}
	user.voice = &current
	return VoiceAuthorityCommit{Previous: previous, Current: current, Cleanup: cleanup}, nil
}

// BeginVoiceDisconnect conditionally clears expected authority and deactivates
// its UDP session. Missing protocol sessions are treated as already inactive so
// UDP expiry can converge the binding after the transport removed it first.
func (c *ConnectionCoordinator) BeginVoiceDisconnect(expected VoiceAuthority, manager *protocol.Manager) (VoiceAuthority, bool, error) {
	if c == nil || !expected.Valid() {
		return VoiceAuthority{}, false, ErrVoiceAuthorityPrecondition
	}
	user := c.acquireUser(expected.UserID)
	defer c.releaseUser(expected.UserID, user)
	user.mu.Lock()
	defer user.mu.Unlock()
	if !sameVoiceAuthority(user.voice, &expected) {
		return VoiceAuthority{}, false, nil
	}
	if manager != nil {
		err := manager.Delete(expected.VoiceSessionID, expected.UserID)
		if err != nil && !errors.Is(err, protocol.ErrSessionNotFound) {
			return VoiceAuthority{}, false, err
		}
	}
	removed := *user.voice
	user.voice = nil
	return removed, true, nil
}

// ExpireAuthLease conditionally begins a 4001 close when expected is still the
// current lease and nowMillis has reached its expiry. An auth.update racing the
// timer increments Revision first, so the timer loses without side effects.
func (c *ConnectionCoordinator) ExpireAuthLease(ref ControlConnectionRef, expected AuthLease, nowMillis int64) bool {
	if c == nil || !validConnectionRef(ref) || expected.Revision == 0 || expected.ExpiresAt <= 0 || nowMillis < expected.ExpiresAt {
		return false
	}
	user := c.acquireUser(ref.UserID)
	defer c.releaseUser(ref.UserID, user)
	user.mu.Lock()
	record := user.connections[ref.ControlConnectionID]
	if record == nil || record.ref != ref || record.state != ConnectionActive || record.lease != expected {
		user.mu.Unlock()
		return false
	}
	plan, ok := c.beginDisconnectLocked(user, ref, 4001, "token expired")
	user.mu.Unlock()
	c.runClosePlan(plan)
	return ok
}

// BeginDisconnect changes ref from opening or active to closing. The first
// caller returns true and owns the terminal-close request; later or stale calls
// return false without disturbing a newer generation.
func (c *ConnectionCoordinator) BeginDisconnect(ref ControlConnectionRef, statusCode int, reason string) bool {
	if c == nil || !validConnectionRef(ref) {
		return false
	}
	user := c.acquireUser(ref.UserID)
	defer c.releaseUser(ref.UserID, user)
	user.mu.Lock()
	plan, ok := c.beginDisconnectLocked(user, ref, statusCode, reason)
	user.mu.Unlock()
	c.runClosePlan(plan)
	return ok
}

// FinishDisconnect removes a connection already placed in closing. It is safe
// after EOF, failed activation, duplicate callbacks, and old generations.
func (c *ConnectionCoordinator) FinishDisconnect(ref ControlConnectionRef) {
	if c == nil || !validConnectionRef(ref) {
		return
	}
	c.finish(ref)
}

// DisconnectLoginSession marks every opening or active connection for one
// login session closing. Auth services call it while their user mutation
// barrier remains held after the persisted session is revoked.
func (c *ConnectionCoordinator) DisconnectLoginSession(userID, loginSessionID int64, reason string) {
	if c == nil || userID <= 0 || loginSessionID <= 0 {
		return
	}
	c.disconnectMatching(userID, reason, func(ref ControlConnectionRef) bool {
		return ref.LoginSessionID == loginSessionID
	})
}

// DisconnectUser marks every opening or active control connection of userID
// closing. Account-wide auth mutations call it while the target user's
// principal mutation barrier remains held.
func (c *ConnectionCoordinator) DisconnectUser(userID int64, reason string) {
	if c == nil || userID <= 0 {
		return
	}
	c.disconnectMatching(userID, reason, func(ControlConnectionRef) bool { return true })
}

// DisconnectAll marks every opening or active control connection closing. It
// must follow StopAdmission during graceful shutdown so no later reservation
// can escape this pass.
func (c *ConnectionCoordinator) DisconnectAll(statusCode int, reason string) {
	if c == nil {
		return
	}
	users := c.acquireAllUsers()
	for _, user := range users {
		plans := make([]connectionClosePlan, 0)
		user.mu.Lock()
		for _, record := range user.connections {
			plan, ok := c.beginDisconnectLocked(user, record.ref, statusCode, reason)
			if ok {
				plans = append(plans, plan)
			}
		}
		user.mu.Unlock()
		for _, plan := range plans {
			c.runClosePlan(plan)
		}
		c.releaseUser(user.userID, user)
	}
}

// State returns ref's current lifecycle state. It is primarily diagnostics and
// deterministic tests; callers must still use BeginDisconnect for mutations.
func (c *ConnectionCoordinator) State(ref ControlConnectionRef) (ConnectionState, bool) {
	if c == nil || !validConnectionRef(ref) {
		return 0, false
	}
	user := c.acquireUser(ref.UserID)
	defer c.releaseUser(ref.UserID, user)
	user.mu.Lock()
	defer user.mu.Unlock()
	record := user.connections[ref.ControlConnectionID]
	if record == nil || record.ref != ref {
		return 0, false
	}
	return record.state, true
}

// ActiveCount returns the number of opening and active admissions. Closing
// records are excluded as soon as their one teardown transition succeeds.
func (c *ConnectionCoordinator) ActiveCount() int {
	if c == nil {
		return 0
	}
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	return c.admitted
}

// SourceCount returns sourceIP's opening and active admission count. It is
// intended for metrics and deterministic admission tests.
func (c *ConnectionCoordinator) SourceCount(sourceIP netip.Addr) int {
	if c == nil || !sourceIP.IsValid() {
		return 0
	}
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	return c.sources[sourceIP.Unmap()]
}

// beginDisconnectLocked claims one connection's teardown. Caller must hold
// user.mu. Socket close is returned as work so it always happens after this
// coordinator lock has been released.
func (c *ConnectionCoordinator) beginDisconnectLocked(user *connectionUser, ref ControlConnectionRef, statusCode int, reason string) (connectionClosePlan, bool) {
	record := user.connections[ref.ControlConnectionID]
	if record == nil || record.ref != ref || record.state == ConnectionClosing {
		return connectionClosePlan{}, false
	}
	record.state = ConnectionClosing
	c.releaseAdmissionLocked(user, record)
	plan := connectionClosePlan{transport: record.transport, status: statusCode, reason: reason}
	if user.voice != nil && user.voice.ControlConnectionID == ref.ControlConnectionID && user.voice.ConnectionGeneration == ref.Generation {
		if stop := c.voiceStop.Load(); stop != nil {
			plan.voiceStop = stop.stop
		}
		plan.voiceID = user.voice.VoiceSessionID
		plan.voiceUser = user.voice.UserID
		user.voice = nil
	}
	return plan, true
}

// runClosePlan executes socket and immediate UDP side effects after all
// coordinator locks have been released. Sequenced membership/presence cleanup
// is deliberately outside this low-level lifecycle callback.
func (c *ConnectionCoordinator) runClosePlan(plan connectionClosePlan) {
	if plan.voiceStop != nil {
		plan.voiceStop(plan.voiceUser, plan.voiceID, plan.reason)
	}
	if plan.transport != nil {
		plan.transport.RequestClose(plan.status, plan.reason)
	}
}

// disconnectMatching applies the same conditional transition to one user's
// matching records, then submits all terminal close requests without holding
// the coordinator's user lock.
func (c *ConnectionCoordinator) disconnectMatching(userID int64, reason string, match func(ControlConnectionRef) bool) {
	user := c.acquireUser(userID)
	defer c.releaseUser(userID, user)
	plans := make([]connectionClosePlan, 0)
	user.mu.Lock()
	for _, record := range user.connections {
		if match(record.ref) {
			plan, ok := c.beginDisconnectLocked(user, record.ref, 4002, reason)
			if ok {
				plans = append(plans, plan)
			}
		}
	}
	user.mu.Unlock()
	for _, plan := range plans {
		c.runClosePlan(plan)
	}
}

// finish removes ref after its write pump has exited. Only a closing record is
// eligible, so an accidental late caller cannot remove a still-active socket.
func (c *ConnectionCoordinator) finish(ref ControlConnectionRef) {
	user := c.acquireUser(ref.UserID)
	defer c.releaseUser(ref.UserID, user)
	user.mu.Lock()
	record := user.connections[ref.ControlConnectionID]
	if record != nil && record.ref == ref && record.state == ConnectionClosing {
		c.removeLocked(user, record)
	}
	user.mu.Unlock()
}

// abort removes an opening reservation that never acquired a transport. It
// also removes a revoked opening record, but never removes an active record: a
// caller that accidentally retains a reservation cannot tear down a live
// connection behind its write pump.
func (c *ConnectionCoordinator) abort(ref ControlConnectionRef) {
	user := c.acquireUser(ref.UserID)
	defer c.releaseUser(ref.UserID, user)
	user.mu.Lock()
	record := user.connections[ref.ControlConnectionID]
	if record != nil && record.ref == ref && record.transport == nil {
		c.removeLocked(user, record)
	}
	user.mu.Unlock()
}

// removeLocked deletes a record and releases its WaitGroup slot. Caller must
// hold user.mu and must have established that no read/write goroutine remains.
func (c *ConnectionCoordinator) removeLocked(user *connectionUser, record *connectionRecord) {
	c.releaseAdmissionLocked(user, record)
	delete(user.connections, record.ref.ControlConnectionID)
	user.live.Add(-1)
	c.wg.Done()
}

// reserveAdmission reserves global and source caps while holding admissionMu.
// It also adds the lifecycle WaitGroup slot before StopAdmission can return.
func (c *ConnectionCoordinator) reserveAdmission(sourceIP netip.Addr) error {
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	if !c.accepting {
		return ErrConnectionAdmissionClosed
	}
	if c.admitted >= MaxActiveControlConnections {
		return ErrControlConnectionLimit
	}
	if sourceIP.IsValid() && c.sources[sourceIP] >= MaxControlConnectionsPerSource {
		return ErrSourceConnectionLimit
	}
	c.admitted++
	if sourceIP.IsValid() {
		c.sources[sourceIP]++
	}
	c.wg.Add(1)
	return nil
}

// releaseAdmissionLocked releases a record's global/source counters once. It
// may run during closing or final removal; the admitted flag makes both paths
// idempotent. Caller must hold user.mu.
func (c *ConnectionCoordinator) releaseAdmissionLocked(user *connectionUser, record *connectionRecord) {
	if !record.admitted {
		return
	}
	record.admitted = false
	user.admitted--
	c.admissionMu.Lock()
	c.admitted--
	if record.sourceIP.IsValid() {
		c.sources[record.sourceIP]--
		if c.sources[record.sourceIP] == 0 {
			delete(c.sources, record.sourceIP)
		}
	}
	c.admissionMu.Unlock()
}

// acquireUser returns a stable per-user registry until releaseUser is called.
func (c *ConnectionCoordinator) acquireUser(userID int64) *connectionUser {
	c.indexMu.Lock()
	defer c.indexMu.Unlock()
	user := c.users[userID]
	if user == nil {
		user = &connectionUser{userID: userID, connections: make(map[[16]byte]*connectionRecord)}
		c.users[userID] = user
	}
	user.refs++
	return user
}

// acquireAllUsers retains every current user registry for a process-wide close
// pass. Each returned registry must be paired with releaseUser.
func (c *ConnectionCoordinator) acquireAllUsers() []*connectionUser {
	c.indexMu.Lock()
	defer c.indexMu.Unlock()
	users := make([]*connectionUser, 0, len(c.users))
	for _, user := range c.users {
		user.refs++
		users = append(users, user)
	}
	return users
}

// releaseUser drops a retained registry reference and prunes an empty entry.
func (c *ConnectionCoordinator) releaseUser(userID int64, user *connectionUser) {
	c.indexMu.Lock()
	defer c.indexMu.Unlock()
	user.refs--
	if user.refs == 0 && user.live.Load() == 0 && c.users[userID] == user {
		delete(c.users, userID)
	}
}

// connectionActiveLocked reports whether ref names the currently active record.
// Caller must hold user.mu.
func (u *connectionUser) connectionActiveLocked(ref ControlConnectionRef) bool {
	record := u.connections[ref.ControlConnectionID]
	return record != nil && record.ref == ref && record.state == ConnectionActive
}

// sameVoiceAuthority compares the complete authority tuple. Nil represents no
// authority and only matches nil, which lets stages distinguish first join from
// a replacement that raced a new binding.
func sameVoiceAuthority(left, right *VoiceAuthority) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

// cloneVoiceAuthority copies an optional authority so an unpublished stage
// cannot retain a pointer into a mutable coordinator user record.
func cloneVoiceAuthority(authority *VoiceAuthority) *VoiceAuthority {
	if authority == nil {
		return nil
	}
	copy := *authority
	return &copy
}

// validConnectionRef rejects zero fields before an operation can reach a user
// registry and accidentally create a permanent empty entry.
func validConnectionRef(ref ControlConnectionRef) bool {
	return ref.UserID > 0 && ref.Generation > 0 && ref.LoginSessionID > 0 && ref.ControlConnectionID != [16]byte{}
}

// randomControlConnectionID returns a cryptographically random 128-bit ID.
func randomControlConnectionID() ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	return id, nil
}
