package realtime

import (
	"sort"
	"sync"
)

const voiceRelayGateCount = 4096

// voiceRelayGateSet is a fixed collision-tolerant lock table. Collisions only
// serialize unrelated users; the fixed footprint is more important than an
// attacker-controlled map of user IDs on the media hot path.
type voiceRelayGateSet struct {
	gates [voiceRelayGateCount]sync.Mutex
}

// newVoiceRelayGateSet creates the fixed source-gate table.
func newVoiceRelayGateSet() *voiceRelayGateSet {
	return &voiceRelayGateSet{}
}

// acquire locks the source gate selected by userID and returns an idempotent
// release function for mutation or relay worker critical sections.
func (g *voiceRelayGateSet) acquire(userID int64) func() {
	if g == nil || userID <= 0 {
		return func() {}
	}
	index := uint64(userID) % voiceRelayGateCount
	gate := &g.gates[index]
	gate.Lock()
	var once sync.Once
	return func() { once.Do(gate.Unlock) }
}

// acquireMany locks every distinct gate slot selected by userIDs in ascending
// order. A fixed order prevents two multi-user state mutations from deadlocking
// when their user IDs hash to overlapping relay-gate slots.
func (g *voiceRelayGateSet) acquireMany(userIDs []int64) func() {
	if g == nil || len(userIDs) == 0 {
		return func() {}
	}
	indices := make([]int, 0, len(userIDs))
	seen := make(map[int]struct{}, len(userIDs))
	for _, userID := range userIDs {
		if userID <= 0 {
			continue
		}
		index := int(uint64(userID) % voiceRelayGateCount)
		if _, ok := seen[index]; ok {
			continue
		}
		seen[index] = struct{}{}
		indices = append(indices, index)
	}
	if len(indices) == 0 {
		return func() {}
	}
	sort.Ints(indices)
	for _, index := range indices {
		g.gates[index].Lock()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for index := len(indices) - 1; index >= 0; index-- {
				g.gates[indices[index]].Unlock()
			}
		})
	}
}

// AcquireVoiceRelayGate serializes one user's relay validation/fanout with
// voice authority and mute mutations. Callers must release the returned
// function promptly and must not hold it across network setup or HTTP I/O.
func (c *ConnectionCoordinator) AcquireVoiceRelayGate(userID int64) func() {
	if c == nil {
		return func() {}
	}
	return c.voiceRelayGates.acquire(userID)
}

// AcquireVoiceRelayGates serializes a multi-user state mutation with relay
// workers. Gate slots are deduplicated and acquired in a stable order; callers
// must release the returned function after StatePublication has completed.
func (c *ConnectionCoordinator) AcquireVoiceRelayGates(userIDs []int64) func() {
	if c == nil {
		return func() {}
	}
	return c.voiceRelayGates.acquireMany(userIDs)
}

// AcquireCurrentVoiceRelayGates snapshots all current voice authorities and
// locks their relay gates in a stable order. Channel, ACL, role, and config
// mutations use this before publication because their candidate may revoke any
// authority visible in the current immutable projection.
func (c *ConnectionCoordinator) AcquireCurrentVoiceRelayGates() func() {
	if c == nil {
		return func() {}
	}
	authorities := c.VoiceAuthorities()
	userIDs := make([]int64, 0, len(authorities))
	for _, authority := range authorities {
		userIDs = append(userIDs, authority.UserID)
	}
	return c.AcquireVoiceRelayGates(userIDs)
}

// VoiceStatsTransport accepts a latest-only telemetry frame. Implementations
// must copy or consume the frame before returning and must never block the
// caller; false means the connection is closed or its telemetry slot is full.
type VoiceStatsTransport interface {
	EnqueueVoiceStats(frame []byte) bool
}

// PublishVoiceStats sends one already-encoded, user-scoped telemetry frame to
// every active control connection of the user's current voice session. The
// coordinator rechecks the exact session before delivery so an old diagnostics
// sample cannot reach a replacement session.
func (c *ConnectionCoordinator) PublishVoiceStats(userID int64, sessionID [16]byte, frame []byte) int {
	if c == nil || userID <= 0 || sessionID == [16]byte{} || len(frame) == 0 {
		return 0
	}
	// Serialize the exact-session check and latest-only enqueue with join,
	// leave, replacement, mute, and access-loss mutations. The enqueue itself
	// is non-blocking, so holding this gate does not wait on socket I/O.
	releaseRelay := c.AcquireVoiceRelayGate(userID)
	defer releaseRelay()
	user := c.acquireUser(userID)
	transports := make([]VoiceStatsTransport, 0)
	user.mu.Lock()
	if user.voice == nil || user.voice.VoiceSessionID != sessionID {
		user.mu.Unlock()
		c.releaseUser(userID, user)
		return 0
	}
	for _, record := range user.connections {
		if record.state != ConnectionActive || record.transport == nil {
			continue
		}
		transport, ok := record.transport.(VoiceStatsTransport)
		if ok {
			transports = append(transports, transport)
		}
	}
	user.mu.Unlock()
	c.releaseUser(userID, user)
	accepted := 0
	for _, transport := range transports {
		if transport.EnqueueVoiceStats(frame) {
			accepted++
		}
	}
	return accepted
}

// VoiceAuthorities returns independent current authority copies ordered by
// user ID. It is used by the diagnostics emitter and never exposes coordinator
// user locks to callers.
func (c *ConnectionCoordinator) VoiceAuthorities() []VoiceAuthority {
	if c == nil {
		return nil
	}
	users := c.acquireAllUsers()
	authorities := make([]VoiceAuthority, 0, len(users))
	for _, user := range users {
		user.mu.Lock()
		if user.voice != nil {
			authorities = append(authorities, *user.voice)
		}
		user.mu.Unlock()
		c.releaseUser(user.userID, user)
	}
	sort.Slice(authorities, func(left, right int) bool { return authorities[left].UserID < authorities[right].UserID })
	return authorities
}

// ActiveConnectionCount returns the current number of active WebSocket control
// connections. It excludes opening reservations and closing sockets so the
// value describes user-visible live control state.
func (c *ConnectionCoordinator) ActiveConnectionCount() int {
	if c == nil {
		return 0
	}
	users := c.acquireAllUsers()
	count := 0
	for _, user := range users {
		user.mu.Lock()
		for _, record := range user.connections {
			if record.state == ConnectionActive {
				count++
			}
		}
		user.mu.Unlock()
		c.releaseUser(user.userID, user)
	}
	return count
}
