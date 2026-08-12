// Package presence tracks whether a user is currently active, based on
// client heartbeats. It is a display-level signal only: it never extends
// sessions, never authorizes anything, and resets on restart.
package presence

import (
	"errors"
	"time"

	"zephyr.vox/server/ce/internal/cache"
)

// Real status values accepted by Heartbeat. These describe the client's
// actual state; a future "invisible" mode would only change what others see
// (a presentation concern), never what this layer records.
const (
	RealStatusOnline = "online"
	RealStatusAway   = "away"
)

// HeartbeatTTL is how long one heartbeat keeps the user visible as online.
// Clients should heartbeat roughly every HeartbeatTTL/2 so one lost beat
// does not flap the status. It is intentionally a constant: the tradeoff is
// stable, and a config knob would just be noise nobody changes.
const HeartbeatTTL = 90 * time.Second

// ErrInvalidStatus is returned when Heartbeat receives an unknown status.
// The service is the single source of truth for the allowed values.
var ErrInvalidStatus = errors.New("presence: invalid status")

// State is the per-user presence snapshot returned by Query.
type State struct {
	RealStatus string `json:"status"`
	LastSeen   int64  `json:"last_seen"` // Unix milliseconds
}

// Presence is an in-memory online/away registry. A user is online when their
// last heartbeat is younger than HeartbeatTTL; expired entries are removed
// lazily on the next access, so the registry owns no background goroutines.
// It is safe for concurrent use.
type Presence struct {
	c   *cache.Cache[int64, State]
	now func() time.Time
}

// New returns an empty Presence. The now function is injectable for
// deterministic tests; production callers pass time.Now.
func New(now func() time.Time) *Presence {
	return &Presence{
		c: cache.New[int64, State](
			cache.WithTTL[int64, State](HeartbeatTTL),
			cache.WithClock[int64, State](now),
		),
		now: now,
	}
}

// Heartbeat records a fresh heartbeat for userID and slides the online
// window forward to now + HeartbeatTTL.
func (p *Presence) Heartbeat(userID int64, status string) error {
	if status != RealStatusOnline && status != RealStatusAway {
		return ErrInvalidStatus
	}
	p.c.Set(userID, State{RealStatus: status, LastSeen: p.now().UnixMilli()})
	return nil
}

// Online returns the current state of every user with a fresh heartbeat.
// Users without one are simply absent; clients treat absence as offline.
// Expired entries are purged as a side effect.
func (p *Presence) Online() map[int64]State {
	return p.c.Snapshot()
}
