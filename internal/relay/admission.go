package relay

import (
	"sync"
	"time"

	"zephyr.vox/server/ce/internal/protocol"
)

// softAdmission applies one global and bounded per-session token bucket before
// relay queue admission. Buckets are short-lived and capped so session churn
// cannot become a memory-growth vector.
type softAdmission struct {
	mu          sync.Mutex
	global      *protocol.TokenBucket
	sessions    map[[16]byte]*sessionBucket
	globalRate  int
	sessionRate int
	now         func() time.Time
}

type sessionBucket struct {
	bucket   *protocol.TokenBucket
	lastSeen time.Time
}

// newSoftAdmission creates a full global/session soft limiter.
func newSoftAdmission(globalRate, sessionRate int, now func() time.Time) *softAdmission {
	return &softAdmission{
		global:      protocol.NewTokenBucket(float64(globalRate), globalRate*2, now),
		sessions:    make(map[[16]byte]*sessionBucket, MaxTrackedSessions),
		globalRate:  globalRate,
		sessionRate: sessionRate,
		now:         now,
	}
}

// set changes both soft rates while retaining token state.
func (a *softAdmission) set(limits SoftLimits) {
	if a == nil {
		return
	}
	globalRate, sessionRate := limits.GlobalPacketsPerSec, limits.SessionPacketsPerSec
	if globalRate < 1 {
		globalRate = 1
	}
	if sessionRate < 1 {
		sessionRate = 1
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.globalRate = globalRate
	a.sessionRate = sessionRate
	a.global.SetRate(float64(globalRate), globalRate*2)
	now := a.now()
	for id, session := range a.sessions {
		if now.Sub(session.lastSeen) > 2*time.Minute {
			delete(a.sessions, id)
			continue
		}
		session.bucket.SetRate(float64(sessionRate), sessionRate*2)
	}
}

// allow consumes one global and one session token, rolling back the global
// token only by omission because token buckets intentionally have no refund;
// this conservative policy makes overload protection fail closed.
func (a *softAdmission) allow(sessionID [16]byte, now time.Time) bool {
	if a == nil || sessionID == [16]byte{} {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.global.TakeAt(now) {
		return false
	}
	session := a.sessions[sessionID]
	if session == nil {
		if len(a.sessions) >= MaxTrackedSessions {
			a.sweepLocked(now)
			if len(a.sessions) >= MaxTrackedSessions {
				return false
			}
		}
		rate := a.sessionRate
		session = &sessionBucket{bucket: protocol.NewTokenBucket(float64(rate), rate*2, a.now)}
		a.sessions[sessionID] = session
	}
	session.lastSeen = now
	return session.bucket.TakeAt(now)
}

// sweepLocked removes idle buckets after the fixed session retention window.
func (a *softAdmission) sweepLocked(now time.Time) {
	for id, session := range a.sessions {
		if now.Sub(session.lastSeen) > 2*time.Minute {
			delete(a.sessions, id)
		}
	}
}
