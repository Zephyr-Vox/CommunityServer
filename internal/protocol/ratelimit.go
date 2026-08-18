package protocol

import (
	"sync"
	"time"
)

const (
	// SessionPacketsPerSec is the per-session token-bucket refill rate. It is
	// checked before decryption because AEAD has real CPU cost and the check
	// must be cheap enough to reject floods.
	//
	// Packet rate is determined by frame length, not bitrate: worst case
	// mic(10ms) + desktop_audio(10ms) = 200 pps, so 300 leaves 1.5x headroom.
	// Higher bitrates make packets larger, not more numerous.
	SessionPacketsPerSec = 300
	// SessionBurst is the initial token-bucket capacity: two seconds of
	// full-rate traffic.
	SessionBurst = 600
)

// TokenBucket is a concurrency-safe token bucket. The burst starts full so a
// fresh session may immediately send a burst; afterwards capacity refills at
// the configured rate. The clock is injectable for deterministic tests.
type TokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

// NewTokenBucket returns a full token bucket with the given refill rate and
// burst capacity.
func NewTokenBucket(rate float64, burst int, now func() time.Time) *TokenBucket {
	return &TokenBucket{
		rate:   rate,
		burst:  float64(burst),
		tokens: float64(burst),
		last:   now(),
		now:    now,
	}
}

// Take reports whether one token was available and consumes it. Overspeed
// packets are simply dropped by the caller: UDP backpressure is packet loss.
func (b *TokenBucket) Take() bool {
	return b.TakeAt(b.now())
}

// SetRate changes the refill rate and burst capacity at runtime. Existing
// tokens are retained, then clamped to the new burst. Non-positive values are
// clamped to one so a misconfigured controller cannot starve the bucket.
func (b *TokenBucket) SetRate(rate float64, burst int) {
	if rate < 1 {
		rate = 1
	}
	if burst < 1 {
		burst = 1
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.refillLocked(now)
	b.rate = rate
	b.burst = float64(burst)
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
}

// TakeAt consumes one token using an explicit clock sample. The UDP read loop
// samples the manager clock once per datagram so budget, TTL and replay all
// observe the same instant.
func (b *TokenBucket) TakeAt(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked(now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// refillLocked adds elapsed tokens up to burst. Callers must hold b.mu.
func (b *TokenBucket) refillLocked(now time.Time) {
	if now.Before(b.last) || now.Equal(b.last) {
		return
	}
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
}
