package realtime

import (
	"net/netip"
	"sync"
	"time"
)

const (
	upgradeTokensPerSecond = 10.0
	upgradeBurst           = 20.0
	upgradeSourceTTL       = 2 * time.Minute
	upgradeSourceLimit     = 4096
)

// UpgradeLimiter bounds WebSocket handshake attempts before token parsing and
// authentication work. It is independent of the active connection cap: a
// source that repeatedly fails handshakes cannot consume CPU by cycling its
// reservations, and idle source entries are pruned on later attempts.
type UpgradeLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	sources map[netip.Addr]*upgradeSource
}

type upgradeSource struct {
	tokens float64
	last   time.Time
}

// NewUpgradeLimiter constructs an empty per-source upgrade limiter. The clock
// is injectable for deterministic tests; nil uses wall clock time.
func NewUpgradeLimiter(now func() time.Time) *UpgradeLimiter {
	if now == nil {
		now = time.Now
	}
	return &UpgradeLimiter{now: now, sources: make(map[netip.Addr]*upgradeSource)}
}

// Allow consumes one source-IP handshake token. Invalid addresses and a full
// source table are denied because they cannot be bounded safely.
func (l *UpgradeLimiter) Allow(sourceIP netip.Addr) bool {
	if l == nil || !sourceIP.IsValid() {
		return false
	}
	sourceIP = sourceIP.Unmap()
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	source := l.sources[sourceIP]
	if source == nil {
		if len(l.sources) >= upgradeSourceLimit {
			return false
		}
		source = &upgradeSource{tokens: upgradeBurst, last: now}
		l.sources[sourceIP] = source
	}
	elapsed := now.Sub(source.last).Seconds()
	if elapsed > 0 {
		source.tokens = min(upgradeBurst, source.tokens+elapsed*upgradeTokensPerSecond)
		source.last = now
	}
	if source.tokens < 1 {
		return false
	}
	source.tokens--
	return true
}

// Len returns the number of source entries retained by the limiter.
func (l *UpgradeLimiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sources)
}

// pruneLocked discards idle source budgets before a new source can allocate a
// table entry. Caller must hold l.mu.
func (l *UpgradeLimiter) pruneLocked(now time.Time) {
	for sourceIP, source := range l.sources {
		if now.Sub(source.last) >= upgradeSourceTTL {
			delete(l.sources, sourceIP)
		}
	}
}
