package protocol

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

const (
	defaultGlobalIngressPacketsPerSec = 20_000
	defaultGlobalIngressBurst         = 40_000
	defaultSourcePacketsPerSec        = 1_200
	defaultSourceBurst                = 2_400
	defaultSourceEntryLimit           = 4_096
	defaultSourceEntryTTL             = 2 * time.Minute
)

// IngressLimits bounds unauthenticated UDP work before a datagram can select
// a session or trigger AEAD authentication.
type IngressLimits struct {
	GlobalPacketsPerSec int
	GlobalBurst         int
	SourcePacketsPerSec int
	SourceBurst         int
	SourceEntryLimit    int
	SourceEntryTTL      time.Duration
}

// DefaultIngressLimits returns the fixed hard limits for unauthenticated UDP
// ingress. Application configuration may lower or override these values.
func DefaultIngressLimits() IngressLimits {
	return IngressLimits{
		GlobalPacketsPerSec: defaultGlobalIngressPacketsPerSec,
		GlobalBurst:         defaultGlobalIngressBurst,
		SourcePacketsPerSec: defaultSourcePacketsPerSec,
		SourceBurst:         defaultSourceBurst,
		SourceEntryLimit:    defaultSourceEntryLimit,
		SourceEntryTTL:      defaultSourceEntryTTL,
	}
}

// IngressDecision describes whether an unauthenticated datagram passed the
// global and source-address admission budgets.
type IngressDecision uint8

const (
	IngressAllowed IngressDecision = iota
	IngressDroppedGlobal
	IngressDroppedSource
	IngressDroppedTableFull
)

type sourceIngress struct {
	budget   *TokenBucket
	lastSeen time.Time
}

// IngressLimiter bounds unauthenticated UDP work. Its mutex protects source
// table membership and last-seen timestamps; bucket methods take their own
// mutex only while l.mu is held, fixing the lock order as ingress then bucket.
type IngressLimiter struct {
	mu      sync.Mutex
	limits  IngressLimits
	global  *TokenBucket
	sources map[netip.Addr]*sourceIngress
	now     func() time.Time
}

// NewIngressLimiter builds an ingress limiter with positive hard limits.
func NewIngressLimiter(limits IngressLimits, now func() time.Time) (*IngressLimiter, error) {
	if limits.GlobalPacketsPerSec <= 0 || limits.GlobalBurst <= 0 || limits.SourcePacketsPerSec <= 0 || limits.SourceBurst <= 0 || limits.SourceEntryLimit <= 0 || limits.SourceEntryTTL <= 0 {
		return nil, errors.New("protocol: ingress limits must be positive")
	}
	if now == nil {
		now = time.Now
	}
	return &IngressLimiter{
		limits:  limits,
		global:  NewTokenBucket(float64(limits.GlobalPacketsPerSec), limits.GlobalBurst, now),
		sources: make(map[netip.Addr]*sourceIngress),
		now:     now,
	}, nil
}

// Allow consumes global then normalized-source budget for addr. Unknown
// sources are refused when the bounded source table is full.
func (l *IngressLimiter) Allow(addr netip.Addr, now time.Time) IngressDecision {
	addr = addr.Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.global.TakeAt(now) {
		return IngressDroppedGlobal
	}
	source := l.sources[addr]
	if source == nil {
		if len(l.sources) >= l.limits.SourceEntryLimit {
			l.sweepLocked(now)
			if len(l.sources) >= l.limits.SourceEntryLimit {
				return IngressDroppedTableFull
			}
		}
		source = &sourceIngress{budget: NewTokenBucket(float64(l.limits.SourcePacketsPerSec), l.limits.SourceBurst, l.now)}
		l.sources[addr] = source
	}
	source.lastSeen = now
	if !source.budget.TakeAt(now) {
		return IngressDroppedSource
	}
	return IngressAllowed
}

// Sweep removes source entries that have been idle for at least SourceEntryTTL.
func (l *IngressLimiter) Sweep(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sweepLocked(now)
}

// sweepLocked removes idle source entries while l.mu is held.
func (l *IngressLimiter) sweepLocked(now time.Time) int {
	removed := 0
	for addr, source := range l.sources {
		if now.Sub(source.lastSeen) >= l.limits.SourceEntryTTL {
			delete(l.sources, addr)
			removed++
		}
	}
	return removed
}

// Len returns the number of tracked source-address budgets.
func (l *IngressLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sources)
}
