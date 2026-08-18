package protocol_test

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/protocol"
)

func TestIngressLimiterBoundsSourcesAndSweepsExpiredEntries(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	limits := protocol.IngressLimits{
		GlobalPacketsPerSec: 100,
		GlobalBurst:         100,
		SourcePacketsPerSec: 100,
		SourceBurst:         100,
		SourceEntryLimit:    2,
		SourceEntryTTL:      time.Minute,
	}
	limiter, err := protocol.NewIngressLimiter(limits, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	c := netip.MustParseAddr("192.0.2.3")
	if got := limiter.Allow(a, clock.Now()); got != protocol.IngressAllowed {
		t.Fatalf("first source = %d, want allowed", got)
	}
	if got := limiter.Allow(b, clock.Now()); got != protocol.IngressAllowed {
		t.Fatalf("second source = %d, want allowed", got)
	}
	if got := limiter.Allow(c, clock.Now()); got != protocol.IngressDroppedTableFull {
		t.Fatalf("third source = %d, want table full", got)
	}
	clock.Advance(time.Minute)
	if got := limiter.Allow(c, clock.Now()); got != protocol.IngressAllowed {
		t.Fatalf("source after implicit sweep = %d, want allowed", got)
	}
	if limiter.Len() != 1 {
		t.Fatalf("source entries after implicit sweep = %d, want 1", limiter.Len())
	}
}

func TestIngressLimiterNormalizesIPv4MappedAddresses(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	limiter, err := protocol.NewIngressLimiter(protocol.IngressLimits{
		GlobalPacketsPerSec: 10,
		GlobalBurst:         10,
		SourcePacketsPerSec: 10,
		SourceBurst:         10,
		SourceEntryLimit:    2,
		SourceEntryTTL:      time.Minute,
	}, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if got := limiter.Allow(netip.MustParseAddr("192.0.2.1"), clock.Now()); got != protocol.IngressAllowed {
		t.Fatalf("IPv4 Allow = %d", got)
	}
	if got := limiter.Allow(netip.MustParseAddr("::ffff:192.0.2.1"), clock.Now()); got != protocol.IngressAllowed {
		t.Fatalf("mapped IPv6 Allow = %d", got)
	}
	if limiter.Len() != 1 {
		t.Fatalf("source entries = %d, want 1", limiter.Len())
	}
}

func TestIngressLimiterGlobalAndSourceDrops(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	global, err := protocol.NewIngressLimiter(protocol.IngressLimits{
		GlobalPacketsPerSec: 1, GlobalBurst: 1, SourcePacketsPerSec: 10, SourceBurst: 10, SourceEntryLimit: 4, SourceEntryTTL: time.Minute,
	}, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if global.Allow(netip.MustParseAddr("192.0.2.1"), clock.Now()) != protocol.IngressAllowed || global.Allow(netip.MustParseAddr("192.0.2.2"), clock.Now()) != protocol.IngressDroppedGlobal {
		t.Fatal("global ingress limit did not classify the second source")
	}
	source, err := protocol.NewIngressLimiter(protocol.IngressLimits{
		GlobalPacketsPerSec: 10, GlobalBurst: 10, SourcePacketsPerSec: 1, SourceBurst: 1, SourceEntryLimit: 4, SourceEntryTTL: time.Minute,
	}, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("192.0.2.1")
	if source.Allow(addr, clock.Now()) != protocol.IngressAllowed || source.Allow(addr, clock.Now()) != protocol.IngressDroppedSource {
		t.Fatal("source ingress limit did not classify the second packet")
	}
}

func TestIngressLimiterConcurrentAllowSweepAndLen(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	limiter, err := protocol.NewIngressLimiter(protocol.IngressLimits{
		GlobalPacketsPerSec: 10000, GlobalBurst: 10000, SourcePacketsPerSec: 10000, SourceBurst: 10000, SourceEntryLimit: 32, SourceEntryTTL: time.Second,
	}, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for round := range 100 {
				addr := netip.AddrFrom4([4]byte{192, 0, 2, byte((worker+round)%32 + 1)})
				_ = limiter.Allow(addr, clock.Now())
				if round%8 == 0 {
					_ = limiter.Sweep(clock.Now())
				}
				_ = limiter.Len()
			}
		})
	}
	wg.Wait()
	if limiter.Len() > 32 {
		t.Fatalf("source entries = %d, want <= 32", limiter.Len())
	}
}

func TestNewIngressLimiterRejectsEveryNonPositiveLimit(t *testing.T) {
	base := protocol.DefaultIngressLimits()
	cases := []struct {
		name string
		set  func(*protocol.IngressLimits)
	}{
		{"global_rate", func(l *protocol.IngressLimits) { l.GlobalPacketsPerSec = 0 }},
		{"global_burst", func(l *protocol.IngressLimits) { l.GlobalBurst = 0 }},
		{"source_rate", func(l *protocol.IngressLimits) { l.SourcePacketsPerSec = 0 }},
		{"source_burst", func(l *protocol.IngressLimits) { l.SourceBurst = 0 }},
		{"source_limit", func(l *protocol.IngressLimits) { l.SourceEntryLimit = 0 }},
		{"source_ttl", func(l *protocol.IngressLimits) { l.SourceEntryTTL = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limits := base
			tc.set(&limits)
			if _, err := protocol.NewIngressLimiter(limits, time.Now); err == nil {
				t.Fatal("non-positive ingress limit accepted")
			}
		})
	}
}

func TestIngressLimiterExplicitSweep(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	limits := protocol.DefaultIngressLimits()
	limits.SourceEntryTTL = time.Minute
	limiter, err := protocol.NewIngressLimiter(limits, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"192.0.2.1", "192.0.2.2"} {
		if got := limiter.Allow(netip.MustParseAddr(raw), clock.Now()); got != protocol.IngressAllowed {
			t.Fatalf("Allow(%s) = %d", raw, got)
		}
	}
	clock.Advance(time.Minute)
	if removed := limiter.Sweep(clock.Now()); removed != 2 {
		t.Fatalf("Sweep removed = %d, want 2", removed)
	}
	if limiter.Len() != 0 {
		t.Fatalf("Len after Sweep = %d, want 0", limiter.Len())
	}
}
