package protocol_test

import (
	"net/netip"
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
