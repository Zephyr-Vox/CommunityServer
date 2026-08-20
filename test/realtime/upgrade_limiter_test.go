package realtime_test

import (
	"net/netip"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/realtime"
)

func TestUpgradeLimiterBoundsAndRefillsOneSource(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := realtime.NewUpgradeLimiter(func() time.Time { return now })
	sourceIP := netip.MustParseAddr("192.0.2.1")
	for i := 0; i < 20; i++ {
		if !limiter.Allow(sourceIP) {
			t.Fatalf("initial upgrade %d denied", i)
		}
	}
	if limiter.Allow(sourceIP) {
		t.Fatal("burst-exhausted source must be denied")
	}
	now = now.Add(100 * time.Millisecond)
	if !limiter.Allow(sourceIP) {
		t.Fatal("one refilled token must permit one upgrade")
	}
	if limiter.Allow(netip.Addr{}) {
		t.Fatal("invalid source address must be denied")
	}
}
