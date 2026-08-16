package protocol_test

import (
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/protocol"
)

func TestTokenBucketBurstAndRefill(t *testing.T) {
	now := time.Unix(1000, 0)
	bucket := protocol.NewTokenBucket(10, 3, func() time.Time { return now })

	for i := range 3 {
		if !bucket.Take() {
			t.Fatalf("burst token %d denied", i)
		}
	}
	if bucket.Take() {
		t.Fatal("token allowed beyond burst")
	}

	now = now.Add(100 * time.Millisecond)
	if !bucket.Take() {
		t.Fatal("refilled token denied")
	}
	if bucket.Take() {
		t.Fatal("token allowed before full refill")
	}

	now = now.Add(time.Second)
	if !bucket.Take() {
		t.Fatal("token denied after full refill")
	}
}

func TestTokenBucketClampsAtBurst(t *testing.T) {
	now := time.Unix(1000, 0)
	bucket := protocol.NewTokenBucket(10, 2, func() time.Time { return now })
	bucket.Take()
	now = now.Add(time.Hour)
	if !bucket.Take() {
		t.Fatal("token denied after long idle")
	}
	if !bucket.Take() {
		t.Fatal("second capacity token denied")
	}
	if bucket.Take() {
		t.Fatal("bucket must clamp at burst capacity")
	}
}

func TestTokenBucketConcurrent(t *testing.T) {
	now := time.Unix(1000, 0)
	bucket := protocol.NewTokenBucket(1000, 100, func() time.Time { return now })
	var wg sync.WaitGroup
	allowed := make(chan struct{}, 100)
	for range 20 {
		wg.Go(func() {
			for range 20 {
				if bucket.Take() {
					allowed <- struct{}{}
				}
			}
		})
	}
	wg.Wait()
	if got := len(allowed); got != 100 {
		t.Fatalf("allowed = %d, want exactly burst 100", got)
	}
}

func TestTokenBucketSetRateAdjustsRefill(t *testing.T) {
	now := time.Unix(1000, 0)
	bucket := protocol.NewTokenBucket(1, 1, func() time.Time { return now })
	if !bucket.Take() {
		t.Fatal("initial token denied")
	}
	if bucket.Take() {
		t.Fatal("token allowed beyond initial burst")
	}

	bucket.SetRate(100, 10)
	now = now.Add(10 * time.Millisecond)
	if !bucket.Take() {
		t.Fatal("token denied after rate increase and refill window")
	}
	if bucket.Take() {
		t.Fatal("second token allowed before enough refill")
	}
}

func TestTokenBucketSetRateClampsInvalidValuesAndTokens(t *testing.T) {
	now := time.Unix(1000, 0)
	bucket := protocol.NewTokenBucket(100, 100, func() time.Time { return now })
	bucket.SetRate(0, 0)
	// The clamped rate/burst still allow exactly one token per sample.
	if !bucket.Take() {
		t.Fatal("clamped bucket denied first token")
	}
	if bucket.Take() {
		t.Fatal("clamped bucket allowed token beyond burst one")
	}
	_ = now
}
