// Package snowflake implements a lock-free, 63-bit snowflake-style ID
// generator for a single process.
//
// The leading bit is always 0, so IDs are positive int64 values that fit
// natively into SQLite's INTEGER PRIMARY KEY.
//
// Memory layout (bit 63 is the MSB):
//
//	63    62                                                20 19               0
//	+-----+---------------------------------------------------+-----------------+
//	|  0  |         43-bit timestamp (ms since epoch)         | 20-bit sequence |
//	+-----+---------------------------------------------------+-----------------+
package snowflake

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

const (
	timestampBits = 43
	sequenceBits  = 20

	sequenceMask = int64(1<<sequenceBits) - 1
	maxSequence  = sequenceMask
	maxTimestamp = int64(1<<timestampBits) - 1
)

var (
	// ErrClockBeforeEpoch is returned when the clock is before the configured epoch.
	ErrClockBeforeEpoch = errors.New("snowflake: clock is before epoch")
	// ErrTimestampOverflow is returned when the timestamp no longer fits in 43 bits.
	ErrTimestampOverflow = errors.New("snowflake: timestamp overflow")
)

// DefaultEpoch is the default timestamp base used by New: 2026-08-10T00:00:00Z.
var DefaultEpoch = time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)

// IDGenerator produces unique, strictly increasing IDs without locking.
// A single 64-bit state word packs the last timestamp (43 bits) and the
// current sequence (20 bits); every ID is claimed with one CompareAndSwap.
type IDGenerator struct {
	state atomic.Int64

	epoch int64               // epoch in Unix milliseconds
	now   func() int64        // current time in Unix milliseconds
	sleep func(time.Duration) // waiting strategy
}

// Option configures an IDGenerator.
type Option func(*IDGenerator)

// WithEpoch sets the custom epoch used as the timestamp base.
// The default is 2026-08-10T00:00:00Z, which keeps IDs valid until ~2305.
func WithEpoch(epoch time.Time) Option {
	return func(g *IDGenerator) { g.epoch = epoch.UnixMilli() }
}

// WithClock overrides the time source. Used by tests to simulate clock skew.
func WithClock(now func() int64) Option {
	return func(g *IDGenerator) { g.now = now }
}

// WithSleep overrides the waiting strategy used when the generator must wait
// for the next millisecond. Used by tests with a fake clock.
func WithSleep(sleep func(time.Duration)) Option {
	return func(g *IDGenerator) { g.sleep = sleep }
}

// New returns an IDGenerator with the given options applied.
func New(opts ...Option) (*IDGenerator, error) {
	g := &IDGenerator{
		epoch: DefaultEpoch.UnixMilli(),
		now:   func() int64 { return time.Now().UnixMilli() },
		sleep: time.Sleep,
	}
	for _, opt := range opts {
		opt(g)
	}
	if g.now == nil || g.sleep == nil {
		return nil, errors.New("snowflake: clock and sleep functions must not be nil")
	}
	return g, nil
}

// Next returns the next ID.
//
// The generator is safe for concurrent use: one goroutine wins the CAS on the
// shared state word, so no mutex is required and IDs remain globally unique
// and strictly increasing within the process.
//
// If the clock moves backwards, Next waits until it catches up to preserve
// monotonicity instead of emitting a duplicate timestamp.
func (g *IDGenerator) Next() (int64, error) {
	for {
		old := g.state.Load()
		ts := old >> sequenceBits // timestamp (ms since epoch) of the last ID
		seq := old & sequenceMask

		rel := g.now() - g.epoch
		switch {
		case rel < 0:
			return 0, fmt.Errorf("%w: now=%d epoch=%d", ErrClockBeforeEpoch, g.now(), g.epoch)
		case rel > maxTimestamp:
			return 0, fmt.Errorf("%w: %d ms since epoch", ErrTimestampOverflow, rel)
		case rel < ts:
			// Clock moved backwards; wait until it catches up.
			g.sleep(time.Duration(ts-rel) * time.Millisecond)
			continue
		case rel > ts:
			// New millisecond: reset the sequence and claim the first slot.
			next := rel << sequenceBits
			if g.state.CompareAndSwap(old, next) {
				return next, nil
			}
			continue
		}

		if seq >= maxSequence {
			// Sequence exhausted for this millisecond; wait for the next one.
			g.sleep(time.Millisecond)
			continue
		}
		next := old + 1
		if g.state.CompareAndSwap(old, next) {
			return next, nil
		}
	}
}

// TimestampMS returns the millisecond timestamp (since the generator's epoch)
// encoded in an ID. Useful for debugging and tests.
func TimestampMS(id int64) int64 {
	return id >> sequenceBits
}
