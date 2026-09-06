package relay

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// LoadTickInterval is the controller sampling cadence.
	LoadTickInterval = time.Second
	// LoadRecoveryTicks is the number of clean samples before recovery begins.
	LoadRecoveryTicks = 30
)

// HardLimits are immutable protocol caps. LoadController may lower its soft
// output but never raises it above these values.
type HardLimits struct {
	GlobalPacketsPerSec  int `json:"global_packets_per_sec"`
	SessionPacketsPerSec int `json:"session_packets_per_sec"`
}

// SoftLimits are the current elastic limits and telemetry cadence.
type SoftLimits struct {
	GlobalPacketsPerSec  int           `json:"global_packets_per_sec"`
	SessionPacketsPerSec int           `json:"session_packets_per_sec"`
	VoiceStatsInterval   time.Duration `json:"-"`
}

// LoadInput contains one short-window pressure sample.
type LoadInput struct {
	QueueUtilization    float64
	RelayDropRatio      float64
	UDPDropRatio        float64
	UDPGlobalDropRatio  float64
	UDPSourceDropRatio  float64
	UDPSessionDropRatio float64
	RelayP95Latency     time.Duration
	StatePublicationLag time.Duration
}

// LoadSnapshot is the metrics-safe current controller state.
type LoadSnapshot struct {
	Hard          HardLimits `json:"hard"`
	Soft          SoftLimits `json:"soft"`
	Overloaded    bool       `json:"overloaded"`
	RecoveryTicks int        `json:"recovery_ticks"`
	LastInput     LoadInput  `json:"last_input"`
}

// LoadController lowers voice soft limits quickly during pressure and recovers
// them slowly after thirty clean ticks. The state pointer is atomic for the
// relay hot path; the mutex protects controller history and observer calls.
type LoadController struct {
	hard HardLimits
	now  func() time.Time

	current atomic.Pointer[SoftLimits]

	mu            sync.Mutex
	overloaded    bool
	recoveryTicks int
	cleanTicks    int
	lastInput     LoadInput
	onUpdate      func(SoftLimits)
}

// NewLoadController creates a controller at hard soft limits and a five-second
// diagnostics cadence.
func NewLoadController(hard HardLimits, now func() time.Time) (*LoadController, error) {
	if hard.GlobalPacketsPerSec <= 0 || hard.SessionPacketsPerSec <= 0 {
		return nil, errors.New("relay: invalid load hard limits")
	}
	if now == nil {
		now = time.Now
	}
	c := &LoadController{hard: hard, now: now}
	initial := SoftLimits{GlobalPacketsPerSec: hard.GlobalPacketsPerSec, SessionPacketsPerSec: hard.SessionPacketsPerSec, VoiceStatsInterval: 5 * time.Second}
	c.current.Store(&initial)
	return c, nil
}

// SetUpdateFunc installs a non-blocking callback invoked synchronously after
// each controller tick. The callback runs while the controller's internal
// state lock is held, so it must not call Snapshot, Current, Tick, or perform
// I/O; it is intended only to publish the new relay admission rates.
func (c *LoadController) SetUpdateFunc(update func(SoftLimits)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.onUpdate = update
	c.mu.Unlock()
}

// Current returns the immutable current soft limit copy.
func (c *LoadController) Current() SoftLimits {
	if c == nil {
		return SoftLimits{}
	}
	limits := c.current.Load()
	if limits == nil {
		return SoftLimits{}
	}
	return *limits
}

// Snapshot returns the current controller state and latest pressure sample.
func (c *LoadController) Snapshot() LoadSnapshot {
	if c == nil {
		return LoadSnapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return LoadSnapshot{Hard: c.hard, Soft: c.Current(), Overloaded: c.overloaded, RecoveryTicks: c.recoveryTicks, LastInput: c.lastInput}
}

// Tick applies one pressure sample and returns the new soft limits. Overload
// steps down immediately; clean samples first need a thirty-tick recovery
// window and then increase rates in small increments.
func (c *LoadController) Tick(input LoadInput) SoftLimits {
	if c == nil {
		return SoftLimits{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastInput = input
	current := c.Current()
	if pressureHigh(input) {
		c.overloaded = true
		c.cleanTicks = 0
		c.recoveryTicks = 0
		globalFloor := maxInt(1, int(math.Floor(float64(c.hard.GlobalPacketsPerSec)*0.25)))
		sessionFloor := maxInt(1, minInt(c.hard.SessionPacketsPerSec, 50))
		current = SoftLimits{
			GlobalPacketsPerSec:  maxInt(globalFloor, int(math.Floor(float64(current.GlobalPacketsPerSec)*0.80))),
			SessionPacketsPerSec: maxInt(sessionFloor, int(math.Floor(float64(current.SessionPacketsPerSec)*0.80))),
			VoiceStatsInterval:   nextStatsInterval(current.VoiceStatsInterval, true),
		}
	} else {
		c.cleanTicks++
		if c.overloaded {
			if c.cleanTicks >= LoadRecoveryTicks {
				c.recoveryTicks++
				if c.recoveryTicks%10 == 0 {
					current.GlobalPacketsPerSec = minInt(c.hard.GlobalPacketsPerSec, current.GlobalPacketsPerSec+maxInt(1, int(math.Floor(float64(c.hard.GlobalPacketsPerSec)*0.05))))
					current.SessionPacketsPerSec = minInt(c.hard.SessionPacketsPerSec, current.SessionPacketsPerSec+maxInt(1, int(math.Floor(float64(c.hard.SessionPacketsPerSec)*0.05))))
					current.VoiceStatsInterval = nextStatsInterval(current.VoiceStatsInterval, false)
				}
			}
			if current.GlobalPacketsPerSec >= c.hard.GlobalPacketsPerSec && current.SessionPacketsPerSec >= c.hard.SessionPacketsPerSec && current.VoiceStatsInterval <= 5*time.Second {
				c.overloaded = false
				c.recoveryTicks = 0
			}
		}
	}
	current.GlobalPacketsPerSec = minInt(c.hard.GlobalPacketsPerSec, maxInt(1, current.GlobalPacketsPerSec))
	current.SessionPacketsPerSec = minInt(c.hard.SessionPacketsPerSec, maxInt(1, current.SessionPacketsPerSec))
	c.current.Store(&current)
	if c.onUpdate != nil {
		c.onUpdate(current)
	}
	return current
}

// Run samples input once per second until ctx is canceled.
func (c *LoadController) Run(ctx context.Context, sample func() LoadInput) error {
	if c == nil || ctx == nil || sample == nil {
		return errors.New("relay: invalid load controller runtime")
	}
	ticker := time.NewTicker(LoadTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.Tick(sample())
		case <-ctx.Done():
			return nil
		}
	}
}

// pressureHigh returns true when any controller overload condition is outside
// its healthy range. UDP hard-drop ratios remain sampled for observability but
// do not independently lower the application soft relay limits.
func pressureHigh(input LoadInput) bool {
	return input.QueueUtilization >= 0.75 || input.RelayDropRatio >= 0.05 || input.RelayP95Latency >= 100*time.Millisecond || input.StatePublicationLag >= 250*time.Millisecond
}

// nextStatsInterval moves diagnostics cadence toward slower telemetry during
// overload and toward fresher telemetry during recovery.
func nextStatsInterval(current time.Duration, overloaded bool) time.Duration {
	if current <= 0 {
		current = 5 * time.Second
	}
	if overloaded {
		switch {
		case current < 10*time.Second:
			return 10 * time.Second
		case current < 20*time.Second:
			return 20 * time.Second
		default:
			return 30 * time.Second
		}
	}
	switch {
	case current >= 30*time.Second:
		return 20 * time.Second
	case current >= 20*time.Second:
		return 10 * time.Second
	case current >= 10*time.Second:
		return 5 * time.Second
	default:
		return 5 * time.Second
	}
}

// maxInt returns the larger integer.
func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

// minInt returns the smaller integer.
func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
