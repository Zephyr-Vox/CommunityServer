package relay

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"zephyr.vox/server/ce/internal/protocol"
)

const (
	// MaxTrackedSessions bounds soft per-session admission buckets and prevents
	// attacker-controlled session IDs from creating unbounded relay state.
	MaxTrackedSessions = 4096
	// MaxLatencySamples bounds the rolling latency sample storage used for p95.
	MaxLatencySamples = 4096
	// MaxFanout bounds the number of recipients one admitted voice frame may
	// traverse, matching the v1 voice-channel capacity ceiling.
	MaxFanout = 256
)

var (
	// ErrInvalidRelay reports missing data-plane dependencies or invalid hard
	// limits during construction.
	ErrInvalidRelay = errors.New("relay: invalid relay configuration")
	// ErrRelayAlreadyStarted reports a second Start call.
	ErrRelayAlreadyStarted = errors.New("relay: already started")
	// ErrRelayNotStarted reports Close before Start.
	ErrRelayNotStarted = errors.New("relay: not started")
)

// Source is the immutable authority tuple captured at relay admission. A
// worker compares the entire tuple again before fanout so an old queued frame
// cannot cross a session, connection, or authority-generation replacement.
type Source struct {
	UserID                   int64
	SessionID                [16]byte
	ChannelID                int64
	ControlConnectionID      [16]byte
	ConnectionGeneration     uint64
	VoiceAuthorityGeneration uint64
}

// Valid reports whether Source has the identity fields required by the relay.
func (s Source) Valid() bool {
	return s.UserID > 0 && s.SessionID != [16]byte{} && s.ChannelID > 0 && s.ControlConnectionID != [16]byte{} && s.ConnectionGeneration > 0 && s.VoiceAuthorityGeneration > 0
}

// Recipient is one current UDP session eligible for a channel fanout.
type Recipient struct {
	UserID    int64
	SessionID [16]byte
}

// MembershipSnapshot is an immutable channel membership view supplied by the
// realtime state adapter. Relay workers do not read StateStore directly.
type MembershipSnapshot struct {
	ChannelID int64
	Members   []Recipient
}

// SourceResolver resolves the current coordinator authority for one user.
// Implementations must be short and lock-bounded because it runs on the UDP
// read callback and again in relay workers.
type SourceResolver func(userID int64) (Source, bool)

// MembershipResolver returns the current voice members for one channel. The
// returned slice is owned by the caller and must not be mutated after return.
type MembershipResolver func(channelID int64) MembershipSnapshot

// MuteResolver decides whether the source is muted for a registered media type.
type MuteResolver func(source Source, channelType uint8) bool

// Gate serializes media fanout with a user's voice authority and mute
// publication mutation. Acquire returns a release function and must be called
// exactly once by the caller.
type Gate interface {
	AcquireVoiceRelayGate(userID int64) func()
}

// Sender writes one already validated media payload to a target UDP session.
type Sender interface {
	Send(id [16]byte, channelType uint8, speakerID int64, channelSeq uint16, payload []byte) error
}

// CapabilitiesResolver supplies the protocol channel registry without making
// relay depend on server or HTTP packages.
type CapabilitiesResolver interface {
	Lookup(channelType uint8) (protocol.Capabilities, bool)
}

// Config contains all application adapters needed by Relay. All functions
// are required except Now, which defaults to time.Now.
type Config struct {
	Sender               Sender
	SourceResolver       SourceResolver
	MembershipResolver   MembershipResolver
	MuteResolver         MuteResolver
	Gate                 Gate
	Capabilities         CapabilitiesResolver
	GlobalPacketsPerSec  int
	SessionPacketsPerSec int
	Now                  func() time.Time
}

// Relay is the asynchronous media fanout engine. Handle runs on the UDP read
// goroutine and performs only source validation, soft admission, and bounded
// queue copy; all recipient traversal and UDP writes run on eight workers.
type Relay struct {
	queue *Queue
	cfg   Config
	soft  *softAdmission

	started  atomic.Bool
	startMu  sync.Mutex
	stop     chan struct{}
	stopOnce sync.Once
	done     chan error
	errMu    sync.Mutex
	err      error

	enqueued                      atomic.Uint64
	intervalEnqueued              atomic.Uint64
	droppedOverload               atomic.Uint64
	intervalDroppedOverload       atomic.Uint64
	droppedSoftLimit              atomic.Uint64
	intervalDroppedSoftLimit      atomic.Uint64
	droppedNoAuthority            atomic.Uint64
	intervalDroppedNoAuthority    atomic.Uint64
	droppedStaleAuthority         atomic.Uint64
	intervalDroppedStaleAuthority atomic.Uint64
	droppedMuted                  atomic.Uint64
	intervalDroppedMuted          atomic.Uint64
	droppedNoMembership           atomic.Uint64
	intervalDroppedNoMembership   atomic.Uint64
	droppedInvalidChannel         atomic.Uint64
	intervalDroppedInvalidChannel atomic.Uint64
	sent                          atomic.Uint64
	intervalSent                  atomic.Uint64
	sendErrors                    atomic.Uint64
	intervalSendErrors            atomic.Uint64

	latencyMu sync.Mutex
	latencies []time.Duration
}

// New creates a relay with fixed queue and hard rate limits. Soft limits start
// at the hard values and can later be lowered by LoadController.
func New(cfg Config) (*Relay, error) {
	if cfg.Sender == nil || cfg.SourceResolver == nil || cfg.MembershipResolver == nil || cfg.MuteResolver == nil || cfg.Gate == nil || cfg.Capabilities == nil || cfg.GlobalPacketsPerSec <= 0 || cfg.SessionPacketsPerSec <= 0 {
		return nil, ErrInvalidRelay
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	r := &Relay{
		queue:     NewQueue(),
		cfg:       cfg,
		soft:      newSoftAdmission(cfg.GlobalPacketsPerSec, cfg.SessionPacketsPerSec, cfg.Now),
		stop:      make(chan struct{}),
		done:      make(chan error, 1),
		latencies: make([]time.Duration, 0, MaxLatencySamples),
	}
	return r, nil
}

// Handle validates one protocol frame and enqueues a copy for asynchronous
// fanout. It never blocks on relay workers or performs UDP writes.
func (r *Relay) Handle(frame protocol.InboundFrame) {
	if r == nil || !r.started.Load() || frame.UserID <= 0 || frame.SessionID == [16]byte{} || len(frame.Payload) == 0 {
		return
	}
	source, ok := r.cfg.SourceResolver(frame.UserID)
	if !ok || !source.Valid() || source.SessionID != frame.SessionID {
		r.droppedNoAuthority.Add(1)
		r.intervalDroppedNoAuthority.Add(1)
		return
	}
	caps, ok := r.cfg.Capabilities.Lookup(frame.ChannelType)
	if !ok || caps.MuteKind == "" {
		r.droppedInvalidChannel.Add(1)
		r.intervalDroppedInvalidChannel.Add(1)
		return
	}
	if !r.soft.allow(frame.SessionID, r.cfg.Now()) {
		r.droppedSoftLimit.Add(1)
		r.intervalDroppedSoftLimit.Add(1)
		return
	}
	shard := ShardFor(source.UserID, frame.ChannelType)
	if !r.queue.Enqueue(shard, Frame{Source: source, ChannelType: frame.ChannelType, ChannelSeq: frame.ChannelSeq, TransportSeq: frame.TransportSeq, Payload: frame.Payload}) {
		r.droppedOverload.Add(1)
		r.intervalDroppedOverload.Add(1)
		return
	}
	r.enqueued.Add(1)
	r.intervalEnqueued.Add(1)
}

// Start starts exactly eight worker goroutines and returns a completion channel
// that receives the final worker error once the relay has stopped. It must be
// called before Handle can admit frames.
func (r *Relay) Start(ctx context.Context) (<-chan error, error) {
	if r == nil || ctx == nil {
		return nil, ErrInvalidRelay
	}
	r.startMu.Lock()
	defer r.startMu.Unlock()
	if r.started.Load() {
		return nil, ErrRelayAlreadyStarted
	}
	r.started.Store(true)
	go r.run(ctx)
	return r.done, nil
}

// Close stops admission, wakes all workers, and waits for deterministic relay
// teardown. It is safe to call repeatedly after Start; concurrent Start and
// Close calls linearize under the relay lifecycle lock.
func (r *Relay) Close(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrInvalidRelay
	}
	r.startMu.Lock()
	if !r.started.Load() {
		r.startMu.Unlock()
		return ErrRelayNotStarted
	}
	r.stopOnce.Do(func() { close(r.stop) })
	done := r.done
	r.startMu.Unlock()
	select {
	case <-done:
		return r.failure()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Done reports the final error of the started relay runtime. The channel is
// buffered and then closed, so a monitor and a later Close can both observe
// completion without blocking one another.
func (r *Relay) Done() <-chan error {
	if r == nil {
		return nil
	}
	return r.done
}

// SetSoftLimits applies controller output, clamped to the immutable hard caps.
// It is safe to call while Handle and workers are active.
func (r *Relay) SetSoftLimits(limits SoftLimits) {
	if r == nil {
		return
	}
	r.soft.set(SoftLimits{
		GlobalPacketsPerSec:  minPositive(limits.GlobalPacketsPerSec, r.cfg.GlobalPacketsPerSec),
		SessionPacketsPerSec: minPositive(limits.SessionPacketsPerSec, r.cfg.SessionPacketsPerSec),
	})
}

// Snapshot returns cumulative relay counters and current queue occupancy.
func (r *Relay) Snapshot() MetricsSnapshot {
	if r == nil {
		return MetricsSnapshot{}
	}
	stats := MetricsSnapshot{
		Enqueued:              r.enqueued.Load(),
		DroppedOverload:       r.droppedOverload.Load(),
		DroppedSoftLimit:      r.droppedSoftLimit.Load(),
		DroppedNoAuthority:    r.droppedNoAuthority.Load(),
		DroppedStaleAuthority: r.droppedStaleAuthority.Load(),
		DroppedMuted:          r.droppedMuted.Load(),
		DroppedNoMembership:   r.droppedNoMembership.Load(),
		DroppedInvalidChannel: r.droppedInvalidChannel.Load(),
		Sent:                  r.sent.Load(),
		SendErrors:            r.sendErrors.Load(),
		Queue:                 r.queue.Stats(),
	}
	r.latencyMu.Lock()
	stats.P95WorkLatency = percentile95(r.latencies)
	stats.P95WorkLatencyMillis = stats.P95WorkLatency.Milliseconds()
	r.latencyMu.Unlock()
	return stats
}

// IntervalSample atomically consumes cumulative deltas and the rolling p95
// work latency since the last sample. It is used by LoadController.
func (r *Relay) IntervalSample() IntervalSample {
	if r == nil {
		return IntervalSample{}
	}
	snapshot := MetricsSnapshot{
		Enqueued: r.intervalEnqueued.Swap(0), DroppedOverload: r.intervalDroppedOverload.Swap(0), DroppedSoftLimit: r.intervalDroppedSoftLimit.Swap(0), DroppedNoAuthority: r.intervalDroppedNoAuthority.Swap(0), DroppedStaleAuthority: r.intervalDroppedStaleAuthority.Swap(0), DroppedMuted: r.intervalDroppedMuted.Swap(0), DroppedNoMembership: r.intervalDroppedNoMembership.Swap(0), DroppedInvalidChannel: r.intervalDroppedInvalidChannel.Swap(0), Sent: r.intervalSent.Swap(0), SendErrors: r.intervalSendErrors.Swap(0), Queue: r.queue.Stats(),
	}
	r.latencyMu.Lock()
	snapshot.P95WorkLatency = percentile95(r.latencies)
	snapshot.P95WorkLatencyMillis = snapshot.P95WorkLatency.Milliseconds()
	r.latencies = r.latencies[:0]
	r.latencyMu.Unlock()
	dropped := snapshot.TotalDropped()
	return IntervalSample{Enqueued: snapshot.Enqueued, Dropped: dropped, SendErrors: snapshot.SendErrors, QueueUtilization: snapshot.Queue.Utilization, P95WorkLatency: snapshot.P95WorkLatency}
}

// run owns worker lifecycle and closes every queue shard when its context or
// explicit stop signal fires. A worker panic becomes a process-visible error.
func (r *Relay) run(ctx context.Context) {
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	for shard := 0; shard < ShardCount; shard++ {
		shard := shard
		workers.Go(func() { r.runShard(workerCtx, shard) })
	}
	select {
	case <-ctx.Done():
	case <-r.stop:
	}
	r.queue.Close()
	cancel()
	workers.Wait()
	r.done <- r.failure()
	close(r.done)
}

// runShard consumes one queue shard and performs the second authority, mute,
// and membership validation immediately before fanout.
func (r *Relay) runShard(ctx context.Context, shard int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			r.setFailure(fmt.Errorf("relay: worker panic: %v", recovered))
			r.stopOnce.Do(func() { close(r.stop) })
		}
	}()
	for {
		frame, ok := r.queue.Pop(ctx, shard)
		if !ok {
			return
		}
		started := r.cfg.Now()
		r.process(frame)
		r.recordLatency(r.cfg.Now().Sub(started))
	}
}

// process applies the authority/mute gate and fans one payload to the current
// members. Each target send is independent; one dead UDP session does not
// delay or suppress other recipients.
func (r *Relay) process(frame Frame) {
	current, ok := r.cfg.SourceResolver(frame.Source.UserID)
	if !ok || current != frame.Source {
		r.droppedStaleAuthority.Add(1)
		r.intervalDroppedStaleAuthority.Add(1)
		return
	}
	release := r.cfg.Gate.AcquireVoiceRelayGate(frame.Source.UserID)
	defer release()
	current, ok = r.cfg.SourceResolver(frame.Source.UserID)
	if !ok || current != frame.Source {
		r.droppedStaleAuthority.Add(1)
		r.intervalDroppedStaleAuthority.Add(1)
		return
	}
	if r.cfg.MuteResolver(frame.Source, frame.ChannelType) {
		r.droppedMuted.Add(1)
		r.intervalDroppedMuted.Add(1)
		return
	}
	members := r.cfg.MembershipResolver(frame.Source.ChannelID)
	if members.ChannelID != frame.Source.ChannelID || len(members.Members) == 0 {
		r.droppedNoMembership.Add(1)
		r.intervalDroppedNoMembership.Add(1)
		return
	}
	fanout := 0
	for _, member := range members.Members {
		if member.UserID <= 0 || member.SessionID == [16]byte{} || member.SessionID == frame.Source.SessionID {
			continue
		}
		if fanout >= MaxFanout {
			break
		}
		fanout++
		if err := r.cfg.Sender.Send(member.SessionID, frame.ChannelType, frame.Source.UserID, frame.ChannelSeq, frame.Payload); err != nil {
			r.sendErrors.Add(1)
			r.intervalSendErrors.Add(1)
			continue
		}
		r.sent.Add(1)
		r.intervalSent.Add(1)
	}
}

// recordLatency stores a bounded rolling latency sample for p95 load signals.
func (r *Relay) recordLatency(latency time.Duration) {
	r.latencyMu.Lock()
	if len(r.latencies) >= MaxLatencySamples {
		copy(r.latencies, r.latencies[1:])
		r.latencies = r.latencies[:MaxLatencySamples-1]
	}
	r.latencies = append(r.latencies, latency)
	r.latencyMu.Unlock()
}

// setFailure preserves the first asynchronous worker failure.
func (r *Relay) setFailure(err error) {
	if err == nil {
		return
	}
	r.errMu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.errMu.Unlock()
}

// failure returns the first relay worker failure.
func (r *Relay) failure() error {
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return r.err
}

// MetricsSnapshot is the cumulative relay and queue metrics response.
type MetricsSnapshot struct {
	Enqueued              uint64        `json:"enqueued"`
	DroppedOverload       uint64        `json:"dropped_overload"`
	DroppedSoftLimit      uint64        `json:"dropped_soft_limit"`
	DroppedNoAuthority    uint64        `json:"dropped_no_authority"`
	DroppedStaleAuthority uint64        `json:"dropped_stale_authority"`
	DroppedMuted          uint64        `json:"dropped_muted"`
	DroppedNoMembership   uint64        `json:"dropped_no_membership"`
	DroppedInvalidChannel uint64        `json:"dropped_invalid_channel"`
	Sent                  uint64        `json:"sent"`
	SendErrors            uint64        `json:"send_errors"`
	Queue                 QueueStats    `json:"queue"`
	P95WorkLatency        time.Duration `json:"-"`
	P95WorkLatencyMillis  int64         `json:"p95_work_latency_ms"`
}

// TotalDropped returns every relay admission or worker drop counter.
func (m MetricsSnapshot) TotalDropped() uint64 {
	return m.DroppedOverload + m.DroppedSoftLimit + m.DroppedNoAuthority + m.DroppedStaleAuthority + m.DroppedMuted + m.DroppedNoMembership + m.DroppedInvalidChannel
}

// IntervalSample contains short-window relay pressure signals.
type IntervalSample struct {
	Enqueued         uint64
	Dropped          uint64
	SendErrors       uint64
	QueueUtilization float64
	P95WorkLatency   time.Duration
}

// percentile95 computes a p95 by sorting a temporary bounded slice.
func percentile95(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	copyValues := append([]time.Duration(nil), values...)
	sort.Slice(copyValues, func(left, right int) bool { return copyValues[left] < copyValues[right] })
	position := (len(copyValues)*95 + 99) / 100
	if position > 0 {
		position--
	}
	return copyValues[position]
}

// minPositive clamps a controller value to one and an immutable hard cap.
func minPositive(value, hard int) int {
	if value < 1 {
		value = 1
	}
	if value > hard {
		return hard
	}
	return value
}
