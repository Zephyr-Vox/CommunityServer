package server

import (
	"context"
	"sync"
	"time"

	"zephyr.vox/server/ce/internal/protocol"
	"zephyr.vox/server/ce/internal/realtime"
)

const (
	voiceStatsWindow      = 10 * time.Second
	voiceStatsMaxSessions = 4096
	voiceStatsBucketCount = 10
)

// voiceDiagnostics keeps a bounded ten-second sample window per active UDP
// session. It intentionally stores counters and timestamps only, never media
// payloads or user labels.
type voiceDiagnostics struct {
	mu       sync.Mutex
	sessions map[[16]byte]*voiceDiagnosticWindow
}

// runVoiceStats emits one latest-only, user-scoped diagnostic frame at the
// current LoadController cadence. It exits with the process supervisor context
// and never enters the replay ring or allocates a state geid.
func (v *voiceRuntime) runVoiceStats(ctx context.Context) error {
	if v == nil || ctx == nil || v.diagnostics == nil || v.connections == nil {
		return nil
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastEmit := make(map[[16]byte]time.Time, voiceStatsMaxSessions)
	for {
		select {
		case now := <-ticker.C:
			interval := 5 * time.Second
			congestion := "normal"
			if v.load != nil {
				load := v.load.Snapshot()
				interval = load.Soft.VoiceStatsInterval
				if load.Overloaded {
					congestion = "overloaded"
				}
			}
			active := make(map[[16]byte]struct{})
			for _, authority := range v.connections.VoiceAuthorities() {
				active[authority.VoiceSessionID] = struct{}{}
				if last, ok := lastEmit[authority.VoiceSessionID]; ok && now.Sub(last) < interval {
					continue
				}
				data := v.diagnostics.snapshot(authority.VoiceSessionID, now, congestion)
				frame, err := realtime.NewVoiceStatsFrame(authority.VoiceSessionID, data)
				if err != nil {
					return err
				}
				v.connections.PublishVoiceStats(authority.UserID, authority.VoiceSessionID, frame)
				lastEmit[authority.VoiceSessionID] = now
			}
			for sessionID := range lastEmit {
				if _, ok := active[sessionID]; !ok {
					delete(lastEmit, sessionID)
				}
			}
		case <-ctx.Done():
			return nil
		}
	}
}

type voiceDiagnosticWindow struct {
	buckets [voiceStatsBucketCount]voiceDiagnosticBucket
}

type voiceDiagnosticBucket struct {
	start           time.Time
	packetsReceived uint64
	packetsDropped  uint64
	bytes           uint64
}

// newVoiceDiagnostics creates bounded transport diagnostics storage.
func newVoiceDiagnostics() *voiceDiagnostics {
	return &voiceDiagnostics{sessions: make(map[[16]byte]*voiceDiagnosticWindow, voiceStatsMaxSessions)}
}

// observe records one session-scoped protocol sample and returns immediately
// when the fixed diagnostics table is full or the sample has no session ID.
func (d *voiceDiagnostics) observe(sample protocol.StatsSample) {
	if d == nil || sample.SessionID == [16]byte{} {
		return
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	window := d.sessions[sample.SessionID]
	if window == nil {
		if len(d.sessions) >= voiceStatsMaxSessions {
			d.pruneLocked(now)
			if len(d.sessions) >= voiceStatsMaxSessions {
				return
			}
		}
		window = &voiceDiagnosticWindow{}
		d.sessions[sample.SessionID] = window
	}
	bucketStart := now.Truncate(time.Second)
	index := int(bucketStart.Unix() % voiceStatsBucketCount)
	if index < 0 {
		index += voiceStatsBucketCount
	}
	bucket := &window.buckets[index]
	if bucket.start != bucketStart {
		*bucket = voiceDiagnosticBucket{start: bucketStart}
	}
	switch sample.Kind {
	case protocol.StatsFrameDelivered:
		bucket.packetsReceived++
		if sample.Bytes > 0 {
			bucket.bytes += uint64(sample.Bytes)
		}
	case protocol.StatsDroppedMalformed,
		protocol.StatsDroppedUnknownSession,
		protocol.StatsDroppedGlobalIngress,
		protocol.StatsDroppedSourceIngress,
		protocol.StatsDroppedSourceTableFull,
		protocol.StatsDroppedAuthentication,
		protocol.StatsDroppedChannel,
		protocol.StatsDroppedReplay,
		protocol.StatsDroppedSessionRateLimit:
		bucket.packetsDropped++
	}
}

// snapshot calculates latest-only voice diagnostics for one session.
func (d *voiceDiagnostics) snapshot(sessionID [16]byte, now time.Time, congestion string) realtime.VoiceStatsData {
	if d == nil || sessionID == [16]byte{} {
		return realtime.VoiceStatsData{CongestionLevel: congestion}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	window := d.sessions[sessionID]
	if window == nil {
		return realtime.VoiceStatsData{CongestionLevel: congestion}
	}
	var received, dropped, bytes uint64
	cutoff := now.Add(-voiceStatsWindow)
	for _, bucket := range window.buckets {
		if bucket.start.IsZero() || bucket.start.Before(cutoff) || bucket.start.After(now.Add(time.Second)) {
			continue
		}
		received += bucket.packetsReceived
		dropped += bucket.packetsDropped
		bytes += bucket.bytes
	}
	data := realtime.VoiceStatsData{PacketsReceived: received, PacketsDropped: dropped, CongestionLevel: congestion}
	if total := received + dropped; total != 0 {
		data.PacketLossPct = float64(dropped) * 100 / float64(total)
	}
	if bytes != 0 {
		data.BitrateBPS = bytes * 8 / uint64(voiceStatsWindow/time.Second)
	}
	return data
}

// prune removes expired session windows from the fixed table.
func (d *voiceDiagnostics) pruneLocked(now time.Time) {
	for id, window := range d.sessions {
		if !window.hasRecent(now) {
			delete(d.sessions, id)
		}
	}
}

// hasRecent reports whether one fixed bucket still overlaps the diagnostics
// window and therefore keeps this session eligible for future samples.
func (w *voiceDiagnosticWindow) hasRecent(now time.Time) bool {
	if w == nil {
		return false
	}
	cutoff := now.Add(-voiceStatsWindow)
	for _, bucket := range w.buckets {
		if !bucket.start.IsZero() && !bucket.start.Before(cutoff) {
			return true
		}
	}
	return false
}
