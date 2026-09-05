package server

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/protocol"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/relay"
)

// httpConnectionTracker counts ordinary HTTP connections by ConnState. A
// mutex-backed set avoids double-counting New -> Active transitions and removes
// hijacked WebSocket sockets from the HTTP gauge.
type httpConnectionTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// newHTTPConnectionTracker creates an empty connection gauge.
func newHTTPConnectionTracker() *httpConnectionTracker {
	return &httpConnectionTracker{conns: make(map[net.Conn]struct{})}
}

// state updates one net/http connection lifecycle state.
func (t *httpConnectionTracker) state(conn net.Conn, state http.ConnState) {
	if t == nil || conn == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	switch state {
	case http.StateNew, http.StateActive, http.StateIdle:
		t.conns[conn] = struct{}{}
	case http.StateClosed, http.StateHijacked:
		delete(t.conns, conn)
	}
}

// count returns the current ordinary HTTP connection count.
func (t *httpConnectionTracker) count() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// transportMetrics aggregates UDP samples with fixed process-wide counters.
type transportMetrics struct {
	packetsReceived atomic.Uint64
	dropped         atomic.Uint64
	globalDropped   atomic.Uint64
	sourceDropped   atomic.Uint64
	sessionDropped  atomic.Uint64
	sendSuccess     atomic.Uint64
	sendErrors      atomic.Uint64
}

// transportMetricsSnapshot is the cumulative read-side value used by metrics
// and the load controller's delta calculation.
type transportMetricsSnapshot struct {
	PacketsReceived uint64
	Dropped         uint64
	GlobalDropped   uint64
	SourceDropped   uint64
	SessionDropped  uint64
	SendSuccess     uint64
	SendErrors      uint64
}

// observe consumes one protocol sample without logging or blocking the UDP
// read goroutine.
func (m *transportMetrics) observe(sample protocol.StatsSample) {
	if m == nil {
		return
	}
	switch sample.Kind {
	case protocol.StatsPacketReceived:
		m.packetsReceived.Add(1)
	case protocol.StatsDroppedGlobalIngress:
		m.dropped.Add(1)
		m.globalDropped.Add(1)
	case protocol.StatsDroppedSourceIngress, protocol.StatsDroppedSourceTableFull:
		m.dropped.Add(1)
		m.sourceDropped.Add(1)
	case protocol.StatsSendSuccess:
		m.sendSuccess.Add(1)
	case protocol.StatsSendError:
		m.sendErrors.Add(1)
	default:
		if sample.Kind >= protocol.StatsDroppedMalformed && sample.Kind <= protocol.StatsDroppedSessionRateLimit {
			m.dropped.Add(1)
			m.sessionDropped.Add(1)
		}
	}
}

// snapshot returns cumulative UDP transport counters.
func (m *transportMetrics) snapshot() transportMetricsSnapshot {
	if m == nil {
		return transportMetricsSnapshot{}
	}
	return transportMetricsSnapshot{PacketsReceived: m.packetsReceived.Load(), Dropped: m.dropped.Load(), GlobalDropped: m.globalDropped.Load(), SourceDropped: m.sourceDropped.Load(), SessionDropped: m.sessionDropped.Load(), SendSuccess: m.sendSuccess.Load(), SendErrors: m.sendErrors.Load()}
}

// serverMetrics owns endpoint and load-controller observability. Counters are
// deliberately process-wide and do not retain user labels or media payloads.
type serverMetrics struct {
	http         *httpConnectionTracker
	transport    *transportMetrics
	diagnostics  *voiceDiagnostics
	connections  *realtime.ConnectionCoordinator
	voice        *voiceRuntime
	relay        *relay.Relay
	load         *relay.LoadController
	publication  *realtime.StatePublication
	syncStrategy *realtime.FullSnapshotSyncStrategy

	sampleMu       sync.Mutex
	lastUDP        transportMetricsSnapshot
	lastSampleAt   time.Time
	relayPPS       float64
	relayDropRatio float64
}

// newServerMetrics creates empty metrics storage before HTTP route assembly.
func newServerMetrics() *serverMetrics {
	return &serverMetrics{http: newHTTPConnectionTracker(), transport: &transportMetrics{}}
}

// observeProtocol records UDP transport samples and feeds the per-session
// diagnostics window used by voice.stats.
func (m *serverMetrics) observeProtocol(sample protocol.StatsSample) {
	if m == nil {
		return
	}
	m.transport.observe(sample)
	if m.diagnostics != nil {
		m.diagnostics.observe(sample)
	}
}

// loadInput consumes only relay's interval counters and derives UDP deltas from
// cumulative snapshots. The metrics endpoint remains cumulative while the
// controller receives short-window pressure signals and rates.
func (m *serverMetrics) loadInput() relay.LoadInput {
	if m == nil {
		return relay.LoadInput{}
	}
	m.sampleMu.Lock()
	defer m.sampleMu.Unlock()
	currentRelay := relay.MetricsSnapshot{}
	intervalRelay := relay.IntervalSample{}
	if m.relay != nil {
		currentRelay = m.relay.Snapshot()
		intervalRelay = m.relay.IntervalSample()
	}
	currentUDP := m.transport.snapshot()
	udpReceived := difference(currentUDP.PacketsReceived, m.lastUDP.PacketsReceived)
	udpDropped := difference(currentUDP.Dropped, m.lastUDP.Dropped)
	udpGlobalDropped := difference(currentUDP.GlobalDropped, m.lastUDP.GlobalDropped)
	udpSourceDropped := difference(currentUDP.SourceDropped, m.lastUDP.SourceDropped)
	udpSessionDropped := difference(currentUDP.SessionDropped, m.lastUDP.SessionDropped)
	m.lastUDP = currentUDP
	now := time.Now()
	m.relayDropRatio = ratio(intervalRelay.Dropped, intervalRelay.Enqueued+intervalRelay.Dropped)
	if !m.lastSampleAt.IsZero() {
		elapsed := now.Sub(m.lastSampleAt).Seconds()
		if elapsed > 0 {
			m.relayPPS = float64(intervalRelay.Enqueued) / elapsed
		}
	}
	m.lastSampleAt = now
	input := relay.LoadInput{
		QueueUtilization:    currentRelay.Queue.Utilization,
		RelayDropRatio:      m.relayDropRatio,
		UDPDropRatio:        ratio(udpDropped, udpReceived),
		UDPGlobalDropRatio:  ratio(udpGlobalDropped, udpReceived),
		UDPSourceDropRatio:  ratio(udpSourceDropped, udpReceived),
		UDPSessionDropRatio: ratio(udpSessionDropped, udpReceived),
		RelayP95Latency:     intervalRelay.P95WorkLatency,
	}
	if m.publication != nil {
		input.StatePublicationLag = m.publication.LastPublishLatency()
	}
	return input
}

// snapshot returns the DTO exposed by the guarded metrics endpoint.
func (m *serverMetrics) snapshot() serverMetricsResponse {
	if m == nil {
		return serverMetricsResponse{}
	}
	result := serverMetricsResponse{}
	if m.http != nil {
		result.HTTPConnections = m.http.count()
	}
	if m.connections != nil {
		result.WebSocketConnections = m.connections.ActiveConnectionCount()
	}
	if m.voice != nil && m.voice.manager != nil {
		result.UDPSessions = m.voice.manager.Len()
	}
	if m.relay != nil {
		result.Relay = m.relay.Snapshot()
	}
	if m.load != nil {
		result.Load = newLoadMetricsResponse(m.load.Snapshot())
	}
	m.sampleMu.Lock()
	result.RelayPPS = m.relayPPS
	result.RelayDropRatio = m.relayDropRatio
	m.sampleMu.Unlock()
	if m.transport != nil {
		transport := m.transport.snapshot()
		result.UDP = udpMetricsResponse{
			PacketsReceived:  transport.PacketsReceived,
			Dropped:          transport.Dropped,
			GlobalDropped:    transport.GlobalDropped,
			SourceDropped:    transport.SourceDropped,
			SessionDropped:   transport.SessionDropped,
			SendSuccess:      transport.SendSuccess,
			SendErrors:       transport.SendErrors,
			DropRatio:        ratio(transport.Dropped, transport.PacketsReceived),
			GlobalDropRatio:  ratio(transport.GlobalDropped, transport.PacketsReceived),
			SourceDropRatio:  ratio(transport.SourceDropped, transport.PacketsReceived),
			SessionDropRatio: ratio(transport.SessionDropped, transport.PacketsReceived),
		}
	}
	if m.publication != nil {
		result.StatePublicationLatencyMS = m.publication.LastPublishLatency().Milliseconds()
	}
	if m.syncStrategy != nil {
		result.SnapshotLatencyMS = m.syncStrategy.SnapshotLatency().Milliseconds()
	}
	return result
}

// serverMetricsResponse is the stable JSON data shape for GET /admin/metrics.
// All *_ms fields are integer milliseconds; RelayPPS and RelayDropRatio are
// measured over the latest one-second controller sample.
type serverMetricsResponse struct {
	HTTPConnections      int                   `json:"http_connections"`
	WebSocketConnections int                   `json:"websocket_connections"`
	UDPSessions          int                   `json:"udp_sessions"`
	UDP                  udpMetricsResponse    `json:"udp"`
	Relay                relay.MetricsSnapshot `json:"relay"`
	// RelayPPS and RelayDropRatio describe the latest one-second controller
	// sample, not the cumulative Relay counters above.
	RelayPPS                  float64             `json:"relay_packets_per_second"`
	RelayDropRatio            float64             `json:"relay_drop_ratio"`
	Load                      loadMetricsResponse `json:"load"`
	StatePublicationLatencyMS int64               `json:"state_publication_latency_ms"`
	SnapshotLatencyMS         int64               `json:"snapshot_latency_ms"`
}

// loadMetricsResponse exposes controller values with explicit millisecond
// units so the metrics API never serializes Go durations as nanoseconds.
type loadMetricsResponse struct {
	Hard          relay.HardLimits         `json:"hard"`
	Soft          loadSoftMetricsResponse  `json:"soft"`
	Overloaded    bool                     `json:"overloaded"`
	RecoveryTicks int                      `json:"recovery_ticks"`
	LastInput     loadInputMetricsResponse `json:"last_input"`
}

// loadSoftMetricsResponse is the public soft-limit DTO used by metrics.
type loadSoftMetricsResponse struct {
	GlobalIngressSoftPPS int   `json:"global_ingress_soft_pps"`
	SessionSoftPPS       int   `json:"session_soft_pps"`
	VoiceStatsIntervalMS int64 `json:"voice_stats_interval_ms"`
}

// loadInputMetricsResponse is the public pressure-sample DTO used by metrics.
type loadInputMetricsResponse struct {
	QueueUtilization      float64 `json:"queue_utilization"`
	RelayDropRatio        float64 `json:"relay_drop_ratio"`
	UDPDropRatio          float64 `json:"udp_drop_ratio"`
	UDPGlobalDropRatio    float64 `json:"udp_global_drop_ratio"`
	UDPSourceDropRatio    float64 `json:"udp_source_drop_ratio"`
	UDPSessionDropRatio   float64 `json:"udp_session_drop_ratio"`
	RelayP95LatencyMS     int64   `json:"relay_p95_latency_ms"`
	StatePublicationLagMS int64   `json:"state_publication_lag_ms"`
}

// newLoadMetricsResponse converts one controller snapshot into the stable
// metrics representation with human-independent integer millisecond units.
func newLoadMetricsResponse(snapshot relay.LoadSnapshot) loadMetricsResponse {
	return loadMetricsResponse{
		Hard: snapshot.Hard,
		Soft: loadSoftMetricsResponse{
			GlobalIngressSoftPPS: snapshot.Soft.GlobalPacketsPerSec,
			SessionSoftPPS:       snapshot.Soft.SessionPacketsPerSec,
			VoiceStatsIntervalMS: snapshot.Soft.VoiceStatsInterval.Milliseconds(),
		},
		Overloaded:    snapshot.Overloaded,
		RecoveryTicks: snapshot.RecoveryTicks,
		LastInput: loadInputMetricsResponse{
			QueueUtilization:      snapshot.LastInput.QueueUtilization,
			RelayDropRatio:        snapshot.LastInput.RelayDropRatio,
			UDPDropRatio:          snapshot.LastInput.UDPDropRatio,
			UDPGlobalDropRatio:    snapshot.LastInput.UDPGlobalDropRatio,
			UDPSourceDropRatio:    snapshot.LastInput.UDPSourceDropRatio,
			UDPSessionDropRatio:   snapshot.LastInput.UDPSessionDropRatio,
			RelayP95LatencyMS:     snapshot.LastInput.RelayP95Latency.Milliseconds(),
			StatePublicationLagMS: snapshot.LastInput.StatePublicationLag.Milliseconds(),
		},
	}
}

// udpMetricsResponse contains process-wide ingress/drop/send counters.
type udpMetricsResponse struct {
	PacketsReceived  uint64  `json:"packets_received"`
	Dropped          uint64  `json:"dropped"`
	GlobalDropped    uint64  `json:"global_dropped"`
	SourceDropped    uint64  `json:"source_dropped"`
	SessionDropped   uint64  `json:"session_dropped"`
	SendSuccess      uint64  `json:"send_success"`
	SendErrors       uint64  `json:"send_errors"`
	DropRatio        float64 `json:"drop_ratio"`
	GlobalDropRatio  float64 `json:"global_drop_ratio"`
	SourceDropRatio  float64 `json:"source_drop_ratio"`
	SessionDropRatio float64 `json:"session_drop_ratio"`
}

// metricsHandler returns the guarded metrics document. Authorization is
// mounted by router.go with the server.metrics RBAC permission.
// Errors:
//   - 1003 forbidden: server.metrics permission is required
//   - 1009 internal: metrics are unavailable
func (a *App) metricsHandler() echo.HandlerFunc {
	return func(c *echo.Context) error {
		if a == nil || a.metrics == nil {
			return errors.New("server: metrics unavailable")
		}
		return api.OK(c, http.StatusOK, a.metrics.snapshot())
	}
}

// difference returns a monotonic counter delta and protects against a future
// counter reset during test or process reconfiguration.
func difference(current, previous uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

// ratio returns a bounded fraction and avoids an artificial overload signal on
// an empty sample window.
func ratio(numerator, denominator uint64) float64 {
	if denominator == 0 {
		return 0
	}
	value := float64(numerator) / float64(denominator)
	if value > 1 {
		return 1
	}
	return value
}
