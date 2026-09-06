package server

import "zephyr.vox/server/ce/internal/relay"

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
