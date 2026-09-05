package realtime

import (
	"encoding/hex"
	"encoding/json"
)

// VoiceStatsData is the latest-only diagnostic payload for the subject's own
// voice session. Fields that the transport cannot measure are omitted rather
// than fabricated.
type VoiceStatsData struct {
	PacketsReceived uint64  `json:"packets_received,omitempty"`
	PacketsDropped  uint64  `json:"packets_dropped,omitempty"`
	PacketLossPct   float64 `json:"packet_loss_percent,omitempty"`
	BitrateBPS      uint64  `json:"bitrate_bps,omitempty"`
	JitterMS        int64   `json:"jitter_ms,omitempty"`
	LatencyMS       int64   `json:"latency_ms,omitempty"`
	CongestionLevel string  `json:"congestion_level,omitempty"`
}

// NewVoiceStatsFrame encodes a session-scoped telemetry frame. It does not
// allocate a geid or enter the replay ring; each connection keeps only its
// newest pending copy in the WebSocket telemetry lane.
func NewVoiceStatsFrame(sessionID [16]byte, data VoiceStatsData) ([]byte, error) {
	if sessionID == [16]byte{} {
		return nil, ErrInvalidConnection
	}
	return json.Marshal(struct {
		Type  string `json:"type"`
		Class string `json:"class"`
		Scope struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"scope"`
		Data VoiceStatsData `json:"data"`
	}{
		Type:  "voice.stats",
		Class: "telemetry",
		Scope: struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}{Type: "session", ID: hex.EncodeToString(sessionID[:])},
		Data: data,
	})
}
