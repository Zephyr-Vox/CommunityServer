package realtime_test

import (
	"encoding/json"
	"testing"

	"zephyr.vox/server/ce/internal/realtime"
)

func TestVoiceStatsFrameIsTelemetryAndSessionScoped(t *testing.T) {
	var sessionID [16]byte
	sessionID[0] = 0xab
	frame, err := realtime.NewVoiceStatsFrame(sessionID, realtime.VoiceStatsData{PacketLossPct: 0.4, CongestionLevel: "normal"})
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Type  string `json:"type"`
		Class string `json:"class"`
		Scope struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(frame, &document); err != nil {
		t.Fatal(err)
	}
	if document.Type != "voice.stats" || document.Class != "telemetry" || document.Scope.Type != "session" || len(document.Scope.ID) != 32 || document.Scope.ID[:2] != "ab" {
		t.Fatalf("voice stats envelope = %+v", document)
	}
}
