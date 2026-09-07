package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestRealtimeHTTPAndWebSocketHandoff exercises metadata, a replace snapshot,
// connection.ready, replay-to-live handoff and a sequenced presence.set event.
func TestRealtimeHTTPAndWebSocketHandoff(t *testing.T) {
	app := newTestApp(t)
	_, token := activateAdmin(t, app)
	server := httptest.NewServer(app.Echo())
	defer server.Close()

	metadataResp, err := http.Get(server.URL + "/api/v0/metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer metadataResp.Body.Close()
	var metadata struct {
		Code int `json:"code"`
		Data struct {
			ProtocolVersion int      `json:"protocol_version"`
			Features        []string `json:"features"`
			VoiceEndpoint   struct {
				Host string `json:"host"`
				Port int    `json:"port"`
			} `json:"voice_endpoint"`
		} `json:"data"`
	}
	if err := json.NewDecoder(metadataResp.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	if metadataResp.StatusCode != http.StatusOK || metadata.Code != 0 || metadata.Data.ProtocolVersion != 1 || len(metadata.Data.Features) != 2 || metadata.Data.Features[0] != "voice" || metadata.Data.Features[1] != "temporary_channels" || metadata.Data.VoiceEndpoint.Host == "" || metadata.Data.VoiceEndpoint.Port == 0 {
		t.Fatalf("metadata = status:%d body:%+v", metadataResp.StatusCode, metadata)
	}

	snapshotRequest, err := http.NewRequest(http.MethodGet, server.URL+"/api/v0/state/snapshot", nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshotRequest.Header.Set("Authorization", "Bearer "+token)
	snapshotResp, err := http.DefaultClient.Do(snapshotRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshotResp.Body.Close()
	var snapshot struct {
		Code int `json:"code"`
		Data struct {
			Cursor string `json:"cursor"`
			State  struct {
				Users            []json.RawMessage `json:"users"`
				Roles            []json.RawMessage `json:"roles"`
				Groups           []json.RawMessage `json:"groups"`
				Channels         []json.RawMessage `json:"channels"`
				VoiceMemberships []json.RawMessage `json:"voice_memberships"`
				Self             struct {
					User struct {
						Username string `json:"username"`
					} `json:"user"`
					Presence struct {
						Status string `json:"status"`
					} `json:"presence"`
					ServerPermissions []string `json:"server_permissions"`
				} `json:"self"`
			} `json:"state"`
		} `json:"data"`
	}
	if err := json.NewDecoder(snapshotResp.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshotResp.StatusCode != http.StatusOK || snapshot.Code != 0 || snapshot.Data.Cursor == "" || snapshot.Data.State.Self.User.Username != "boss" || snapshot.Data.State.Self.Presence.Status != "offline" || len(snapshot.Data.State.Self.ServerPermissions) != 1 || snapshot.Data.State.Self.ServerPermissions[0] != "*" {
		t.Fatalf("snapshot = status:%d body:%+v", snapshotResp.StatusCode, snapshot)
	}
	if snapshot.Data.State.Users == nil || snapshot.Data.State.Roles == nil || snapshot.Data.State.Groups == nil || snapshot.Data.State.Channels == nil || snapshot.Data.State.VoiceMemberships == nil {
		t.Fatalf("snapshot state collections must be JSON arrays: %+v", snapshot.Data.State)
	}
	if cacheControl := snapshotResp.Header.Get("Cache-Control"); cacheControl != "private, no-store" {
		t.Fatalf("snapshot Cache-Control = %q", cacheControl)
	}

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v0/ws"
	conn, response, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + token}})
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var ready struct {
		Type string `json:"type"`
		Data struct {
			ControlConnectionID string `json:"control_connection_id"`
		} `json:"data"`
	}
	if err := conn.ReadJSON(&ready); err != nil {
		t.Fatal(err)
	}
	if ready.Type != "connection.ready" || len(ready.Data.ControlConnectionID) != 32 {
		t.Fatalf("ready = %+v", ready)
	}
	if err := conn.WriteJSON(map[string]any{"type": "sync.hello", "data": map[string]any{"cursor": snapshot.Data.Cursor}}); err != nil {
		t.Fatal(err)
	}

	seenReplay := false
	seenComplete := false
	for !seenComplete {
		var frame struct {
			Type string `json:"type"`
			Data struct {
				Events []struct {
					EventType string `json:"event_type"`
				} `json:"events"`
				Cursor string `json:"cursor"`
			} `json:"data"`
		}
		if err := conn.ReadJSON(&frame); err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "sync.replay":
			seenReplay = true
			if len(frame.Data.Events) != 1 || frame.Data.Events[0].EventType != "presence.updated" {
				t.Fatalf("replay = %+v", frame)
			}
		case "sync.complete":
			if frame.Data.Cursor == "" {
				t.Fatal("sync.complete has empty cursor")
			}
			seenComplete = true
		default:
			t.Fatalf("unexpected sync frame = %+v", frame)
		}
	}
	if !seenReplay {
		t.Fatal("sync replay was not sent")
	}

	if err := conn.WriteJSON(map[string]any{"type": "presence.set", "request_id": "presence-set-0001", "data": map[string]any{"status": "dnd"}}); err != nil {
		t.Fatal(err)
	}
	seenPresence := false
	seenAck := false
	for !seenPresence || !seenAck {
		var frame struct {
			Type      string `json:"type"`
			RequestID string `json:"request_id"`
			EventType string `json:"event_type"`
			Data      struct {
				CommandType string `json:"command_type"`
				CommandID   string `json:"command_id"`
				User        struct {
					Presence struct {
						Status string `json:"status"`
					} `json:"presence"`
				} `json:"user"`
			} `json:"data"`
		}
		if err := conn.ReadJSON(&frame); err != nil {
			t.Fatal(err)
		}
		if frame.Type == "state.event" && frame.EventType == "presence.updated" {
			if frame.Data.User.Presence.Status != "dnd" {
				t.Fatalf("presence event = %+v", frame)
			}
			seenPresence = true
		}
		if frame.Type == "command.ok" && frame.RequestID == "presence-set-0001" {
			if frame.Data.CommandType != "presence.set" || frame.Data.CommandID == "" {
				t.Fatalf("presence acknowledgement = %+v", frame)
			}
			seenAck = true
		}
	}
}
