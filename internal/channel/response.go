package channel

import (
	"strconv"

	"zephyr.vox/server/ce/internal/realtime"
)

// groupPageResponse is one visible page of canonical group snapshots.
type groupPageResponse struct {
	Items  []realtime.SnapshotGroup `json:"items"`
	Limit  int64                    `json:"limit"`
	Offset int64                    `json:"offset"`
	Total  int64                    `json:"total"`
}

// channelPageResponse is one visible page of canonical channel snapshots.
type channelPageResponse struct {
	Items  []realtime.SnapshotChannel `json:"items"`
	Limit  int64                      `json:"limit"`
	Offset int64                      `json:"offset"`
	Total  int64                      `json:"total"`
}

// accessResponse is one wire-safe ACL entry. Snowflake values remain decimal
// text at the JSON boundary to preserve their full signed 63-bit precision.
type accessResponse struct {
	ID            string  `json:"id"`
	PrincipalType string  `json:"principal_type"`
	UserID        *string `json:"user_id,omitempty"`
	RoleKey       *string `json:"role_key,omitempty"`
	CreatedAt     int64   `json:"created_at"`
}

// accessPageResponse is one ordered page of ACL entries for a group or channel.
type accessPageResponse struct {
	Items  []accessResponse `json:"items"`
	Limit  int64            `json:"limit"`
	Offset int64            `json:"offset"`
	Total  int64            `json:"total"`
}

// voiceJoinResponse is the complete response for a successful voice join.
// State fields are embedded in the body as well as response headers so a
// client can apply the channel/member projection only at the returned cursor.
type voiceJoinResponse struct {
	Channel         realtime.SnapshotChannel           `json:"channel"`
	Members         []realtime.SnapshotVoiceMembership `json:"members"`
	Voice           voiceSessionResponse               `json:"voice"`
	StateCursor     string                             `json:"state_cursor"`
	StateCheckpoint stateCheckpointResponse            `json:"state_checkpoint"`
}

// voiceSessionResponse is the one-time HTTP negotiation result for a UDP
// session. Key is omitted for reuse and for plaintext deployments.
type voiceSessionResponse struct {
	Created         bool   `json:"created"`
	SessionID       string `json:"session_id"`
	Key             string `json:"key,omitempty"`
	Encrypted       bool   `json:"encrypted"`
	Warning         string `json:"warning,omitempty"`
	MaxPayload      int    `json:"max_payload"`
	ProtocolVersion int    `json:"protocol_version"`
	ExpiresAt       int64  `json:"expires_at"`
}

// stateCheckpointResponse preserves decimal GEID text at the JSON boundary.
type stateCheckpointResponse struct {
	StreamEpoch string `json:"stream_epoch"`
	GEID        string `json:"geid"`
}

// snapshotAccessResponse converts one immutable access entry into its public
// JSON DTO without exposing nullable database implementation details.
func snapshotAccessResponse(entry realtime.AccessEntry) accessResponse {
	response := accessResponse{
		ID:            strconv.FormatInt(entry.ID, 10),
		PrincipalType: entry.PrincipalType,
		RoleKey:       entry.RoleKey,
		CreatedAt:     entry.CreatedAt,
	}
	if entry.UserID != nil {
		userID := strconv.FormatInt(*entry.UserID, 10)
		response.UserID = &userID
	}
	return response
}
