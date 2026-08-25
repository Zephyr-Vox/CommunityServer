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
