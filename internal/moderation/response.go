package moderation

import (
	"strconv"

	"zephyr.vox/server/ce/internal/realtime"
)

// scopeResponse is a wire-safe moderation scope.
type scopeResponse struct {
	Type string  `json:"type"`
	ID   *string `json:"id,omitempty"`
}

// muteResponse is one management-facing mute resource.
type muteResponse struct {
	ID        string        `json:"id"`
	Scope     scopeResponse `json:"scope"`
	UserID    string        `json:"user_id"`
	Kind      string        `json:"kind"`
	ExpiresAt *int64        `json:"expires_at"`
	Reason    string        `json:"reason"`
	CreatedAt int64         `json:"created_at"`
	Version   string        `json:"version"`
}

// pageResponse is one stable moderation list page.
type pageResponse struct {
	Items  []muteResponse `json:"items"`
	Limit  int64          `json:"limit"`
	Offset int64          `json:"offset"`
	Total  int64          `json:"total"`
}

// muteInvalidation is the minimal state-event payload for management cache
// invalidation. It deliberately excludes reason and target identity.
type muteInvalidation struct {
	Scope           scopeResponse `json:"scope"`
	ModerationEpoch string        `json:"moderation_epoch"`
}

// muteResponseFromState converts immutable state into the management DTO.
func muteResponseFromState(mute realtime.Mute) muteResponse {
	return muteResponse{
		ID:        strconv.FormatInt(mute.ID, 10),
		Scope:     scopeResponseFromRealtime(mute.Scope),
		UserID:    strconv.FormatInt(mute.UserID, 10),
		Kind:      mute.Kind,
		ExpiresAt: cloneInt64(mute.ExpiresAt),
		Reason:    mute.Reason,
		CreatedAt: mute.CreatedAt,
		Version:   strconv.FormatInt(mute.Version, 10),
	}
}

// scopeResponseFromRealtime converts one immutable scope to its JSON form.
func scopeResponseFromRealtime(scope realtime.Scope) scopeResponse {
	if scope.Type == "server" {
		return scopeResponse{Type: "server"}
	}
	id := strconv.FormatInt(scope.ID, 10)
	return scopeResponse{Type: scope.Type, ID: &id}
}

// cloneInt64 prevents response callers from observing mutable state pointers.
func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// page returns a non-nil stable page slice.
func page[T any](items []T, limit, offset int64) []T {
	if offset >= int64(len(items)) {
		return []T{}
	}
	end := offset + limit
	if end > int64(len(items)) {
		end = int64(len(items))
	}
	return append([]T(nil), items[offset:end]...)
}
