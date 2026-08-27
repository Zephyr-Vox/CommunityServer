package moderation

import "encoding/json"

// scopeRequest is the JSON moderation scope. Non-server IDs remain decimal
// strings so snowflake precision never enters a JavaScript number.
type scopeRequest struct {
	Type string  `json:"type" validate:"required,oneof=server group channel"`
	ID   *string `json:"id" validate:"omitempty"`
}

// createRequest is the POST /mutes payload.
type createRequest struct {
	Scope     scopeRequest `json:"scope" validate:"required"`
	UserID    string       `json:"user_id" validate:"required"`
	Kind      string       `json:"kind" validate:"required,oneof=text voice desktop_audio"`
	ExpiresAt *int64       `json:"expires_at" validate:"omitempty,min=1"`
	Reason    string       `json:"reason" validate:"omitempty,max=256"`
}

// optionalExpiry records explicit null so PATCH can clear an expiry.
type optionalExpiry struct {
	Set   bool
	Value *int64
}

// UnmarshalJSON accepts a Unix-millisecond number or null for an expiry patch.
func (e *optionalExpiry) UnmarshalJSON(data []byte) error {
	var value *int64
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	e.Set = true
	e.Value = value
	return nil
}

// updateRequest is the PATCH /mutes/:id payload.
type updateRequest struct {
	ExpiresAt optionalExpiry `json:"expires_at"`
	Reason    *string        `json:"reason" validate:"omitempty,max=256"`
}
