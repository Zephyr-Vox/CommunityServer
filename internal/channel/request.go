// Package channel implements the HTTP control-plane slice for channel groups
// and channels.
package channel

import "encoding/json"

// createGroupRequest is the POST /groups request payload.
type createGroupRequest struct {
	Name       string `json:"name" validate:"required,min=1,max=64"`
	Position   *int64 `json:"position" validate:"required,gte=-2147483648,lte=2147483647"`
	Visibility string `json:"visibility" validate:"required,oneof=public private"`
}

// createChannelRequest is the POST /channels request payload. GroupID remains
// decimal text at the wire boundary so snowflake precision is never lost.
type createChannelRequest struct {
	GroupID    *string `json:"group_id" validate:"omitempty"`
	Name       string  `json:"name" validate:"required,min=1,max=64"`
	Mode       string  `json:"mode" validate:"required,oneof=voice text announcement"`
	Temporary  *bool   `json:"temporary" validate:"required"`
	Visibility string  `json:"visibility" validate:"required,oneof=public private"`
	Capacity   *int64  `json:"capacity" validate:"omitempty,min=1,max=256"`
	Position   *int64  `json:"position" validate:"required,gte=-2147483648,lte=2147483647"`
	Pinned     *bool   `json:"pinned" validate:"required"`
}

// updateGroupRequest is the PATCH /groups/:id request payload.
type updateGroupRequest struct {
	Name       *string `json:"name" validate:"omitempty,min=1,max=64"`
	Position   *int64  `json:"position" validate:"omitempty,gte=-2147483648,lte=2147483647"`
	Visibility *string `json:"visibility" validate:"omitempty,oneof=public private"`
}

// optionalGroupIDRequest preserves the distinction between an omitted group_id
// and an explicit JSON null that removes a channel from its group.
type optionalGroupIDRequest struct {
	Set   bool
	Value *string
}

// UnmarshalJSON records an explicit group_id field while accepting only a JSON
// string snowflake or null.
func (r *optionalGroupIDRequest) UnmarshalJSON(data []byte) error {
	var value *string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	r.Set = true
	r.Value = value
	return nil
}

// updateChannelRequest is the PATCH /channels/:id request payload. Immutable
// fields are bound only so the handler can reject attempts to modify them.
type updateChannelRequest struct {
	GroupID    optionalGroupIDRequest `json:"group_id"`
	Name       *string                `json:"name" validate:"omitempty,min=1,max=64"`
	Visibility *string                `json:"visibility" validate:"omitempty,oneof=public private"`
	Capacity   *int64                 `json:"capacity" validate:"omitempty,min=1,max=256"`
	Position   *int64                 `json:"position" validate:"omitempty,gte=-2147483648,lte=2147483647"`
	Pinned     *bool                  `json:"pinned" validate:"omitempty"`
	Mode       *string                `json:"mode"`
	Temporary  *bool                  `json:"temporary"`
	CreatedBy  *string                `json:"created_by"`
}

// accessRequest is the POST /groups/:id/access and POST /channels/:id/access
// payload. Principal exact-one validation is completed by the handler because
// it depends on principal_type rather than independent field constraints.
type accessRequest struct {
	PrincipalType string  `json:"principal_type" validate:"required,oneof=user role"`
	UserID        *string `json:"user_id" validate:"omitempty"`
	RoleKey       *string `json:"role_key" validate:"omitempty,min=1,max=64"`
	GrantParent   bool    `json:"grant_parent"`
}
