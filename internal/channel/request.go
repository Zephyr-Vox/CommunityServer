// Package channel implements the HTTP control-plane slice for channel groups
// and channels.
package channel

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
