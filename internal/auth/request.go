package auth

// Request payloads for the authentication endpoints.

type loginRequest struct {
	Username string `json:"username" validate:"required,username"`
	Password string `json:"password" validate:"required"`
	DeviceID string `json:"device_id" validate:"required,max=128"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type registerRequest struct {
	Username string `json:"username" validate:"required,username"`
	Password string `json:"password" validate:"required,password"`
	Nickname string `json:"nickname" validate:"omitempty,max=32"`
	Invite   string `json:"invite" validate:"omitempty,invite_code"`
}

type activateRequest struct {
	Code     string `json:"code" validate:"required,activation_code"`
	Username string `json:"username" validate:"required,username"`
	Password string `json:"password" validate:"required,password"`
	Nickname string `json:"nickname" validate:"omitempty,max=32"`
}

// activationIdentityRequest is the validated, code-free DTO hashed into the
// first-owner idempotency identity. Password remains only in the in-memory
// request while the HMAC is computed and is never persisted.
type activationIdentityRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Nickname string `json:"nickname"`
}

type inviteCreateRequest struct {
	Role      string `json:"role" validate:"omitempty,max=64"`
	Uses      int64  `json:"uses" validate:"omitempty,min=1"`
	ExpiresAt int64  `json:"expires_at" validate:"omitempty,min=1"`
}

type updateProfileRequest struct {
	Nickname string `json:"nickname" validate:"omitempty,max=32"`
}

type resetPasswordRequest struct {
	Password string `json:"password" validate:"required,password"`
}

type changeOwnPasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,password"`
}
