package auth

import "zephyr.vox/server/ce/internal/db"

// Response payloads for the authentication endpoints.

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type userResponse struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
}

type loginResponse struct {
	tokenResponse
	User userResponse `json:"user"`
}

type userEnvelope struct {
	User userResponse `json:"user"`
}

type inviteResponse struct {
	ID        int64  `json:"id"`
	Role      string `json:"role"`
	UsesLeft  int64  `json:"uses_left"`
	ExpiresAt *int64 `json:"expires_at"`
	CreatedAt int64  `json:"created_at"`
}

type inviteCreateResponse struct {
	Code   string         `json:"code"`
	Invite inviteResponse `json:"invite"`
}

type meResponse struct {
	userResponse
	Permissions []string `json:"permissions"`
}

type statusResponse struct {
	RegistrationMode   string `json:"registration_mode"`
	ActivationRequired bool   `json:"activation_required"`
}

func newUserResponse(u *db.User) userResponse {
	avatar := ""
	if u.Avatar.Valid {
		avatar = u.Avatar.String
	}
	return userResponse{
		ID:       u.ID,
		Username: u.Username,
		Nickname: u.Nickname,
		Avatar:   avatar,
	}
}

func newInviteResponse(inv *db.Invite) inviteResponse {
	var expiresAt *int64
	if inv.ExpiresAt.Valid {
		v := inv.ExpiresAt.Int64
		expiresAt = &v
	}
	return inviteResponse{
		ID:        inv.ID,
		Role:      inv.Role,
		UsesLeft:  inv.UsesLeft,
		ExpiresAt: expiresAt,
		CreatedAt: inv.CreatedAt,
	}
}

func optionalInt64(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}
