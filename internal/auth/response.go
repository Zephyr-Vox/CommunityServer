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
	RoleKey   string `json:"role_key"`
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

type userDetailResponse struct {
	userResponse
	Roles       []string `json:"roles"`
	Banned      bool     `json:"banned"`
	LastLoginAt *int64   `json:"last_login_at"`
	CreatedAt   int64    `json:"created_at"`
}

// newUserDetailResponse converts a user and its roles into the admin response.
func newUserDetailResponse(u *UserWithRoles) userDetailResponse {
	var lastLoginAt *int64
	if u.User.LastLoginAt.Valid {
		v := u.User.LastLoginAt.Int64
		lastLoginAt = &v
	}
	return userDetailResponse{
		userResponse: newUserResponse(u.User),
		Roles:        u.Roles,
		Banned:       u.User.BannedAt.Valid,
		LastLoginAt:  lastLoginAt,
		CreatedAt:    u.User.CreatedAt,
	}
}

// newUserResponse converts a database user into its public response shape.
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

// newInviteResponse converts a database invite into its response shape.
func newInviteResponse(inv *db.Invite) inviteResponse {
	var expiresAt *int64
	if inv.ExpiresAt.Valid {
		v := inv.ExpiresAt.Int64
		expiresAt = &v
	}
	return inviteResponse{
		ID:        inv.ID,
		RoleKey:   inv.RoleKey,
		UsesLeft:  inv.UsesLeft,
		ExpiresAt: expiresAt,
		CreatedAt: inv.CreatedAt,
	}
}

// optionalInt64 returns nil for zero and a pointer for every other value.
func optionalInt64(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}
