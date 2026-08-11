package auth

// Request payloads for the authentication endpoints.

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	DeviceID string `json:"device_id"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}
