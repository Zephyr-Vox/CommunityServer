package presence

// Request payloads for the presence endpoints.

type heartbeatRequest struct {
	// Allowed values are validated by the service (single source of truth:
	// RealStatusOnline / RealStatusAway), so the tag only requires presence.
	Status string `json:"status" validate:"required"`
}
