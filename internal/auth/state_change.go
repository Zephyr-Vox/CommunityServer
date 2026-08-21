package auth

import "context"

// StateChange identifies an account mutation that must be reflected in the
// application-owned realtime projection after its database transaction commits.
// It intentionally contains only public synchronization facts, never password,
// token, ban reason, or other credential/admin-only data.
type StateChange struct {
	EventType string
	UserID    int64
}

// StateChangePublisher serializes a committed account change into the
// application realtime projection. Server assembly supplies it; standalone auth
// tests and HTTP-only embeddings may leave it nil.
type StateChangePublisher func(context.Context, StateChange) error
