package auth

import "context"

// StateChange identifies an account mutation that must be reflected in the
// application-owned realtime projection after its database transaction commits.
// It intentionally contains only public synchronization facts, never password,
// token, ban reason, or other credential/admin-only data.
type StateChange struct {
	EventType string
	UserID    int64
	CommandID int64
}

// StateChangePublisher serializes a committed account change into the
// application realtime projection. Server assembly supplies it; standalone auth
// tests and HTTP-only embeddings may leave it nil.
type StateChangePublisher func(context.Context, StateChange) error

// MutationGate serializes one persistent account write with its following
// in-process state publication. Server assembly shares one gate across every
// domain that changes the realtime persistent projection.
type MutationGate interface {
	Acquire(context.Context) (func(), error)
}

// acquireMutation returns a no-op release when realtime assembly has not
// installed a gate, preserving standalone service behavior in focused tests.
func acquireMutation(ctx context.Context, gate MutationGate) (func(), error) {
	if gate == nil {
		return func() {}, nil
	}
	return gate.Acquire(ctx)
}
