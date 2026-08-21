package realtime

import (
	"context"
	"errors"
)

// ErrInvalidMutationGate is returned when a persistent mutation gate cannot
// accept an acquisition request.
var ErrInvalidMutationGate = errors.New("realtime: invalid persistent mutation gate")

// MutationGate serializes persistent writes with the following StateStore
// publication. Domain services acquire it before opening their database
// transaction and retain it until the committed change has reached the ring,
// preventing a later SQLite commit from being represented by an earlier GEID.
// It is process-local; SQLite remains the cross-process authority.
type MutationGate struct {
	permit chan struct{}
}

// NewMutationGate creates an unlocked process-local persistent mutation gate.
func NewMutationGate() *MutationGate {
	gate := &MutationGate{permit: make(chan struct{}, 1)}
	gate.permit <- struct{}{}
	return gate
}

// Acquire waits for one mutation slot or returns ctx's cancellation before any
// database write begins. The returned release function must be called exactly
// once after the mutation's state publication has completed.
func (g *MutationGate) Acquire(ctx context.Context) (func(), error) {
	if g == nil || ctx == nil {
		return nil, ErrInvalidMutationGate
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.permit:
	}
	return func() { g.permit <- struct{}{} }, nil
}
