package realtime

import "context"

// HTTPMutationCommand identifies one validated HTTP mutation that must persist
// a durable result before its state transaction commits.
type HTTPMutationCommand struct {
	Identity       HTTPCommandIdentity
	IdempotencyKey string
}

type httpMutationCommandContextKey struct{}

// NewHTTPMutationCommand validates the retry key and canonical identity shape
// before an HTTP adapter looks up a completed durable response.
func NewHTTPMutationCommand(identity HTTPCommandIdentity, idempotencyKey string) (HTTPMutationCommand, error) {
	if !IdempotencyKeyValid(idempotencyKey) {
		return HTTPMutationCommand{}, ErrInvalidIdempotencyKey
	}
	if _, err := canonicalHTTPCommandIdentity(identity); err != nil {
		return HTTPMutationCommand{}, err
	}
	return HTTPMutationCommand{Identity: identity, IdempotencyKey: idempotencyKey}, nil
}

// WithHTTPMutationCommand attaches one already validated durable command to a
// request context for the application service that owns its transaction.
func WithHTTPMutationCommand(ctx context.Context, command HTTPMutationCommand) context.Context {
	return context.WithValue(ctx, httpMutationCommandContextKey{}, command)
}

// HTTPMutationCommandFromContext returns the durable command attached by an
// HTTP adapter, or false for non-HTTP callers and focused service tests.
func HTTPMutationCommandFromContext(ctx context.Context) (HTTPMutationCommand, bool) {
	if ctx == nil {
		return HTTPMutationCommand{}, false
	}
	command, ok := ctx.Value(httpMutationCommandContextKey{}).(HTTPMutationCommand)
	return command, ok
}
