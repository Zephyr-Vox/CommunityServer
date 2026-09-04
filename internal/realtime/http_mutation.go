package realtime

import (
	"context"
	"encoding/json"

	"zephyr.vox/server/ce/internal/store"
)

// HTTPMutationCommand identifies one validated HTTP mutation that must persist
// a durable result before its state transaction commits.
type HTTPMutationCommand struct {
	Identity       HTTPCommandIdentity
	IdempotencyKey string
}

// RegistrationHTTPMutationCommand identifies the durable unauthenticated
// registration mutation. Its dedicated identity and store are separate from
// the first-owner activation exception because no principal exists yet.
type RegistrationHTTPMutationCommand struct {
	Identity       RegistrationCommandIdentity
	IdempotencyKey string
}

// HTTPMutationResponse is the canonical successful HTTP result that a
// sequenced domain mutation must persist before its transaction commits.
// Data is the unwrapped API envelope payload; a 204 response uses a nil Data.
type HTTPMutationResponse struct {
	Status  int
	Data    any
	Headers store.IdempotencyHeaders
}

// HTTPMutationResponseBuilder converts a domain result into the exact
// successful HTTP response that durable idempotency must replay.
type HTTPMutationResponseBuilder func(value any) (HTTPMutationResponse, error)

// HTTPMutationState receives the command metadata produced by a sequenced
// HTTP mutation. It is deliberately request-local and must not be shared
// between requests.
type HTTPMutationState struct {
	CommandID   int64
	Checkpoint  Checkpoint
	StateCursor string
	// Committed reports that the owning database transaction committed before
	// a later publication phase returned an error.
	Committed bool
	Replay    *DurableReplay
}

type httpMutationCommandContextKey struct{}
type registrationHTTPMutationCommandContextKey struct{}
type httpMutationResponseBuilderContextKey struct{}
type httpMutationStateContextKey struct{}

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

// NewRegistrationHTTPCommandIdentity creates the installation-scoped identity
// for registration. The request HMAC covers the complete canonical DTO,
// including sensitive fields, without persisting an activation-code digest.
func NewRegistrationHTTPCommandIdentity(installationID, method, route string, dto any) (RegistrationCommandIdentity, error) {
	raw, err := json.Marshal(dto)
	if err != nil {
		return RegistrationCommandIdentity{}, err
	}
	identity := RegistrationCommandIdentity{
		InstallationID: installationID,
		Method:         method, RouteTemplate: route, CanonicalDTO: raw,
	}
	if _, err := canonicalRegistrationCommandIdentity(identity); err != nil {
		return RegistrationCommandIdentity{}, err
	}
	return identity, nil
}

// NewRegistrationHTTPMutationCommand validates registration before its adapter
// performs durable replay lookup.
func NewRegistrationHTTPMutationCommand(identity RegistrationCommandIdentity, idempotencyKey string) (RegistrationHTTPMutationCommand, error) {
	if !IdempotencyKeyValid(idempotencyKey) {
		return RegistrationHTTPMutationCommand{}, ErrInvalidIdempotencyKey
	}
	if _, err := canonicalRegistrationCommandIdentity(identity); err != nil {
		return RegistrationHTTPMutationCommand{}, err
	}
	return RegistrationHTTPMutationCommand{Identity: identity, IdempotencyKey: idempotencyKey}, nil
}

// WithHTTPMutationCommand attaches one already validated durable command to a
// request context for the application service that owns its transaction.
func WithHTTPMutationCommand(ctx context.Context, command HTTPMutationCommand) context.Context {
	return context.WithValue(ctx, httpMutationCommandContextKey{}, command)
}

// WithRegistrationHTTPMutationCommand attaches registration to a request
// context before the account service enters the sequencer.
func WithRegistrationHTTPMutationCommand(ctx context.Context, command RegistrationHTTPMutationCommand) context.Context {
	return context.WithValue(ctx, registrationHTTPMutationCommandContextKey{}, command)
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

// RegistrationHTTPMutationCommandFromContext returns registration attached by
// an unauthenticated HTTP adapter, if any.
func RegistrationHTTPMutationCommandFromContext(ctx context.Context) (RegistrationHTTPMutationCommand, bool) {
	if ctx == nil {
		return RegistrationHTTPMutationCommand{}, false
	}
	command, ok := ctx.Value(registrationHTTPMutationCommandContextKey{}).(RegistrationHTTPMutationCommand)
	return command, ok
}

// WithHTTPMutationResponseBuilder attaches the response encoder used by the
// owning HTTP adapter to the command context.
func WithHTTPMutationResponseBuilder(ctx context.Context, builder HTTPMutationResponseBuilder) context.Context {
	return context.WithValue(ctx, httpMutationResponseBuilderContextKey{}, builder)
}

// HTTPMutationResponseBuilderFromContext returns the response encoder attached
// to a sequenced HTTP command, if any.
func HTTPMutationResponseBuilderFromContext(ctx context.Context) (HTTPMutationResponseBuilder, bool) {
	if ctx == nil {
		return nil, false
	}
	builder, ok := ctx.Value(httpMutationResponseBuilderContextKey{}).(HTTPMutationResponseBuilder)
	return builder, ok
}

// WithHTTPMutationState attaches a request-local output carrier for command
// ID, checkpoint/cursor and same-key in-flight replay metadata.
func WithHTTPMutationState(ctx context.Context, state *HTTPMutationState) context.Context {
	return context.WithValue(ctx, httpMutationStateContextKey{}, state)
}

// HTTPMutationStateFromContext returns the request-local output carrier, if
// the adapter installed one before submitting its mutation.
func HTTPMutationStateFromContext(ctx context.Context) (*HTTPMutationState, bool) {
	if ctx == nil {
		return nil, false
	}
	state, ok := ctx.Value(httpMutationStateContextKey{}).(*HTTPMutationState)
	return state, ok && state != nil
}
