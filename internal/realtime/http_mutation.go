package realtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"zephyr.vox/server/ce/internal/store"
)

// HTTPMutationCommand identifies one validated HTTP mutation that must persist
// a durable result before its state transaction commits.
type HTTPMutationCommand struct {
	Identity       HTTPCommandIdentity
	IdempotencyKey string
}

// PublicHTTPMutationCommand identifies a durable unauthenticated mutation
// whose identity is installation-scoped. Registration uses this shape because
// no principal exists until its transaction creates the new user.
type PublicHTTPMutationCommand struct {
	Identity       InstallationCommandIdentity
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
	Replay      *DurableReplay
}

type httpMutationCommandContextKey struct{}
type publicHTTPMutationCommandContextKey struct{}
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

// NewPublicHTTPCommandIdentity creates the installation-scoped identity for a
// public mutation. The derived code-hash slot is an internal stable namespace
// discriminator; unlike activation it is not a credential supplied by the
// caller.
func NewPublicHTTPCommandIdentity(installationID, method, route string, dto any) (InstallationCommandIdentity, error) {
	raw, err := json.Marshal(dto)
	if err != nil {
		return InstallationCommandIdentity{}, err
	}
	identity := InstallationCommandIdentity{
		InstallationID:     installationID,
		ActivationCodeHash: strings.Repeat("0", 64),
		Method:             method, RouteTemplate: route, CanonicalDTO: raw,
	}
	canonical, err := canonicalInstallationCommandIdentity(identity)
	if err != nil {
		return InstallationCommandIdentity{}, err
	}
	digest := sha256.Sum256(canonical)
	identity.ActivationCodeHash = hex.EncodeToString(digest[:])
	return identity, nil
}

// NewPublicHTTPMutationCommand validates one installation-scoped public
// mutation before its adapter performs durable replay lookup.
func NewPublicHTTPMutationCommand(identity InstallationCommandIdentity, idempotencyKey string) (PublicHTTPMutationCommand, error) {
	if !IdempotencyKeyValid(idempotencyKey) {
		return PublicHTTPMutationCommand{}, ErrInvalidIdempotencyKey
	}
	if _, err := canonicalInstallationCommandIdentity(identity); err != nil {
		return PublicHTTPMutationCommand{}, err
	}
	return PublicHTTPMutationCommand{Identity: identity, IdempotencyKey: idempotencyKey}, nil
}

// WithHTTPMutationCommand attaches one already validated durable command to a
// request context for the application service that owns its transaction.
func WithHTTPMutationCommand(ctx context.Context, command HTTPMutationCommand) context.Context {
	return context.WithValue(ctx, httpMutationCommandContextKey{}, command)
}

// WithPublicHTTPMutationCommand attaches an installation-scoped public
// mutation to a request context.
func WithPublicHTTPMutationCommand(ctx context.Context, command PublicHTTPMutationCommand) context.Context {
	return context.WithValue(ctx, publicHTTPMutationCommandContextKey{}, command)
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

// PublicHTTPMutationCommandFromContext returns a public mutation attached by
// an unauthenticated HTTP adapter, if any.
func PublicHTTPMutationCommandFromContext(ctx context.Context) (PublicHTTPMutationCommand, bool) {
	if ctx == nil {
		return PublicHTTPMutationCommand{}, false
	}
	command, ok := ctx.Value(publicHTTPMutationCommandContextKey{}).(PublicHTTPMutationCommand)
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
