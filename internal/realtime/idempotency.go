package realtime

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"regexp"
	"sort"
	"strings"

	"zephyr.vox/server/ce/internal/store"
)

// idempotencyKeyPattern matches the portable key grammar used by HTTP and WS
// command adapters. Keeping it local avoids coupling realtime policy to store.
var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// installationIdentityPattern matches the persisted 128-bit installation ID.
var installationIdentityPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// activationCodeHashPattern matches the digest used in the public bootstrap
// exception. Plaintext activation codes never cross this identity boundary.
var activationCodeHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var (
	// ErrInvalidIdempotencyKey is returned when a client retry key does not use
	// the protocol's fixed portable token grammar.
	ErrInvalidIdempotencyKey = errors.New("realtime: invalid idempotency key")
	// ErrInvalidRequestIdentity is returned when a command identity cannot be
	// normalized into the authenticated retry contract.
	ErrInvalidRequestIdentity = errors.New("realtime: invalid request identity")
	// ErrIdempotencyMismatch is returned when a retry key belongs to a different
	// canonical request identity than the completed or in-flight command.
	ErrIdempotencyMismatch = errors.New("realtime: idempotency key reused with different request")
	// ErrInvalidCommandResult is returned when a canonical replay result lacks a
	// valid status, JSON body, state checkpoint, or safe resource header value.
	ErrInvalidCommandResult = errors.New("realtime: invalid command result")
)

// IdempotencyKeyValid reports whether key satisfies the HTTP retry key grammar.
func IdempotencyKeyValid(key string) bool {
	return idempotencyKeyPattern.MatchString(key)
}

// CanonicalField is one named path ID or concurrency precondition included in
// a command identity. Names and values are sorted during canonicalization, so
// HTTP adapter map iteration cannot change the persisted identity.
type CanonicalField struct {
	Name  string
	Value string
}

// HTTPCommandIdentity is the complete stable identity of one sequenced HTTP
// mutation. CanonicalDTO must represent the already validated DTO; raw JSON
// byte order is intentionally not part of this contract.
type HTTPCommandIdentity struct {
	PrincipalID         int64
	Method              string
	RouteTemplate       string
	PathIDs             []CanonicalField
	CanonicalDTO        json.RawMessage
	PreconditionHeaders []CanonicalField
	ControlConnectionID string
}

// InstallationCommandIdentity is the stable identity of an unauthenticated
// installation-scoped mutation. Activation uses the SHA-256 activation-code
// digest; other public mutations use the fixed public namespace in
// http_mutation.go and rely on the keyed request HMAC to bind their full DTO.
type InstallationCommandIdentity struct {
	InstallationID     string
	ActivationCodeHash string
	Method             string
	RouteTemplate      string
	CanonicalDTO       json.RawMessage
}

// RequestIdentitySigner computes the HMAC of canonical authenticated request
// identities. Its key must remain stable across process restarts when durable
// idempotency records are enabled, and must never be returned to clients.
type RequestIdentitySigner struct {
	key []byte
}

// NewRequestIdentitySigner creates an identity signer from key. The key is
// copied and must contain at least 256 bits of application-controlled secret
// material so durable retries remain verifiable after a restart.
func NewRequestIdentitySigner(key []byte) (*RequestIdentitySigner, error) {
	if len(key) < sha256.Size {
		return nil, ErrInvalidRequestIdentity
	}
	return &RequestIdentitySigner{key: append([]byte(nil), key...)}, nil
}

// Sum returns the lowercase hexadecimal HMAC-SHA-256 of identity's canonical
// representation. The result is safe to store but is not a client credential.
func (s *RequestIdentitySigner) Sum(identity HTTPCommandIdentity) (string, error) {
	if s == nil || len(s.key) < sha256.Size {
		return "", ErrInvalidRequestIdentity
	}
	canonical, err := canonicalHTTPCommandIdentity(identity)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// DurableIdempotency provides process-restart-safe completed HTTP command
// lookup and persistence. Admit and Save receive one transaction-bound Stores
// so capacity is checked before, and the idempotency fact commits or rolls back
// with, its domain mutation.
type DurableIdempotency struct {
	stores *store.Stores
	signer *RequestIdentitySigner
}

// DurableActivationIdempotency provides restart-safe deduplication for the
// first-owner activation exception. It uses a separate store shape because the
// command creates the principal referenced by ordinary durable records.
type DurableActivationIdempotency struct {
	stores *store.Stores
	signer *RequestIdentitySigner
}

// ActivationCommandResult is the canonical response stored for a bootstrap
// activation. Checkpoint and StateCursor are persisted with the response when
// activation is executed through the StateMutationRuntime.
type ActivationCommandResult struct {
	CommandID   int64
	Status      int
	Body        json.RawMessage
	Headers     store.IdempotencyHeaders
	Checkpoint  Checkpoint
	StateCursor string
}

// ActivationReplay is the response reconstructed from a completed activation.
type ActivationReplay struct {
	CommandID   int64
	Status      int
	Body        json.RawMessage
	Headers     store.IdempotencyHeaders
	Checkpoint  Checkpoint
	StateCursor string
}

// activationStoredResult is the private durable representation used by the
// existing activation table. Keeping the API body nested preserves exact
// replay bytes while allowing checkpoint metadata to survive restarts without
// exposing it as part of the public response body.
type activationStoredResult struct {
	Body        json.RawMessage `json:"body"`
	Checkpoint  Checkpoint      `json:"checkpoint"`
	StateCursor string          `json:"state_cursor"`
}

// DurableReplay is the canonical response reconstructed from a completed
// durable command. SyncRequired suppresses old epoch checkpoint fields while
// preserving the original status, result and allowed resource headers.
type DurableReplay struct {
	CommandID    int64
	Status       int
	Body         json.RawMessage
	Headers      store.IdempotencyHeaders
	Checkpoint   Checkpoint
	StateCursor  string
	SyncRequired bool
}

// IdempotencyMismatchReplay returns the fixed API error emitted when an
// in-flight retry discovers that another request completed the same key with a
// different canonical identity.
func IdempotencyMismatchReplay() DurableReplay {
	return DurableReplay{
		Status: 409,
		Body:   json.RawMessage(`{"code":9,"message":"idempotency key reused with different request","data":null}`),
	}
}

// CanonicalCommandResult is the completed response stored or replayed by both
// durable and runtime idempotency layers. Body is normalized JSON; Headers only
// contains the resource headers permitted by the protocol retry contract.
type CanonicalCommandResult struct {
	CommandID   int64
	Status      int
	Body        json.RawMessage
	Headers     store.IdempotencyHeaders
	Checkpoint  Checkpoint
	StateCursor string
}

// NewDurableIdempotency creates durable retry support over stores and signer.
func NewDurableIdempotency(stores *store.Stores, signer *RequestIdentitySigner) (*DurableIdempotency, error) {
	if stores == nil || stores.Idempotency == nil || signer == nil {
		return nil, ErrInvalidRequestIdentity
	}
	return &DurableIdempotency{stores: stores, signer: signer}, nil
}

// NewDurableActivationIdempotency creates installation-scoped retry support.
func NewDurableActivationIdempotency(stores *store.Stores, signer *RequestIdentitySigner) (*DurableActivationIdempotency, error) {
	if stores == nil || stores.ActivationIdempotency == nil || signer == nil {
		return nil, ErrInvalidRequestIdentity
	}
	return &DurableActivationIdempotency{stores: stores, signer: signer}, nil
}

// Lookup returns a completed matching activation result or found=false. A
// matching idempotency key with a different code/request identity is reported
// as ErrIdempotencyMismatch before any activation state is inspected.
func (d *DurableActivationIdempotency) Lookup(ctx context.Context, identity InstallationCommandIdentity, idempotencyKey string) (replay ActivationReplay, found bool, err error) {
	if d == nil || !IdempotencyKeyValid(idempotencyKey) {
		return ActivationReplay{}, false, ErrInvalidRequestIdentity
	}
	requestHMAC, err := d.signer.SumInstallation(identity)
	if err != nil {
		return ActivationReplay{}, false, err
	}
	record, err := d.stores.ActivationIdempotency.Lookup(ctx, identity.InstallationID, idempotencyKey)
	if errors.Is(err, store.ErrNotFound) {
		return ActivationReplay{}, false, nil
	}
	if err != nil {
		return ActivationReplay{}, false, err
	}
	if !equalHexDigest(record.ActivationCodeHash, identity.ActivationCodeHash) || !equalHexDigest(record.RequestHMAC, requestHMAC) {
		return ActivationReplay{}, true, ErrIdempotencyMismatch
	}
	result, err := activationResultFromStoredBody(ActivationCommandResult{
		CommandID: record.CommandID,
		Status:    int(record.Status),
		Body:      record.ResultBody,
		Headers:   record.Headers,
	})
	if err != nil {
		return ActivationReplay{}, true, err
	}
	return ActivationReplay{
		CommandID:   result.CommandID,
		Status:      result.Status,
		Body:        append(json.RawMessage(nil), result.Body...),
		Headers:     result.Headers,
		Checkpoint:  result.Checkpoint,
		StateCursor: result.StateCursor,
	}, true, nil
}

// LookupPublic returns a completed installation-scoped public mutation and
// suppresses checkpoint metadata when the record belongs to an older process
// epoch. Public identities use the same durable table as activation because
// both commands run before an authenticated principal is available.
func (d *DurableActivationIdempotency) LookupPublic(ctx context.Context, identity InstallationCommandIdentity, idempotencyKey, currentEpoch string) (DurableReplay, bool, error) {
	replay, found, err := d.Lookup(ctx, identity, idempotencyKey)
	if err != nil || !found {
		return DurableReplay{}, found, err
	}
	result := DurableReplay{
		CommandID: replay.CommandID, Status: replay.Status, Body: replay.Body, Headers: replay.Headers,
		Checkpoint: replay.Checkpoint, StateCursor: replay.StateCursor,
	}
	if currentEpoch != "" && result.Checkpoint.StreamEpoch != "" && result.Checkpoint.StreamEpoch != currentEpoch {
		result.SyncRequired = true
		result.Checkpoint = Checkpoint{}
		result.StateCursor = ""
	}
	return result, true, nil
}

// Admit reserves a shared durable retry slot in the activation transaction.
func (d *DurableActivationIdempotency) Admit(ctx context.Context, txStores *store.Stores) error {
	if d == nil || txStores == nil || txStores.ActivationIdempotency == nil {
		return ErrInvalidRequestIdentity
	}
	return txStores.ActivationIdempotency.Admit(ctx)
}

// Save persists one activation response in the transaction that creates the
// first owner. The response never stores plaintext code or password fields.
func (d *DurableActivationIdempotency) Save(ctx context.Context, txStores *store.Stores, identity InstallationCommandIdentity, idempotencyKey string, result ActivationCommandResult) error {
	if d == nil || txStores == nil || txStores.ActivationIdempotency == nil || !IdempotencyKeyValid(idempotencyKey) {
		return ErrInvalidRequestIdentity
	}
	requestHMAC, err := d.signer.SumInstallation(identity)
	if err != nil {
		return err
	}
	result, err = canonicalizeActivationCommandResult(result)
	if err != nil {
		return err
	}
	body := result.Body
	if result.StateCursor != "" || result.Checkpoint.StreamEpoch != "" {
		stored, err := json.Marshal(activationStoredResult{
			Body: result.Body, Checkpoint: result.Checkpoint, StateCursor: result.StateCursor,
		})
		if err != nil {
			return err
		}
		body = stored
	}
	return txStores.ActivationIdempotency.Save(ctx, store.ActivationIdempotencyRecord{
		InstallationID:     identity.InstallationID,
		IdempotencyKey:     idempotencyKey,
		ActivationCodeHash: identity.ActivationCodeHash,
		RequestHMAC:        requestHMAC,
		CommandID:          result.CommandID,
		Status:             int64(result.Status),
		ResultBody:         body,
		Headers:            result.Headers,
	})
}

// SavePublic persists one public mutation response in the same transaction as
// its domain change. The installation-scoped record remains replayable even
// though the mutation creates or changes no authenticated principal.
func (d *DurableActivationIdempotency) SavePublic(ctx context.Context, txStores *store.Stores, identity InstallationCommandIdentity, idempotencyKey string, result CanonicalCommandResult) error {
	return d.Save(ctx, txStores, identity, idempotencyKey, ActivationCommandResult{
		CommandID: result.CommandID, Status: result.Status, Body: result.Body,
		Headers: result.Headers, Checkpoint: result.Checkpoint, StateCursor: result.StateCursor,
	})
}

// Lookup returns a completed matching retry result or found=false. A matching
// record from another stream epoch remains a valid command replay, but sets
// SyncRequired and deliberately omits obsolete cursor/checkpoint fields.
func (d *DurableIdempotency) Lookup(ctx context.Context, identity HTTPCommandIdentity, idempotencyKey, currentEpoch string) (replay DurableReplay, found bool, err error) {
	if d == nil || !IdempotencyKeyValid(idempotencyKey) || validateStreamEpoch(currentEpoch) != nil {
		return DurableReplay{}, false, ErrInvalidRequestIdentity
	}
	requestHMAC, err := d.signer.Sum(identity)
	if err != nil {
		return DurableReplay{}, false, err
	}
	record, err := d.stores.Idempotency.Lookup(ctx, identity.PrincipalID, idempotencyKey)
	if errors.Is(err, store.ErrNotFound) {
		return DurableReplay{}, false, nil
	}
	if err != nil {
		return DurableReplay{}, false, err
	}
	if record.Endpoint != commandEndpoint(identity) || !equalRequestHMAC(record.RequestHMAC, requestHMAC) {
		return DurableReplay{}, true, ErrIdempotencyMismatch
	}
	result, err := canonicalCommandResultFromRecord(*record)
	if err != nil {
		return DurableReplay{}, true, err
	}
	replay = DurableReplay{
		CommandID: result.CommandID,
		Status:    result.Status,
		Body:      append(json.RawMessage(nil), result.Body...),
		Headers:   result.Headers,
	}
	if result.Checkpoint.StreamEpoch != currentEpoch {
		replay.SyncRequired = true
		return replay, true, nil
	}
	replay.Checkpoint = result.Checkpoint
	replay.StateCursor = result.StateCursor
	return replay, true, nil
}

// Save persists a completed result using txStores after Admit has reserved its
// capacity. The transaction-bound store requirement guarantees a process crash
// after the domain commit still leaves one replayable result, while a failed
// mutation leaves neither fact behind.
func (d *DurableIdempotency) Save(ctx context.Context, txStores *store.Stores, identity HTTPCommandIdentity, idempotencyKey string, result CanonicalCommandResult) error {
	if d == nil || txStores == nil || txStores.Idempotency == nil || !IdempotencyKeyValid(idempotencyKey) {
		return ErrInvalidRequestIdentity
	}
	requestHMAC, err := d.signer.Sum(identity)
	if err != nil {
		return err
	}
	result, err = canonicalizeCommandResult(result)
	if err != nil {
		return err
	}
	return txStores.Idempotency.Save(ctx, store.CommandIdempotencyRecord{
		PrincipalID:    identity.PrincipalID,
		IdempotencyKey: idempotencyKey,
		Endpoint:       commandEndpoint(identity),
		RequestHMAC:    requestHMAC,
		CommandID:      result.CommandID,
		Status:         int64(result.Status),
		ResultBody:     result.Body,
		Headers:        result.Headers,
		StreamEpoch:    result.Checkpoint.StreamEpoch,
		GEID:           result.Checkpoint.GEID,
		StateCursor:    result.StateCursor,
	})
}

// Admit reserves one durable retry slot in txStores before a new command
// mutates domain data. The caller must call Save once in that same transaction
// after reserving its final publication result; a full window leaves the domain
// mutation unstarted and returns store.ErrCommandIdempotencyFull.
func (d *DurableIdempotency) Admit(ctx context.Context, txStores *store.Stores) error {
	if d == nil || txStores == nil || txStores.Idempotency == nil {
		return ErrInvalidRequestIdentity
	}
	return txStores.Idempotency.Admit(ctx)
}

// canonicalCommandResultFromRecord converts one store record through the same
// validation used before insertion, catching corruption before an HTTP replay.
func canonicalCommandResultFromRecord(record store.CommandIdempotencyRecord) (CanonicalCommandResult, error) {
	return canonicalizeCommandResult(CanonicalCommandResult{
		CommandID:   record.CommandID,
		Status:      int(record.Status),
		Body:        record.ResultBody,
		Headers:     record.Headers,
		Checkpoint:  Checkpoint{StreamEpoch: record.StreamEpoch, GEID: record.GEID},
		StateCursor: record.StateCursor,
	})
}

// canonicalizeCommandResult normalizes the JSON response and validates the
// state fields that future HTTP adapters copy into response headers.
func canonicalizeCommandResult(result CanonicalCommandResult) (CanonicalCommandResult, error) {
	if result.CommandID <= 0 || result.Status < 100 || result.Status > 599 || validateStreamEpoch(result.Checkpoint.StreamEpoch) != nil || result.StateCursor == "" || invalidResourceHeaders(result.Headers) {
		return CanonicalCommandResult{}, ErrInvalidCommandResult
	}
	if result.Status == 204 && len(result.Body) == 0 {
		// A 204 has no wire body, but storing canonical JSON null keeps the
		// database result shape uniform while HTTP replay emits no body again.
		result.Body = json.RawMessage("null")
	}
	body, err := canonicalJSONValue(result.Body)
	if err != nil {
		return CanonicalCommandResult{}, ErrInvalidCommandResult
	}
	result.Body = body
	return result, nil
}

// canonicalHTTPCommandIdentity normalizes every identity component using line
// delimiters and stable field ordering. Length prefixes make delimiter content
// unambiguous without requiring a new serialization dependency.
func canonicalHTTPCommandIdentity(identity HTTPCommandIdentity) ([]byte, error) {
	if identity.PrincipalID <= 0 || identity.Method == "" || identity.Method != strings.ToUpper(identity.Method) || identity.RouteTemplate == "" || len(identity.RouteTemplate) > 256 || hasControlCharacters(identity.RouteTemplate) || hasControlCharacters(identity.ControlConnectionID) {
		return nil, ErrInvalidRequestIdentity
	}
	dto, err := canonicalJSONValue(identity.CanonicalDTO)
	if err != nil {
		return nil, ErrInvalidRequestIdentity
	}
	pathIDs, err := canonicalFields(identity.PathIDs)
	if err != nil {
		return nil, err
	}
	preconditions, err := canonicalPreconditionHeaders(identity.PreconditionHeaders)
	if err != nil {
		return nil, err
	}
	var builder strings.Builder
	appendIdentityPart(&builder, "principal", fmt.Sprintf("%d", identity.PrincipalID))
	appendIdentityPart(&builder, "method", identity.Method)
	appendIdentityPart(&builder, "route", identity.RouteTemplate)
	for _, field := range pathIDs {
		appendIdentityPart(&builder, "path:"+field.Name, field.Value)
	}
	appendIdentityPart(&builder, "dto", string(dto))
	for _, field := range preconditions {
		appendIdentityPart(&builder, "precondition:"+field.Name, field.Value)
	}
	appendIdentityPart(&builder, "control_connection", identity.ControlConnectionID)
	return []byte(builder.String()), nil
}

// canonicalInstallationCommandIdentity normalizes the bootstrap identity while
// keeping its code/password values out of durable storage.
func canonicalInstallationCommandIdentity(identity InstallationCommandIdentity) ([]byte, error) {
	if !installationIdentityPattern.MatchString(identity.InstallationID) || !activationCodeHashPattern.MatchString(identity.ActivationCodeHash) || identity.Method == "" || identity.Method != strings.ToUpper(identity.Method) || identity.RouteTemplate == "" || len(identity.RouteTemplate) > 256 || hasControlCharacters(identity.RouteTemplate) {
		return nil, ErrInvalidRequestIdentity
	}
	dto, err := canonicalJSONValue(identity.CanonicalDTO)
	if err != nil {
		return nil, ErrInvalidRequestIdentity
	}
	var builder strings.Builder
	appendIdentityPart(&builder, "installation", identity.InstallationID)
	appendIdentityPart(&builder, "activation_code_hash", identity.ActivationCodeHash)
	appendIdentityPart(&builder, "method", identity.Method)
	appendIdentityPart(&builder, "route", identity.RouteTemplate)
	appendIdentityPart(&builder, "dto", string(dto))
	return []byte(builder.String()), nil
}

// SumInstallation returns the HMAC of an installation-scoped activation
// identity. The canonical bytes include the activation-code digest and
// validated account DTO; durable storage receives only the keyed digest.
func (s *RequestIdentitySigner) SumInstallation(identity InstallationCommandIdentity) (string, error) {
	if s == nil || len(s.key) < sha256.Size {
		return "", ErrInvalidRequestIdentity
	}
	canonical, err := canonicalInstallationCommandIdentity(identity)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// canonicalizeActivationCommandResult normalizes the JSON response and checks
// the limited headers retained for a public activation replay.
func canonicalizeActivationCommandResult(result ActivationCommandResult) (ActivationCommandResult, error) {
	if result.CommandID <= 0 || result.Status < 100 || result.Status > 599 || invalidResourceHeaders(result.Headers) {
		return ActivationCommandResult{}, ErrInvalidCommandResult
	}
	if result.Checkpoint.StreamEpoch != "" {
		if validateStreamEpoch(result.Checkpoint.StreamEpoch) != nil || result.StateCursor == "" {
			return ActivationCommandResult{}, ErrInvalidCommandResult
		}
	} else if result.StateCursor != "" {
		return ActivationCommandResult{}, ErrInvalidCommandResult
	}
	if result.Status == 204 && len(result.Body) == 0 {
		result.Body = json.RawMessage("null")
	}
	body, err := canonicalJSONValue(result.Body)
	if err != nil {
		return ActivationCommandResult{}, ErrInvalidCommandResult
	}
	result.Body = body
	return result, nil
}

// activationResultFromStoredBody unwraps new activation records and accepts
// older records that predate checkpoint persistence.
func activationResultFromStoredBody(result ActivationCommandResult) (ActivationCommandResult, error) {
	var stored activationStoredResult
	if err := json.Unmarshal(result.Body, &stored); err == nil && len(stored.Body) > 0 {
		result.Body = stored.Body
		result.Checkpoint = stored.Checkpoint
		result.StateCursor = stored.StateCursor
	}
	return canonicalizeActivationCommandResult(result)
}

// canonicalFields sorts named command identity components and rejects duplicate
// names. Adapters must merge duplicate HTTP headers before this boundary.
func canonicalFields(fields []CanonicalField) ([]CanonicalField, error) {
	cloned := append([]CanonicalField(nil), fields...)
	for _, field := range cloned {
		if field.Name == "" || hasControlCharacters(field.Name) || hasControlCharacters(field.Value) {
			return nil, ErrInvalidRequestIdentity
		}
	}
	sort.Slice(cloned, func(i, j int) bool {
		if cloned[i].Name != cloned[j].Name {
			return cloned[i].Name < cloned[j].Name
		}
		return cloned[i].Value < cloned[j].Value
	})
	for i := 1; i < len(cloned); i++ {
		if cloned[i-1].Name == cloned[i].Name {
			return nil, ErrInvalidRequestIdentity
		}
	}
	return cloned, nil
}

// canonicalPreconditionHeaders applies HTTP's case-insensitive header-name
// rule before using preconditions in a retry identity. Values are kept exact:
// request validation owns any header-specific whitespace normalization.
func canonicalPreconditionHeaders(headers []CanonicalField) ([]CanonicalField, error) {
	canonical := append([]CanonicalField(nil), headers...)
	for i := range canonical {
		if !validHTTPHeaderName(canonical[i].Name) {
			return nil, ErrInvalidRequestIdentity
		}
		canonical[i].Name = textproto.CanonicalMIMEHeaderKey(canonical[i].Name)
	}
	return canonicalFields(canonical)
}

// validHTTPHeaderName accepts the RFC token grammar used for HTTP field names.
func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			continue
		}
		return false
	}
	return true
}

// appendIdentityPart writes one unambiguous length-prefixed canonical part.
func appendIdentityPart(builder *strings.Builder, name, value string) {
	fmt.Fprintf(builder, "%d:%s=%d:%s\n", len(name), name, len(value), value)
}

// canonicalJSONValue validates one JSON value and re-encodes it with stable
// object key order. UseNumber avoids collapsing large validated ID values.
func canonicalJSONValue(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidRequestIdentity
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

// CanonicalJSON normalizes one JSON value with stable object key order for an
// HTTP response that must match its durable replay byte-for-byte.
func CanonicalJSON(raw json.RawMessage) (json.RawMessage, error) {
	return canonicalJSONValue(raw)
}

// commandEndpoint is the human-inspectable durable endpoint field. The HMAC
// includes all remaining identity inputs, while this cleartext value permits a
// fast mismatch diagnosis without exposing request bodies.
func commandEndpoint(identity HTTPCommandIdentity) string {
	return identity.Method + " " + identity.RouteTemplate
}

// equalRequestHMAC compares fixed hexadecimal digest text in constant time.
func equalRequestHMAC(left, right string) bool {
	return equalHexDigest(left, right)
}

// equalHexDigest compares fixed hexadecimal digests in constant time.
func equalHexDigest(left, right string) bool {
	leftBytes, leftErr := hex.DecodeString(left)
	rightBytes, rightErr := hex.DecodeString(right)
	return leftErr == nil && rightErr == nil && hmac.Equal(leftBytes, rightBytes)
}

// invalidResourceHeaders detects forbidden line breaks in persisted replay
// headers, preventing command results from becoming header injection sources.
func invalidResourceHeaders(headers store.IdempotencyHeaders) bool {
	return hasControlCharacters(headers.ETag) || hasControlCharacters(headers.ParentETag) || hasControlCharacters(headers.Location) || hasControlCharacters(headers.CacheControl) || hasControlCharacters(headers.Pragma)
}

// hasControlCharacters rejects CR and LF, which are invalid in canonical
// identity values and replayable HTTP header values.
func hasControlCharacters(value string) bool {
	return strings.ContainsAny(value, "\r\n")
}
