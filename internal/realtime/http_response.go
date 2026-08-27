package realtime

import (
	"encoding/json"
)

// NewHTTPCommandIdentity encodes one already-validated mutation DTO for the
// durable request identity. DurableIdempotency canonicalizes the JSON before it
// signs or compares the identity.
func NewHTTPCommandIdentity(principalID int64, method, route string, pathIDs, preconditions []CanonicalField, dto any) (HTTPCommandIdentity, error) {
	raw, err := json.Marshal(dto)
	if err != nil {
		return HTTPCommandIdentity{}, err
	}
	return HTTPCommandIdentity{
		PrincipalID:         principalID,
		Method:              method,
		RouteTemplate:       route,
		PathIDs:             pathIDs,
		CanonicalDTO:        raw,
		PreconditionHeaders: preconditions,
	}, nil
}

// CanonicalSuccessBody encodes the server's standard successful JSON envelope
// before a durable command commits it with its domain mutation.
func CanonicalSuccessBody(data any) (json.RawMessage, error) {
	body, err := json.Marshal(struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    any    `json:"data"`
	}{Code: 0, Message: "", Data: data})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}
