package api

// Uniform messages for global request errors; per-field messages live in
// data.fields.
const (
	MessageInvalidRequest   = "invalid request parameters"
	MessageMalformedRequest = "malformed request"
)

// Global codes, ordered by HTTP status. Endpoint business codes occupy
// 1..999; this block starts at 1000 so the two ranges can never overlap.
const (
	CodeInvalidParameters = 1000 // 400: field validation failed; see data.fields
	CodeMalformedRequest  = 1001 // 400: request body could not be parsed or bound
	CodeUnauthorized      = 1002 // 401: missing or invalid access token
	CodeForbidden         = 1003 // 403: authenticated but not allowed
	CodeNotFound          = 1004 // 404: resource does not exist
	CodeMethodNotAllowed  = 1005 // 405: method not allowed for the route
	CodePayloadTooLarge   = 1006 // 413: request body too large
	CodeUnsupportedMedia  = 1007 // 415: unsupported content type
	CodeRateLimited       = 1008 // 429: too many requests
	CodeInternal          = 1009 // 500+: unexpected server error
)
