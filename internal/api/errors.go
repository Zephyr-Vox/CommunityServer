package api

// Error is a business error. It carries the HTTP status for transport
// semantics and the endpoint-local code clients match against.
type Error struct {
	Code     int
	HTTPCode int
	Message  string
	err      error
}

// NewError returns an Error with the given business code, HTTP status and
// client-facing message.
func NewError(code, httpCode int, message string) *Error {
	return &Error{Code: code, HTTPCode: httpCode, Message: message}
}

func (e *Error) Error() string {
	if e.err != nil {
		return e.Message + ": " + e.err.Error()
	}
	return e.Message
}

// Unwrap exposes the underlying cause, if any.
func (e *Error) Unwrap() error {
	return e.err
}

// StatusCode implements echo.HTTPStatusCoder.
func (e *Error) StatusCode() int {
	return e.HTTPCode
}

// FieldErrors is implemented by validation errors that carry one message per
// request field; the central error handler folds them into the message.
type FieldErrors interface {
	Fields() map[string]string
}
