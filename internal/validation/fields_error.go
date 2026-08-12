package validation

import (
	"fmt"
	"net/http"
)

// FieldsError describes a 400 validation failure with one message per field.
// It implements HTTPStatusCoder and the api.FieldErrors interface; the
// central api.ErrorHandler folds the messages into the response envelope.
type FieldsError struct {
	fields map[string]string
}

// Error returns a short summary of the failure.
func (e *FieldsError) Error() string {
	return fmt.Sprintf("validation failed for %d field(s)", len(e.fields))
}

// StatusCode implements echo.HTTPStatusCoder.
func (e *FieldsError) StatusCode() int {
	return http.StatusBadRequest
}

// Fields exposes the per-field messages so the central error handler can
// fold them into the envelope message.
func (e *FieldsError) Fields() map[string]string {
	return e.fields
}
