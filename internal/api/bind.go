package api

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"
)

// ValidationError is a structured request-validation failure rendered with
// CodeInvalidParameters and MessageInvalidRequest; data.fields maps each
// failing field name to its message. Field names identify the location, so
// no per-field codes exist.
type ValidationError struct {
	Fields map[string]string
}

// InvalidField returns a structured validation error for one request location.
// It is used for required headers and path/query values validated outside the
// JSON struct-tag binder.
func InvalidField(field, message string) *ValidationError {
	return &ValidationError{Fields: map[string]string{field: message}}
}

// Error returns the uniform client-facing validation message.
func (e *ValidationError) Error() string {
	return MessageInvalidRequest
}

// StatusCode implements echo.HTTPStatusCoder.
func (e *ValidationError) StatusCode() int {
	return http.StatusBadRequest
}

// Bind binds and validates a request payload. Binding failures become a
// global CodeMalformedRequest error (transport-level rejections such as 415
// pass through untouched), and validation failures become a ValidationError
// with per-field messages.
func Bind(c *echo.Context, dst any) error {
	if err := c.Bind(dst); err != nil {
		if httpErr, ok := errors.AsType[*echo.HTTPError](err); ok && httpErr.Code != http.StatusBadRequest {
			return err
		}
		return NewError(CodeMalformedRequest, http.StatusBadRequest, MessageMalformedRequest)
	}
	if err := c.Validate(dst); err != nil {
		if fieldErr, ok := err.(FieldErrors); ok {
			return &ValidationError{Fields: fieldErr.Fields()}
		}
		return err // validator misconfiguration; surfaces as 500
	}
	return nil
}
