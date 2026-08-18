package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v5"
)

// NewErrorHandler returns the Echo error handler wired to logger. Every error
// that reaches it is rendered as an Envelope: business errors keep their own
// endpoint-local code; everything without one (stray validation errors,
// middleware rejections, unexpected failures) uses the shared 1000 block.
// Unhandled errors are logged with the [api] module before answering 500.
func NewErrorHandler(logger *slog.Logger) echo.HTTPErrorHandler {
	return func(c *echo.Context, err error) {
		if apiErr, ok := errors.AsType[*Error](err); ok {
			_ = c.JSON(apiErr.HTTPCode, Envelope{Code: apiErr.Code, Message: apiErr.Message})
			return
		}
		if valErr, ok := errors.AsType[*ValidationError](err); ok {
			_ = c.JSON(http.StatusBadRequest, Envelope{
				Code:    CodeInvalidParameters,
				Message: valErr.Error(),
				Data:    map[string]any{"fields": valErr.Fields},
			})
			return
		}
		if fieldErr, ok := err.(FieldErrors); ok {
			_ = c.JSON(http.StatusBadRequest, Envelope{
				Code:    CodeInvalidParameters,
				Message: MessageInvalidRequest,
				Data:    map[string]any{"fields": fieldErr.Fields()},
			})
			return
		}

		var sc echo.HTTPStatusCoder
		if errors.As(err, &sc) {
			status := sc.StatusCode()
			if status != 0 {
				message := http.StatusText(status)
				if httpErr, ok := errors.AsType[*echo.HTTPError](err); ok && httpErr.Message != "" {
					message = httpErr.Message
				}
				_ = c.JSON(status, Envelope{Code: codeForStatus(status), Message: message})
				return
			}
		}

		logger.With("module", "api").Error("unhandled error: " + err.Error())
		_ = c.JSON(http.StatusInternalServerError, Envelope{
			Code:    CodeInternal,
			Message: http.StatusText(http.StatusInternalServerError),
		})
	}
}

// codeForStatus maps an HTTP status to its shared API error code.
func codeForStatus(status int) int {
	switch status {
	case http.StatusBadRequest:
		return CodeInvalidParameters
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusMethodNotAllowed:
		return CodeMethodNotAllowed
	case http.StatusRequestEntityTooLarge:
		return CodePayloadTooLarge
	case http.StatusUnsupportedMediaType:
		return CodeUnsupportedMedia
	case http.StatusTooManyRequests:
		return CodeRateLimited
	default:
		return CodeInternal
	}
}
