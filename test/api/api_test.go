package api_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/validation"
)

type sampleRequest struct {
	Username string `json:"username" validate:"required,username"`
	Password string `json:"password" validate:"required,password"`
}

type echoData struct {
	Username string `json:"username"`
}

func newApp(t *testing.T) *echo.Echo {
	t.Helper()
	app := echo.New()
	app.Validator = validation.New()
	app.HTTPErrorHandler = api.NewErrorHandler(slog.New(slog.NewTextHandler(io.Discard, nil)))
	return app
}

func postJSON(t *testing.T, app *echo.Echo, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	return resp
}

func TestBindValid(t *testing.T) {
	app := newApp(t)
	app.POST("/", func(c *echo.Context) error {
		var req sampleRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		return api.OK(c, http.StatusOK, echoData{Username: req.Username})
	})

	rec := postJSON(t, app, "/", `{"username":"alice01","password":"secret123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	resp := decodeEnvelope(t, rec)
	if resp["code"] != float64(api.CodeOK) || resp["message"] != "" {
		t.Fatalf("envelope = %+v, want success", resp)
	}
	data, ok := resp["data"].(map[string]any)
	if !ok || data["username"] != "alice01" {
		t.Fatalf("data = %v, want username", resp["data"])
	}
}

func TestBindValidationCarriesFieldMessages(t *testing.T) {
	app := newApp(t)
	app.POST("/", func(c *echo.Context) error {
		var req sampleRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		return c.NoContent(http.StatusOK)
	})

	rec := postJSON(t, app, "/", `{"username":"x","password":"secret"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	resp := decodeEnvelope(t, rec)
	if resp["code"] != float64(api.CodeInvalidParameters) {
		t.Fatalf("code = %v, want %d", resp["code"], api.CodeInvalidParameters)
	}
	if resp["message"] != api.MessageInvalidRequest {
		t.Fatalf("message = %v, want uniform invalid request parameters", resp["message"])
	}
	fields, ok := resp["data"].(map[string]any)["fields"].(map[string]any)
	if !ok {
		t.Fatalf("data.fields missing: %v", resp["data"])
	}
	if username, _ := fields["username"].(string); username == "" {
		t.Fatalf("username message missing: %v", fields)
	}
	if password, _ := fields["password"].(string); password == "" {
		t.Fatalf("password message missing: %v", fields)
	}
}

func TestBindMalformedRequestUsesGlobalCode(t *testing.T) {
	app := newApp(t)
	app.POST("/", func(c *echo.Context) error {
		var req sampleRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		return c.NoContent(http.StatusOK)
	})

	rec := postJSON(t, app, "/", `{`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if resp := decodeEnvelope(t, rec); resp["code"] != float64(api.CodeMalformedRequest) {
		t.Fatalf("code = %v, want %d", resp["code"], api.CodeMalformedRequest)
	}
}

func TestBindUnsupportedMediaTypePassesThrough(t *testing.T) {
	app := newApp(t)
	app.POST("/", func(c *echo.Context) error {
		var req sampleRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username":"alice01","password":"secret123"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMETextPlain)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rec.Code)
	}
	if resp := decodeEnvelope(t, rec); resp["code"] != float64(api.CodeUnsupportedMedia) {
		t.Fatalf("code = %v, want %d", resp["code"], api.CodeUnsupportedMedia)
	}
}

func TestErrorHandlerKeepsBusinessCode(t *testing.T) {
	app := newApp(t)
	app.GET("/", func(c *echo.Context) error {
		return api.NewError(7, http.StatusConflict, "username taken")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	resp := decodeEnvelope(t, rec)
	if resp["code"] != float64(7) || resp["message"] != "username taken" {
		t.Fatalf("envelope = %+v, want code 7", resp)
	}
}

func TestErrorHandlerUsesGenericCodeForMiddlewareErrors(t *testing.T) {
	app := newApp(t)
	app.GET("/", func(c *echo.Context) error {
		return echo.ErrUnauthorized
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	resp := decodeEnvelope(t, rec)
	if resp["code"] != float64(api.CodeUnauthorized) {
		t.Fatalf("code = %v, want %d", resp["code"], api.CodeUnauthorized)
	}
}

func TestErrorHandlerMethodNotAllowed(t *testing.T) {
	app := newApp(t)
	app.GET("/", func(c *echo.Context) error {
		return echo.ErrMethodNotAllowed
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	resp := decodeEnvelope(t, rec)
	if resp["code"] != float64(api.CodeMethodNotAllowed) {
		t.Fatalf("code = %v, want %d", resp["code"], api.CodeMethodNotAllowed)
	}
}

func TestErrorHandlerUnexpectedIs500Generic(t *testing.T) {
	app := newApp(t)
	app.GET("/", func(c *echo.Context) error {
		return errors.New("boom")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	resp := decodeEnvelope(t, rec)
	if resp["code"] != float64(api.CodeInternal) {
		t.Fatalf("code = %v, want %d", resp["code"], api.CodeInternal)
	}
}

func TestErrorHandlerLogsUnhandledWithAPIModule(t *testing.T) {
	var buf bytes.Buffer
	app := echo.New()
	app.HTTPErrorHandler = api.NewErrorHandler(slog.New(slog.NewTextHandler(&buf, nil)))
	app.GET("/boom", func(c *echo.Context) error { return errors.New("boom") })

	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(buf.String(), "unhandled error") || !strings.Contains(buf.String(), "module=api") {
		t.Fatalf("unhandled error not logged with api module: %q", buf.String())
	}
}
