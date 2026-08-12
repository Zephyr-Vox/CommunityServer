package oss_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/oss"
)

func newHandlerApp(t *testing.T, e *env) *echo.Echo {
	t.Helper()
	app := echo.New()
	app.HTTPErrorHandler = api.ErrorHandler
	h, err := e.objects.GetHandler("avatars")
	if err != nil {
		t.Fatal(err)
	}
	app.GET("/avatar/:file", h)
	return app
}

func get(t *testing.T, app *echo.Echo, path string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if header != nil {
		req.Header = header
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func envelopeCode(t *testing.T, rec *httptest.ResponseRecorder) int {
	t.Helper()
	var env struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	return env.Code
}

func TestGetHandlerServesObject(t *testing.T) {
	e := newEnv(t)
	app := newHandlerApp(t, e)

	body := "image-bytes"
	if _, err := e.objects.Put(t.Context(), "avatars", "1.png", strings.NewReader(body),
		oss.PutOptions{ContentType: "image/png"}); err != nil {
		t.Fatal(err)
	}

	rec := get(t, app, "/avatar/1.png", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("Content-Type = %q, want image/png", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Content-Length") != "11" {
		t.Fatalf("Content-Length = %q, want 11", rec.Header().Get("Content-Length"))
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", rec.Header().Get("X-Content-Type-Options"))
	}
	if rec.Body.String() != body {
		t.Fatalf("body = %q, want %q", rec.Body.String(), body)
	}
}

func TestGetHandlerMissingObjectIsNotFound(t *testing.T) {
	e := newEnv(t)
	app := newHandlerApp(t, e)

	rec := get(t, app, "/avatar/nope.png", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if code := envelopeCode(t, rec); code != api.CodeNotFound {
		t.Fatalf("code = %d, want %d", code, api.CodeNotFound)
	}
}

func TestGetHandlerInvalidNameIsNotFound(t *testing.T) {
	e := newEnv(t)
	app := newHandlerApp(t, e)

	rec := get(t, app, "/avatar/..", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if code := envelopeCode(t, rec); code != api.CodeNotFound {
		t.Fatalf("code = %d, want %d", code, api.CodeNotFound)
	}
}

func TestGetHandlerSupportsRange(t *testing.T) {
	e := newEnv(t)
	app := newHandlerApp(t, e)

	if _, err := e.objects.Put(t.Context(), "avatars", "1.txt", strings.NewReader("0123456789"),
		oss.PutOptions{ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}

	rec := get(t, app, "/avatar/1.txt", http.Header{"Range": {"bytes=1-3"}})
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", rec.Code)
	}
	if rec.Body.String() != "123" {
		t.Fatalf("body = %q, want 123", rec.Body.String())
	}
	if rec.Header().Get("Content-Range") != "bytes 1-3/10" {
		t.Fatalf("Content-Range = %q", rec.Header().Get("Content-Range"))
	}
}

func TestGetHandlerUnicodeName(t *testing.T) {
	e := newEnv(t)
	app := newHandlerApp(t, e)

	if _, err := e.objects.Put(t.Context(), "avatars", "头像.png", strings.NewReader("x"),
		oss.PutOptions{ContentType: "image/png"}); err != nil {
		t.Fatal(err)
	}

	rec := get(t, app, "/avatar/%E5%A4%B4%E5%83%8F.png", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGetHandlerRejectsInvalidBucket(t *testing.T) {
	e := newEnv(t)
	for _, bucket := range []string{"", "..", "a/b"} {
		if _, err := e.objects.GetHandler(bucket); err == nil {
			t.Fatalf("GetHandler(%q) should fail", bucket)
		}
	}
}
