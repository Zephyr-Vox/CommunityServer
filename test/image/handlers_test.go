package image_test

import (
	"bytes"
	"context"
	"encoding/json"
	"image/color"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/auth"
	img "zephyr.vox/server/ce/internal/image"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/validation"
)

func newAvatarEcho(t *testing.T, e *env) *echo.Echo {
	t.Helper()
	app := echo.New()
	app.Validator = validation.New()
	app.HTTPErrorHandler = api.NewErrorHandler(slog.New(slog.NewTextHandler(io.Discard, nil)))
	app.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey:    e.secret,
		NewClaimsFunc: func(c *echo.Context) jwt.Claims { return &auth.Claims{} },
	}))
	app.Use(rbacecho.AuthN(auth.NewPrincipalResolver(e.principals)))
	app.POST("/api/v0/me/avatar", img.UploadAvatarHandler(e.svc))
	app.DELETE("/api/v0/me/avatar", img.DeleteAvatarHandler(e.svc))
	return app
}

func loginToken(t *testing.T, e *env, username string) string {
	t.Helper()
	login, err := e.authSvc.Login(context.Background(), username, "secret123", "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	return login.AccessToken
}

// multipartBody builds a multipart form with one file field.
func multipartBody(t *testing.T, field string, data []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile(field, "upload.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, w.FormDataContentType()
}

func doRequest(t *testing.T, app *echo.Echo, method, path, token, contentType string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	if contentType != "" {
		req.Header.Set(echo.HeaderContentType, contentType)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestUploadAvatarHandlerSuccess(t *testing.T) {
	e := newEnv(t, defaultCfg())
	app := newAvatarEcho(t, e)
	createUser(t, e, "alice")
	token := loginToken(t, e, "alice")

	body, ctype := multipartBody(t, "file", pngBytes(t, 100, 50, nrgba(10, 20, 30)))
	rec := doRequest(t, app, http.MethodPost, "/api/v0/me/avatar", token, ctype, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		t.Fatalf("data missing: %v", resp)
	}
	name, ok := data["avatar"].(string)
	if !ok || !managedNameRE.MatchString(name) {
		t.Fatalf("avatar = %v, want managed name", data["avatar"])
	}
}

func TestUploadAvatarHandlerUnauthorized(t *testing.T) {
	e := newEnv(t, defaultCfg())
	app := newAvatarEcho(t, e)
	body, ctype := multipartBody(t, "file", pngBytes(t, 32, 32, nrgba(1, 2, 3)))
	rec := doRequest(t, app, http.MethodPost, "/api/v0/me/avatar", "", ctype, body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestUploadAvatarHandlerMissingFile(t *testing.T) {
	e := newEnv(t, defaultCfg())
	app := newAvatarEcho(t, e)
	createUser(t, e, "alice")
	token := loginToken(t, e, "alice")

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("note", "no file here"); err != nil {
		t.Fatal(err)
	}
	w.Close()

	rec := doRequest(t, app, http.MethodPost, "/api/v0/me/avatar", token, w.FormDataContentType(), &buf)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["code"] != float64(1) {
		t.Fatalf("code = %v, want 1 (missing file)", resp["code"])
	}
}

func TestUploadAvatarHandlerNotImage(t *testing.T) {
	e := newEnv(t, defaultCfg())
	app := newAvatarEcho(t, e)
	createUser(t, e, "alice")
	token := loginToken(t, e, "alice")

	body, ctype := multipartBody(t, "file", []byte("hello, definitely not an image"))
	rec := doRequest(t, app, http.MethodPost, "/api/v0/me/avatar", token, ctype, body)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != api.CodeUnsupportedMedia {
		t.Fatalf("code = %d, want %d", response.Code, api.CodeUnsupportedMedia)
	}
}

func TestUploadAvatarHandlerPayloadTooLarge(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxUploadSize = 64 // tiny limit: any real upload exceeds it
	e := newEnv(t, cfg)
	app := newAvatarEcho(t, e)
	createUser(t, e, "alice")
	token := loginToken(t, e, "alice")

	body, ctype := multipartBody(t, "file", pngBytes(t, 32, 32, nrgba(1, 2, 3)))
	rec := doRequest(t, app, http.MethodPost, "/api/v0/me/avatar", token, ctype, body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != api.CodePayloadTooLarge {
		t.Fatalf("code = %d, want %d", response.Code, api.CodePayloadTooLarge)
	}
}

func TestUploadAvatarHandlerRejectsOversizedTrailingPartBeforeCommit(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxUploadSize = 1024
	e := newEnv(t, cfg)
	app := newAvatarEcho(t, e)
	userID := createUser(t, e, "alice")
	token := loginToken(t, e, "alice")

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("file", "avatar.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(pngBytes(t, 8, 8, nrgba(1, 2, 3))); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("trailing", string(bytes.Repeat([]byte{'x'}, 2048))); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	rec := doRequest(t, app, http.MethodPost, "/api/v0/me/avatar", token, writer.FormDataContentType(), &body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != api.CodePayloadTooLarge {
		t.Fatalf("code = %d, want %d", response.Code, api.CodePayloadTooLarge)
	}
	user, err := e.stores.Users.GetUserByID(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if user.Avatar.Valid {
		t.Fatalf("oversized request committed avatar %q", user.Avatar.String)
	}
}

func TestUploadAvatarHandlerTranscodeBusy(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxConcurrentTranscodes = 1
	e := newEnv(t, cfg)
	createUser(t, e, "alice")
	createUser(t, e, "bob")
	firstToken := loginToken(t, e, "alice")
	secondToken := loginToken(t, e, "bob")
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	e.svc = img.NewAvatarService(e.stores.Users, e.objects, idGen, cfg, img.WithTranscode(
		func(io.Reader, img.ImageConverter, int, int) ([]byte, error) {
			once.Do(func() { close(started) })
			<-release
			return []byte("fake-jpeg"), nil
		},
	))
	app := newAvatarEcho(t, e)

	body, ctype := multipartBody(t, "file", pngBytes(t, 8, 8, nrgba(1, 2, 3)))
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstDone <- doRequest(t, app, http.MethodPost, "/api/v0/me/avatar", firstToken, ctype, body)
	}()
	<-started

	secondBody, secondType := multipartBody(t, "file", pngBytes(t, 8, 8, nrgba(4, 5, 6)))
	second := doRequest(t, app, http.MethodPost, "/api/v0/me/avatar", secondToken, secondType, secondBody)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, body = %s", second.Code, second.Body.String())
	}
	var response struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != api.CodeRateLimited {
		t.Fatalf("second code = %d, want %d", response.Code, api.CodeRateLimited)
	}

	close(release)
	if first := <-firstDone; first.Code != http.StatusOK {
		t.Fatalf("first status = %d, body = %s", first.Code, first.Body.String())
	}
}

func TestDeleteAvatarHandler(t *testing.T) {
	e := newEnv(t, defaultCfg())
	app := newAvatarEcho(t, e)
	createUser(t, e, "alice")
	token := loginToken(t, e, "alice")

	// Idempotent: deleting without an avatar returns 204.
	rec := doRequest(t, app, http.MethodDelete, "/api/v0/me/avatar", token, "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func nrgba(r, g, b uint8) color.NRGBA { return color.NRGBA{R: r, G: g, B: b, A: 255} }
