package server_test

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

// avatarPNG builds a tiny solid-color PNG for uploads.
func avatarPNG(t *testing.T) []byte {
	t.Helper()
	m := newNRGBA(16, 16, color.NRGBA{R: 10, G: 20, B: 30, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, m); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newNRGBA(w, h int, fill color.NRGBA) *image.NRGBA {
	m := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			m.SetNRGBA(x, y, fill)
		}
	}
	return m
}

// TestAvatarUploadServesPublicly verifies the end-to-end avatar flow: the
// upload response carries the bare object name (no path prefix), and the
// public GET route streams the stored JPEG with Content-Type image/jpeg and
// X-Content-Type-Options: nosniff, so a browser can never sniff the bytes as
// HTML.
func TestAvatarUploadServesPublicly(t *testing.T) {
	app := newTestApp(t)
	_, token := activateAdmin(t, app)

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", "a.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(avatarPNG(t)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v0/me/avatar", &buf)
	req.Header.Set(echo.HeaderContentType, w.FormDataContentType())
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	rec := httptest.NewRecorder()
	app.Echo().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, body = %s", rec.Code, rec.Body.String())
	}
	name, _ := dataOf(t, rec)["avatar"].(string)
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "/") {
		t.Fatalf("avatar = %q, want a bare object name", name)
	}
	if !strings.HasSuffix(name, ".jpg") {
		t.Fatalf("avatar = %q, want .jpg suffix", name)
	}

	prec := get(t, app, "/avatar/"+name)
	if prec.Code != http.StatusOK {
		t.Fatalf("public read status = %d", prec.Code)
	}
	if ct := prec.Header().Get(echo.HeaderContentType); ct != "image/jpeg" {
		t.Fatalf("content-type = %q, want image/jpeg", ct)
	}
	if prec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", prec.Header().Get("X-Content-Type-Options"))
	}
}
