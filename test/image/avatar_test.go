package image_test

import (
	"bytes"
	"context"
	"errors"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	stdimage "image"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/db"
	img "zephyr.vox/server/ce/internal/image"
	"zephyr.vox/server/ce/internal/oss"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
)

type env struct {
	stores     *store.Stores
	objects    *oss.LocalObjectStorage
	svc        *img.AvatarService
	authSvc    *auth.AuthService
	principals *auth.PrincipalCache
	secret     []byte
}

func newEnv(t *testing.T, cfg config.AvatarConfig) *env {
	t.Helper()
	conn, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Exec(db.SchemaSQL); err != nil {
		t.Fatal(err)
	}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	now := func() int64 { return time.Now().UnixMilli() }
	stores := store.New(conn, idGen, now)
	objects, err := oss.NewLocalObjectStorage(t.TempDir(), conn, now)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("test-secret-0123456789abcdef0123456789abcdef")
	principals := auth.NewPrincipalCache(stores, time.Minute)
	authSvc := auth.NewAuthService(stores, principals, secret, 15*time.Minute, 30*24*time.Hour, now)
	return &env{
		stores:     stores,
		objects:    objects,
		svc:        img.NewAvatarService(stores.Users, objects, idGen, cfg),
		authSvc:    authSvc,
		principals: principals,
		secret:     secret,
	}
}

func defaultCfg() config.AvatarConfig {
	return config.AvatarConfig{MaxUploadSize: 10 << 20, MaxDimension: 4096, TargetSize: 64, Quality: 85}
}

// pngBytes encodes a solid-color NRGBA image as PNG bytes.
func pngBytes(t *testing.T, w, h int, fill color.NRGBA) []byte {
	t.Helper()
	m := stdimage.NewNRGBA(stdimage.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			m.SetNRGBA(x, y, fill)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, m); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decodeJPEG(t *testing.T, data []byte) stdimage.Image {
	t.Helper()
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode jpeg: %v", err)
	}
	return img
}

func TestTranscodeJPEGRoundtrip(t *testing.T) {
	conv := img.JPEGConverter{Quality: 85}
	out, err := img.Transcode(bytes.NewReader(pngBytes(t, 100, 50, color.NRGBA{R: 200, G: 100, B: 50, A: 255})), conv, 64, 4096)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeJPEG(t, out)
	b := got.Bounds()
	if b.Dx() != 64 || b.Dy() != 64 {
		t.Fatalf("bounds = %v, want 64x64", b)
	}
	if conv.Extension() != "jpg" || conv.ContentType() != "image/jpeg" {
		t.Fatalf("conv = %q/%q, want jpg/image/jpeg", conv.Extension(), conv.ContentType())
	}
}

func TestTranscodeCompositesAlphaOntoWhite(t *testing.T) {
	// Fully transparent source: the JPEG output must be white, not black.
	out, err := img.Transcode(bytes.NewReader(pngBytes(t, 32, 32, color.NRGBA{A: 0})), img.JPEGConverter{Quality: 85}, 32, 4096)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeJPEG(t, out)
	r, g, b, _ := got.At(0, 0).RGBA()
	if r < 0xF000 || g < 0xF000 || b < 0xF000 { // near-white within JPEG loss
		t.Fatalf("corner = %d/%d/%d, want near-white", r>>8, g>>8, b>>8)
	}
}

func TestTranscodeRejectsOversized(t *testing.T) {
	_, err := img.Transcode(bytes.NewReader(pngBytes(t, 200, 200, color.NRGBA{R: 1, G: 2, B: 3, A: 255})), img.JPEGConverter{Quality: 85}, 64, 100)
	if !errors.Is(err, img.ErrImageTooLarge) {
		t.Fatalf("err = %v, want ErrImageTooLarge", err)
	}
}

func TestTranscodeRejectsNonImage(t *testing.T) {
	_, err := img.Transcode(bytes.NewReader([]byte("hello, not an image")), img.JPEGConverter{Quality: 85}, 64, 4096)
	if !errors.Is(err, img.ErrNotAnImage) {
		t.Fatalf("err = %v, want ErrNotAnImage", err)
	}
}

// TestJPEGConverterCompositesPalettedAlpha covers the color.Palette branch
// of hasAlpha: a paletted image whose palette contains a transparent entry
// (RGB 0) must be composited onto white before JPEG encoding, or the
// transparent pixels would come out black.
func TestJPEGConverterCompositesPalettedAlpha(t *testing.T) {
	pal := color.Palette{
		color.NRGBA{R: 0, G: 0, B: 0, A: 0}, // transparent, RGB 0
		color.NRGBA{R: 255, G: 0, B: 0, A: 255},
	}
	m := stdimage.NewPaletted(stdimage.Rect(0, 0, 4, 4), pal)
	for i := range m.Pix {
		m.Pix[i] = 0 // every pixel uses the transparent entry
	}
	var out bytes.Buffer
	if err := (img.JPEGConverter{Quality: 85}).Encode(&out, m); err != nil {
		t.Fatal(err)
	}
	got := decodeJPEG(t, out.Bytes())
	r, g, b, _ := got.At(0, 0).RGBA()
	if r < 0xF000 || g < 0xF000 || b < 0xF000 { // near-white within JPEG loss
		t.Fatalf("corner = %d/%d/%d, want near-white", r>>8, g>>8, b>>8)
	}
}

// TestJPEGConverterPalettedPNGRoundtrip covers the real-world path: a PNG
// with a tRNS-transparent palette, decoded and encoded directly (without the
// avatar pipeline's NRGBA conversion).
func TestJPEGConverterPalettedPNGRoundtrip(t *testing.T) {
	pal := color.Palette{
		color.NRGBA{A: 0},
		color.NRGBA{R: 1, G: 2, B: 3, A: 255},
	}
	m := stdimage.NewPaletted(stdimage.Rect(0, 0, 8, 8), pal)
	for i := range m.Pix {
		m.Pix[i] = 0
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, m); err != nil {
		t.Fatal(err)
	}
	decoded, _, err := stdimage.Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := (img.JPEGConverter{Quality: 85}).Encode(&out, decoded); err != nil {
		t.Fatal(err)
	}
	got := decodeJPEG(t, out.Bytes())
	r, g, b, _ := got.At(0, 0).RGBA()
	if r < 0xF000 || g < 0xF000 || b < 0xF000 { // near-white within JPEG loss
		t.Fatalf("corner = %d/%d/%d, want near-white", r>>8, g>>8, b>>8)
	}
}

var managedNameRE = regexp.MustCompile(`^[1-9][0-9]*\.jpg$`)

// createUser inserts a user with the fixed test password "secret123".
func createUser(t *testing.T, e *env, username string) int64 {
	t.Helper()
	hash, err := auth.HashPassword("secret123")
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.stores.Users.CreateUser(context.Background(), username, hash, username, nil)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestAvatarUpload(t *testing.T) {
	e := newEnv(t, defaultCfg())
	ctx := context.Background()
	userID := createUser(t, e, "alice")

	name, err := e.svc.Upload(ctx, userID, bytes.NewReader(pngBytes(t, 100, 50, color.NRGBA{R: 10, G: 20, B: 30, A: 255})))
	if err != nil {
		t.Fatal(err)
	}
	if !managedNameRE.MatchString(name) {
		t.Fatalf("name = %q, want <id>.jpg", name)
	}

	user, err := e.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if !user.Avatar.Valid || user.Avatar.String != name {
		t.Fatalf("avatar = %+v, want %q", user.Avatar, name)
	}

	obj, rc, err := e.objects.Open(ctx, img.AvatarBucket, name)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if obj.ContentType != "image/jpeg" {
		t.Fatalf("content_type = %q, want image/jpeg", obj.ContentType)
	}
	data, _, err := stdimage.Decode(rc)
	if err != nil {
		t.Fatal(err)
	}
	if b := data.Bounds(); b.Dx() != 64 || b.Dy() != 64 {
		t.Fatalf("stored avatar bounds = %v, want 64x64", b)
	}
}

func TestAvatarUploadReplacesAndDeletesOld(t *testing.T) {
	e := newEnv(t, defaultCfg())
	ctx := context.Background()
	userID := createUser(t, e, "alice")

	first, err := e.svc.Upload(ctx, userID, bytes.NewReader(pngBytes(t, 64, 64, color.NRGBA{R: 1, A: 255})))
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.svc.Upload(ctx, userID, bytes.NewReader(pngBytes(t, 64, 64, color.NRGBA{R: 2, A: 255})))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("replace must produce a new name")
	}
	if _, _, err := e.objects.Open(ctx, img.AvatarBucket, first); !errors.Is(err, oss.ErrNotFound) {
		t.Fatalf("old object still present: %v", err)
	}
	user, err := e.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if !user.Avatar.Valid || user.Avatar.String != second {
		t.Fatalf("avatar = %+v, want %q", user.Avatar, second)
	}
}

func TestAvatarReset(t *testing.T) {
	e := newEnv(t, defaultCfg())
	ctx := context.Background()
	userID := createUser(t, e, "alice")

	name, err := e.svc.Upload(ctx, userID, bytes.NewReader(pngBytes(t, 64, 64, color.NRGBA{R: 1, A: 255})))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reset(ctx, userID); err != nil {
		t.Fatal(err)
	}
	user, err := e.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if user.Avatar.Valid {
		t.Fatalf("avatar = %+v, want null", user.Avatar)
	}
	if _, _, err := e.objects.Open(ctx, img.AvatarBucket, name); !errors.Is(err, oss.ErrNotFound) {
		t.Fatalf("object still present: %v", err)
	}

	// Idempotent: resetting without an avatar is fine.
	if err := e.svc.Reset(ctx, userID); err != nil {
		t.Fatal(err)
	}
}

func TestAvatarUploadUserNotFound(t *testing.T) {
	e := newEnv(t, defaultCfg())
	_, err := e.svc.Upload(context.Background(), 12345, bytes.NewReader(pngBytes(t, 64, 64, color.NRGBA{R: 1, A: 255})))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound", err)
	}
}

func TestAvatarUploadRejectsOversizedSource(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxDimension = 32
	e := newEnv(t, cfg)
	userID := createUser(t, e, "alice")
	_, err := e.svc.Upload(context.Background(), userID, bytes.NewReader(pngBytes(t, 64, 64, color.NRGBA{R: 1, A: 255})))
	if !errors.Is(err, img.ErrImageTooLarge) {
		t.Fatalf("err = %v, want ErrImageTooLarge", err)
	}
}

func TestAvatarUploadRejectsNonImage(t *testing.T) {
	e := newEnv(t, defaultCfg())
	userID := createUser(t, e, "alice")
	_, err := e.svc.Upload(context.Background(), userID, bytes.NewReader([]byte("not an image")))
	if !errors.Is(err, img.ErrNotAnImage) {
		t.Fatalf("err = %v, want ErrNotAnImage", err)
	}
}

func TestAvatarDeleteAvatar(t *testing.T) {
	e := newEnv(t, defaultCfg())
	ctx := context.Background()
	userID := createUser(t, e, "alice")

	name, err := e.svc.Upload(ctx, userID, bytes.NewReader(pngBytes(t, 64, 64, color.NRGBA{R: 1, A: 255})))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteAvatar(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.objects.Open(ctx, img.AvatarBucket, name); !errors.Is(err, oss.ErrNotFound) {
		t.Fatalf("object still present: %v", err)
	}
	// Idempotent and safe against arbitrary strings (no path traversal).
	if err := e.svc.DeleteAvatar(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteAvatar(ctx, "../escape"); err == nil {
		t.Fatal("want error for invalid name")
	}
}

// TestAvatarServiceWithInjectedTranscode proves the functional-option
// injection point works: WithTranscode replaces the pipeline, and the
// replaced function is what Upload actually runs.
func TestAvatarServiceWithInjectedTranscode(t *testing.T) {
	e := newEnv(t, defaultCfg())
	ctx := context.Background()
	userID := createUser(t, e, "alice")

	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	var called bool
	svc := img.NewAvatarService(e.stores.Users, e.objects, idGen, defaultCfg(),
		img.WithTranscode(func(src io.Reader, conv img.ImageConverter, size, maxDim int) ([]byte, error) {
			called = true
			return []byte("fake-jpeg-bytes"), nil
		}))

	name, err := svc.Upload(ctx, userID, strings.NewReader("ignored by injected transcode"))
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("injected transcode was not called")
	}
	if !managedNameRE.MatchString(name) {
		t.Fatalf("name = %q, want <id>.jpg", name)
	}
	// The injected bytes were stored with the default converter's metadata.
	obj, rc, err := e.objects.Open(ctx, img.AvatarBucket, name)
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if obj.ContentType != "image/jpeg" {
		t.Fatalf("content_type = %q, want image/jpeg", obj.ContentType)
	}
}
