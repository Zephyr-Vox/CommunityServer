package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/store"
)

var activationCodeRe = regexp.MustCompile(`^[A-Z2-7]{16}$`)

func TestEnsureActivationCode(t *testing.T) {
	app := newTestApp(t)
	ctx := context.Background()

	code, ok, err := app.EnsureActivationCode(ctx)
	if err != nil || !ok {
		t.Fatalf("EnsureActivationCode = (_, %v, %v), want ok", ok, err)
	}
	if !activationCodeRe.MatchString(code) {
		t.Fatalf("code = %q, want 16 base32 chars", code)
	}

	// While a code is pending the manager keeps it but never returns the
	// plaintext twice.
	code2, ok2, err := app.EnsureActivationCode(ctx)
	if err != nil || !ok2 || code2 != "" {
		t.Fatalf("second EnsureActivationCode = (%q, %v, %v), want pending without plaintext", code2, ok2, err)
	}

	// Redeem the code through the API, then no code may be pending anymore.
	req := httptest.NewRequest(http.MethodPost, "/api/v0/admin/activate",
		strings.NewReader(`{"code":"`+code+`","username":"boss","password":"secret123"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("Idempotency-Key", "activate-owner-0001")
	rec := httptest.NewRecorder()
	app.Echo().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate status = %d, body = %s", rec.Code, rec.Body.String())
	}

	_, ok3, err := app.EnsureActivationCode(ctx)
	if err != nil || ok3 {
		t.Fatalf("EnsureActivationCode after activation = (_, %v, %v), want no pending code", ok3, err)
	}
}

func TestActivationResponseLossReplaysAfterRestart(t *testing.T) {
	dir := t.TempDir()
	app := newAppAt(t, dir)
	code, pending, err := app.EnsureActivationCode(context.Background())
	if err != nil || !pending {
		t.Fatalf("EnsureActivationCode = (_, %t, %v)", pending, err)
	}
	const key = "activate-replay-0001"
	body := `{"code":"` + code + `","username":"boss","password":"secret123","nickname":"Boss"}`
	first := postJSONIdempotency(t, app, "/api/v0/admin/activate", key, body)
	if first.Code != http.StatusOK {
		t.Fatalf("first activation = %d %s", first.Code, first.Body.String())
	}
	firstCommandID := first.Header().Get("X-Zephyr-Command-ID")
	if firstCommandID == "" {
		t.Fatal("first activation omitted command ID")
	}
	for _, header := range []string{"X-Zephyr-State-Cursor", "X-Zephyr-Stream-Epoch", "X-Zephyr-Geid"} {
		if first.Header().Get(header) == "" {
			t.Fatalf("first activation omitted %s", header)
		}
	}
	firstBody := first.Body.String()
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	restarted := newAppAt(t, dir)
	replay := postJSONIdempotency(t, restarted, "/api/v0/admin/activate", key, body)
	if replay.Code != http.StatusOK || replay.Header().Get("X-Zephyr-Command-ID") != firstCommandID || replay.Body.String() != firstBody {
		t.Fatalf("activation replay = %d command=%q body=%s", replay.Code, replay.Header().Get("X-Zephyr-Command-ID"), replay.Body.String())
	}
	if replay.Header().Get("X-Zephyr-Sync-Required") != "true" || replay.Header().Get("X-Zephyr-State-Cursor") != "" || replay.Header().Get("X-Zephyr-Stream-Epoch") != "" || replay.Header().Get("X-Zephyr-Geid") != "" {
		t.Fatalf("activation restart headers = %v", replay.Header())
	}
	mismatch := postJSONIdempotency(t, restarted, "/api/v0/admin/activate", key, `{"code":"`+code+`","username":"other","password":"secret123","nickname":"Boss"}`)
	if mismatch.Code != http.StatusConflict {
		t.Fatalf("activation mismatch = %d %s", mismatch.Code, mismatch.Body.String())
	}
	var mismatchEnvelope struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(mismatch.Body.Bytes(), &mismatchEnvelope); err != nil || mismatchEnvelope.Code != 9 {
		t.Fatalf("activation mismatch envelope = %+v err=%v", mismatchEnvelope, err)
	}

	conn, err := store.Open(filepath.Join(dir, "zephyr.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var codeHash, requestHMAC, resultBody string
	if err := conn.QueryRow(`SELECT activation_code_hash, request_hmac, result_body FROM activation_idempotency WHERE idempotency_key = ?`, key).Scan(&codeHash, &requestHMAC, &resultBody); err != nil {
		t.Fatal(err)
	}
	persisted := strings.Join([]string{codeHash, requestHMAC, resultBody}, "\n")
	if strings.Contains(persisted, code) || strings.Contains(persisted, "secret123") {
		t.Fatalf("activation record contains plaintext secret: %s", persisted)
	}
}

func TestLegacyActivationReplayRequiresSync(t *testing.T) {
	dir := t.TempDir()
	app := newAppAt(t, dir)
	code, pending, err := app.EnsureActivationCode(context.Background())
	if err != nil || !pending {
		t.Fatalf("EnsureActivationCode = (_, %t, %v)", pending, err)
	}
	const key = "activate-legacy-0001"
	body := `{"code":"` + code + `","username":"boss","password":"secret123","nickname":"Boss"}`
	first := postJSONIdempotency(t, app, "/api/v0/admin/activate", key, body)
	if first.Code != http.StatusOK {
		t.Fatalf("first activation = %d %s", first.Code, first.Body.String())
	}
	commandID := first.Header().Get("X-Zephyr-Command-ID")
	if commandID == "" {
		t.Fatal("first activation omitted command ID")
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	// Replace the new wrapped result with the legacy user envelope to model a
	// record created before activation checkpoint persistence was introduced.
	conn, err := store.Open(filepath.Join(dir, "zephyr.db"))
	if err != nil {
		t.Fatal(err)
	}
	var storedBody string
	if err := conn.QueryRow(`SELECT result_body FROM activation_idempotency WHERE idempotency_key = ?`, key).Scan(&storedBody); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	var stored struct {
		Body json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal([]byte(storedBody), &stored); err != nil || len(stored.Body) == 0 {
		conn.Close()
		t.Fatalf("stored activation result = %s, want wrapped body", storedBody)
	}
	if _, err := conn.Exec(`UPDATE activation_idempotency SET result_body = ? WHERE idempotency_key = ?`, string(stored.Body), key); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	restarted := newAppAt(t, dir)
	replay := postJSONIdempotency(t, restarted, "/api/v0/admin/activate", key, body)
	if replay.Code != http.StatusOK || replay.Header().Get("X-Zephyr-Command-ID") != commandID {
		t.Fatalf("legacy activation replay = %d command=%q body=%s", replay.Code, replay.Header().Get("X-Zephyr-Command-ID"), replay.Body.String())
	}
	if replay.Header().Get("X-Zephyr-Sync-Required") != "true" || replay.Header().Get("X-Zephyr-State-Cursor") != "" || replay.Header().Get("X-Zephyr-Stream-Epoch") != "" || replay.Header().Get("X-Zephyr-Geid") != "" {
		t.Fatalf("legacy activation replay headers = %v", replay.Header())
	}
}

func TestActivationRequiresIdempotencyKey(t *testing.T) {
	app := newTestApp(t)
	code, _, err := app.EnsureActivationCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, app, "/api/v0/admin/activate", `{"code":"`+code+`","username":"boss","password":"secret123"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"code":1000`) || !strings.Contains(rec.Body.String(), `"header.Idempotency-Key"`) {
		t.Fatalf("missing activation idempotency key = %d %s", rec.Code, rec.Body.String())
	}
}
