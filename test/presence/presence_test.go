package presence_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/presence"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
	"zephyr.vox/server/ce/internal/validation"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t0 time.Time) *fakeClock {
	return &fakeClock{now: t0}
}

func (c *fakeClock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestHeartbeatAndQuery(t *testing.T) {
	t0 := time.UnixMilli(1_700_000_000_000)
	clock := newFakeClock(t0)
	p := presence.New(clock.get)

	if err := p.Heartbeat(1, presence.RealStatusOnline); err != nil {
		t.Fatal(err)
	}
	states := p.Online()
	if len(states) != 1 {
		t.Fatalf("states = %v, want only user 1", states)
	}
	if states[1].RealStatus != presence.RealStatusOnline {
		t.Fatalf("status = %q, want online", states[1].RealStatus)
	}
	if states[1].LastSeen != t0.UnixMilli() {
		t.Fatalf("last_seen = %d, want %d", states[1].LastSeen, t0.UnixMilli())
	}
}

func TestHeartbeatAwayOverwrites(t *testing.T) {
	p := presence.New(time.Now)
	if err := p.Heartbeat(1, presence.RealStatusOnline); err != nil {
		t.Fatal(err)
	}
	if err := p.Heartbeat(1, presence.RealStatusAway); err != nil {
		t.Fatal(err)
	}
	states := p.Online()
	if states[1].RealStatus != presence.RealStatusAway {
		t.Fatalf("status = %q, want away", states[1].RealStatus)
	}
}

func TestHeartbeatInvalidStatus(t *testing.T) {
	p := presence.New(time.Now)
	if err := p.Heartbeat(1, "invisible"); err == nil {
		t.Fatal("want ErrInvalidStatus")
	}
	if states := p.Online(); len(states) != 0 {
		t.Fatalf("states = %v, want empty", states)
	}
}

func TestHeartbeatExpiry(t *testing.T) {
	t0 := time.UnixMilli(1_700_000_000_000)
	clock := newFakeClock(t0)
	p := presence.New(clock.get)

	if err := p.Heartbeat(1, presence.RealStatusOnline); err != nil {
		t.Fatal(err)
	}
	clock.advance(presence.HeartbeatTTL - time.Second)
	if states := p.Online(); len(states) != 1 {
		t.Fatalf("at TTL-1s states = %v, want online", states)
	}
	clock.advance(2 * time.Second)
	if states := p.Online(); len(states) != 0 {
		t.Fatalf("after TTL states = %v, want offline", states)
	}
}

func TestHeartbeatSlidingRenewal(t *testing.T) {
	t0 := time.UnixMilli(1_700_000_000_000)
	clock := newFakeClock(t0)
	p := presence.New(clock.get)

	if err := p.Heartbeat(1, presence.RealStatusOnline); err != nil {
		t.Fatal(err)
	}
	// Renew halfway through the window, then wait until the original
	// deadline would have passed. Without sliding, the user would be gone.
	clock.advance(presence.HeartbeatTTL / 2)
	if err := p.Heartbeat(1, presence.RealStatusOnline); err != nil {
		t.Fatal(err)
	}
	clock.advance(presence.HeartbeatTTL / 2)
	if states := p.Online(); len(states) != 1 {
		t.Fatalf("at original deadline states = %v, want still online", states)
	}
	clock.advance(presence.HeartbeatTTL / 2)
	if states := p.Online(); len(states) != 0 {
		t.Fatalf("after renewed deadline states = %v, want offline", states)
	}
}

func TestHeartbeatConcurrent(t *testing.T) {
	p := presence.New(time.Now)
	const users = 64

	var wg sync.WaitGroup
	for i := int64(1); i <= users; i++ {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			status := presence.RealStatusOnline
			if id%2 == 0 {
				status = presence.RealStatusAway
			}
			if err := p.Heartbeat(id, status); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()

	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids := make([]int64, users)
			for i := range ids {
				ids[i] = int64(i + 1)
			}
			states := p.Online()
			if len(states) != users {
				t.Errorf("states = %d, want %d", len(states), users)
			}
		}()
	}
	wg.Wait()
}

type env struct {
	stores     *store.Stores
	principals *auth.PrincipalCache
	secret     []byte
}

func newEnv(t *testing.T) *env {
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
	secret := []byte("test-secret-0123456789abcdef0123456789abcdef")
	return &env{
		stores:     stores,
		principals: auth.NewPrincipalCache(stores.Users, time.Minute),
		secret:     secret,
	}
}

func (e *env) createUser(t *testing.T, username string) *db.User {
	t.Helper()
	hash, err := auth.HashPassword("secret123")
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.stores.Users.CreateUser(context.Background(), username, hash, username, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.stores.Users.SetRoles(context.Background(), u.ID, []string{"member"}); err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *env) token(t *testing.T, u *db.User) string {
	t.Helper()
	tok, err := auth.SignAccess(e.secret, u.ID, u.AuthVersion, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newApp(e *env, p *presence.Presence) *echo.Echo {
	app := echo.New()
	app.Validator = validation.New()
	app.HTTPErrorHandler = api.NewErrorHandler(slog.New(slog.NewTextHandler(io.Discard, nil)))
	app.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey:    e.secret,
		NewClaimsFunc: func(c *echo.Context) jwt.Claims { return &auth.Claims{} },
	}))
	app.Use(rbacecho.AuthN(auth.NewPrincipalResolver(e.principals)))
	app.POST("/api/v0/presence/heartbeat", presence.HeartbeatHandler(p))
	app.GET("/api/v0/presence", presence.QueryHandler(p))
	return app
}

func request(t *testing.T, app *echo.Echo, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestHeartbeatHandler(t *testing.T) {
	e := newEnv(t)
	p := presence.New(time.Now)
	app := newApp(e, p)
	u := e.createUser(t, "alice")
	token := e.token(t, u)

	rec := request(t, app, http.MethodPost, "/api/v0/presence/heartbeat", token, `{"status":"online"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = request(t, app, http.MethodGet, "/api/v0/presence", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("query status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data map[string]struct {
			Status   string `json:"status"`
			LastSeen int64  `json:"last_seen"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != 0 {
		t.Fatalf("code = %d, want 0", resp.Code)
	}
	states := resp.Data
	key := strconv.FormatInt(u.ID, 10)
	if states[key].Status != "online" {
		t.Fatalf("states = %v, want alice online", states)
	}
}

func TestHeartbeatHandlerInvalidStatus(t *testing.T) {
	e := newEnv(t)
	p := presence.New(time.Now)
	app := newApp(e, p)
	token := e.token(t, e.createUser(t, "alice"))

	rec := request(t, app, http.MethodPost, "/api/v0/presence/heartbeat", token, `{"status":"invisible"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != 1 || resp.Message != "invalid status" {
		t.Fatalf("envelope = %+v, want code 1 with invalid status message", resp)
	}
}

func TestHeartbeatHandlerUnauthenticated(t *testing.T) {
	e := newEnv(t)
	app := newApp(e, presence.New(time.Now))

	rec := request(t, app, http.MethodPost, "/api/v0/presence/heartbeat", "", `{"status":"online"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestQueryHandlerReturnsOnlyOnline(t *testing.T) {
	e := newEnv(t)
	p := presence.New(time.Now)
	app := newApp(e, p)
	alice := e.createUser(t, "alice")
	bob := e.createUser(t, "bob")
	token := e.token(t, alice)

	if err := p.Heartbeat(alice.ID, presence.RealStatusOnline); err != nil {
		t.Fatal(err)
	}
	rec := request(t, app, http.MethodGet, "/api/v0/presence", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data map[string]struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	states := resp.Data
	if _, ok := states[strconv.FormatInt(bob.ID, 10)]; ok {
		t.Fatalf("bob must be absent: %v", states)
	}
	if states[strconv.FormatInt(alice.ID, 10)].Status != "online" {
		t.Fatalf("alice = %v, want online", states)
	}
}

func TestQueryHandlerUnauthenticated(t *testing.T) {
	e := newEnv(t)
	app := newApp(e, presence.New(time.Now))

	rec := request(t, app, http.MethodGet, "/api/v0/presence", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
