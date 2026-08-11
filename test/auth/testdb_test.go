package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
)

type fakeClock struct {
	mu  sync.Mutex
	now int64
}

func (c *fakeClock) get() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) set(now int64) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

type env struct {
	stores     *store.Stores
	svc        *auth.AuthService
	principals *auth.PrincipalCache
	clock      *fakeClock
	secret     []byte
}

func newEnv(t *testing.T) *env {
	t.Helper()

	conn, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	schema, err := os.ReadFile("../../db/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(string(schema)); err != nil {
		t.Fatal(err)
	}

	clock := &fakeClock{now: time.Now().UnixMilli()}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	stores := store.New(conn, idGen, clock.get)

	secret := []byte("test-secret-0123456789abcdef0123456789abcdef")
	principals := auth.NewPrincipalCache(stores.Users, time.Minute)
	svc := auth.NewAuthService(stores, principals, secret, 15*time.Minute, 30*24*time.Hour, clock.get)
	return &env{
		stores:     stores,
		svc:        svc,
		principals: principals,
		clock:      clock,
		secret:     secret,
	}
}

func (e *env) createUser(t *testing.T, username, password string, roles ...string) *db.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.stores.Users.CreateUser(context.Background(), username, hash, username, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) > 0 {
		if err := e.stores.Users.SetRoles(context.Background(), u.ID, roles); err != nil {
			t.Fatal(err)
		}
	}
	return u
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
