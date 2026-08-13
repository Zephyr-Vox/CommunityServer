package store_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

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

func newTestEnv(t *testing.T) (*store.Stores, *fakeClock) {
	t.Helper()

	conn, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	if _, err := conn.Exec(db.SchemaSQL); err != nil {
		t.Fatal(err)
	}

	var fk int
	if err := conn.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if fk != 1 {
		t.Fatal("foreign keys are not enabled")
	}

	var journalMode string
	if err := conn.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %s, want wal", journalMode)
	}

	clock := &fakeClock{now: snowflake.DefaultEpoch.UnixMilli() + 60_000}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	return store.New(conn, idGen, clock.get), clock
}

func mustCreateUser(t *testing.T, s *store.Stores, username string) *db.User {
	t.Helper()
	u, err := s.Users.CreateUser(context.Background(), username, "hash", username, nil)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
