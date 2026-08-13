package oss_test

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/oss"
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
	root    string
	dbPath  string
	conn    *sql.DB
	objects *oss.LocalObjectStorage
	clock   *fakeClock
}

func newEnv(t *testing.T) *env {
	t.Helper()

	root := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	conn, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	if _, err := conn.Exec(db.SchemaSQL); err != nil {
		t.Fatal(err)
	}

	clock := &fakeClock{now: time.Now().UnixMilli()}
	objects, err := oss.NewLocalObjectStorage(root, conn, clock.get)
	if err != nil {
		t.Fatal(err)
	}
	return &env{root: root, dbPath: dbPath, conn: conn, objects: objects, clock: clock}
}
