package auth_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
)

type principalDriverGate struct {
	enabled atomic.Bool
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newPrincipalDriverGate() *principalDriverGate {
	return &principalDriverGate{started: make(chan struct{}), release: make(chan struct{})}
}

func (g *principalDriverGate) enable() { g.enabled.Store(true) }

func (g *principalDriverGate) trip() {
	if !g.enabled.CompareAndSwap(true, false) {
		return
	}
	close(g.started)
	<-g.release
}

func (g *principalDriverGate) unblock() { g.once.Do(func() { close(g.release) }) }

type principalGatedConnector struct {
	driver.Connector
	queryGate  *principalDriverGate
	commitGate *principalDriverGate
}

func (c *principalGatedConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &principalGatedConn{Conn: conn, queryGate: c.queryGate, commitGate: c.commitGate}, nil
}

type principalGatedConn struct {
	driver.Conn
	queryGate  *principalDriverGate
	commitGate *principalDriverGate
}

func (c *principalGatedConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	rows, err := queryer.QueryContext(ctx, query, args)
	if err != nil || !strings.Contains(query, "FROM users WHERE id") {
		return rows, err
	}
	return &principalGatedRows{Rows: rows, gate: c.queryGate}, nil
}

func (c *principalGatedConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return execer.ExecContext(ctx, query, args)
}

func (c *principalGatedConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	beginner, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, driver.ErrSkip
	}
	tx, err := beginner.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &principalGatedTx{Tx: tx, gate: c.commitGate}, nil
}

type principalGatedRows struct {
	driver.Rows
	gate *principalDriverGate
}

func (r *principalGatedRows) Next(dest []driver.Value) error {
	err := r.Rows.Next(dest)
	if err == nil {
		r.gate.trip()
	}
	return err
}

type principalGatedTx struct {
	driver.Tx
	gate *principalDriverGate
}

func (tx *principalGatedTx) Commit() error {
	if err := tx.Tx.Commit(); err != nil {
		return err
	}
	tx.gate.trip()
	return nil
}

func newGatedPrincipalEnv(t *testing.T) (*env, *principalDriverGate, *principalDriverGate) {
	t.Helper()
	queryGate := newPrincipalDriverGate()
	commitGate := newPrincipalDriverGate()
	t.Cleanup(queryGate.unblock)
	t.Cleanup(commitGate.unblock)
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", filepath.Join(t.TempDir(), "test.db"))
	base, err := sqlite.NewConnector(dsn)
	if err != nil {
		t.Fatal(err)
	}
	conn := sql.OpenDB(&principalGatedConnector{Connector: base, queryGate: queryGate, commitGate: commitGate})
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.Ping(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(db.SchemaSQL); err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{now: time.Now().UnixMilli()}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	stores := store.New(conn, idGen, clock.get)
	principals := auth.NewPrincipalCache(stores, time.Minute)
	return &env{conn: conn, stores: stores, principals: principals, clock: clock}, queryGate, commitGate
}

func TestPrincipalCacheLoadsAndInvalidates(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "password", "member", "moderator")

	snap, err := e.principals.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Roles) != 2 || snap.Roles[0] != "member" || snap.Roles[1] != "moderator" {
		t.Fatalf("unexpected roles: %v", snap.Roles)
	}
	if snap.Banned {
		t.Fatal("user should not be banned")
	}

	// Invalidation forces re-resolution.
	e.principals.Invalidate(u.ID)
	snap, err = e.principals.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Roles) != 2 {
		t.Fatalf("roles after invalidate: %v", snap.Roles)
	}
}

func TestPrincipalCacheReflectsBan(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "password", "member")

	if _, err := e.principals.Get(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.stores.Users.Ban(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	e.principals.Invalidate(u.ID)

	snap, err := e.principals.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Banned {
		t.Fatal("snapshot must reflect the ban")
	}
}

func TestPrincipalCacheUnknownUser(t *testing.T) {
	e := newEnv(t)
	_, err := e.principals.Get(context.Background(), 123456)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestPrincipalCacheClonesRoles(t *testing.T) {
	e := newEnv(t)
	u := e.createUser(t, "alice", "password", "member", "moderator")

	snap, err := e.principals.Get(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	snap.Roles[0] = "changed"
	again, err := e.principals.Get(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.Roles[0] != "member" {
		t.Fatalf("cached roles were mutated through returned snapshot: %v", again.Roles)
	}
}

func TestPrincipalMutationBarrierUsesRealBanAndInvalidation(t *testing.T) {
	e, _, commitGate := newGatedPrincipalEnv(t)
	boss := e.createUser(t, "boss", "password", "admin")
	u := e.createUser(t, "alice", "password", "member")
	ctx := context.Background()
	if _, err := e.principals.Get(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	svc, _ := newUserService(t, e)
	commitGate.enable()
	mutation := make(chan error, 1)
	go func() { mutation <- svc.Ban(ctx, boss.ID, u.ID) }()
	select {
	case err := <-mutation:
		t.Fatalf("Ban returned before commit gate: %v", err)
	case <-commitGate.started:
	case <-time.After(time.Second):
		t.Fatal("Ban did not reach the commit gate")
	}

	type result struct {
		banned bool
		err    error
	}
	read := make(chan result, 1)
	go func() {
		snap, err := e.principals.Get(ctx, u.ID)
		read <- result{banned: snap.Banned, err: err}
	}()
	select {
	case got := <-read:
		t.Fatalf("principal Get bypassed real Ban mutation barrier: %+v", got)
	case <-time.After(25 * time.Millisecond):
	}

	committed, err := e.stores.Users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !committed.BannedAt.Valid {
		t.Fatal("commit gate fired before the Ban transaction became visible")
	}
	commitGate.unblock()
	if err := <-mutation; err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-read:
		if got.err != nil || !got.banned {
			t.Fatalf("principal Get after Ban = %+v, want banned snapshot", got)
		}
	case <-time.After(time.Second):
		t.Fatal("principal Get did not resume after real Ban committed")
	}
}

func TestPrincipalMutationLocksSortOverlappingUsers(t *testing.T) {
	e := newEnv(t)
	first := e.createUser(t, "alice", "password", "member")
	second := e.createUser(t, "bob", "password", "member")
	third := e.createUser(t, "carol", "password", "member")

	unlockFirst := e.principals.LockMutation(first.ID, second.ID)
	lockedSecond := make(chan func(), 1)
	var wg sync.WaitGroup
	wg.Go(func() { lockedSecond <- e.principals.LockMutation(second.ID, first.ID) })
	select {
	case unlock := <-lockedSecond:
		unlock()
		t.Fatal("overlapping mutation locks did not serialize")
	case <-time.After(25 * time.Millisecond):
	}

	independent := make(chan error, 1)
	wg.Go(func() {
		_, err := e.principals.Get(context.Background(), third.ID)
		independent <- err
	})
	select {
	case err := <-independent:
		if err != nil {
			t.Fatalf("independent principal Get = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unrelated principal read was blocked")
	}

	unlockFirst()
	select {
	case unlock := <-lockedSecond:
		unlock()
	case <-time.After(time.Second):
		t.Fatal("overlapping mutation lock did not resume")
	}
	wg.Wait()
}

func TestPrincipalLoaderReadsCommittedSnapshotDuringSQLiteWrite(t *testing.T) {
	e, queryGate, _ := newGatedPrincipalEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "password", "member")
	queryGate.enable()

	type result struct {
		banned bool
		roles  []string
		err    error
	}
	loaded := make(chan result, 1)
	go func() {
		snap, err := e.principals.Get(ctx, u.ID)
		loaded <- result{banned: snap.Banned, roles: snap.Roles, err: err}
	}()
	select {
	case <-queryGate.started:
	case got := <-loaded:
		t.Fatalf("loader completed before the user-query gate: %+v", got)
	case <-time.After(time.Second):
		t.Fatal("PrincipalCache loader did not reach the user-query gate")
	}

	tx, err := e.stores.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	txStores := e.stores.WithTx(tx)
	if err := txStores.Users.Ban(ctx, u.ID); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := txStores.Users.SetRoles(ctx, u.ID, []string{"admin"}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	queryGate.unblock()
	select {
	case got := <-loaded:
		if got.err != nil || got.banned || len(got.roles) != 1 || got.roles[0] != "member" {
			t.Fatalf("loader observed mixed snapshot: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("real PrincipalCache loader did not resume after query gate")
	}

	e.principals.Invalidate(u.ID)
	snap, err := e.principals.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Banned || len(snap.Roles) != 1 || snap.Roles[0] != "admin" {
		t.Fatalf("loader did not observe complete committed state: %+v", snap)
	}
}

func waitForDBConnections(t *testing.T, e *env, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for e.conn.Stats().InUse < want {
		if time.Now().After(deadline) {
			t.Fatalf("database connections in use = %d, want at least %d", e.conn.Stats().InUse, want)
		}
		time.Sleep(time.Millisecond)
	}
}
