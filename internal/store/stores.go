package store

import (
	"context"
	"database/sql"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/snowflake"
)

// Stores bundles the domain stores that share one connection.
type Stores struct {
	conn *sql.DB // nil on transaction-bound stores

	// Users manages user accounts and their roles.
	Users *UserStore
	// Sessions manages per-device login sessions and refresh token rotation.
	Sessions *SessionStore
	// Invites manages registration invite codes.
	Invites *InviteStore
}

// New builds the stores over a connection. The idGen supplies snowflake IDs
// for every new row; now returns Unix milliseconds and is injectable for tests.
func New(conn *sql.DB, idGen *snowflake.IDGenerator, now func() int64) *Stores {
	q := db.New(conn)
	return &Stores{
		conn:     conn,
		Users:    &UserStore{conn: conn, q: q, idGen: idGen, now: now},
		Sessions: &SessionStore{q: q, idGen: idGen, now: now},
		Invites:  &InviteStore{q: q, idGen: idGen, now: now},
	}
}

// BeginTx starts a transaction on the root connection. Use WithTx to get
// stores bound to it; the caller owns Commit and Rollback.
func (s *Stores) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return s.conn.BeginTx(ctx, nil)
}

// WithTx returns stores bound to tx. Store methods that normally open their
// own transaction (SetRoles) run directly on the caller-owned transaction
// instead. The returned stores share idGen and clock but not the root conn.
func (s *Stores) WithTx(tx *sql.Tx) *Stores {
	q := db.New(tx)
	return &Stores{
		conn:     nil,
		Users:    &UserStore{conn: nil, q: q, idGen: s.Users.idGen, now: s.Users.now},
		Sessions: &SessionStore{q: q, idGen: s.Sessions.idGen, now: s.Sessions.now},
		Invites:  &InviteStore{q: q, idGen: s.Invites.idGen, now: s.Invites.now},
	}
}
