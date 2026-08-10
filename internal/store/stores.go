package store

import (
	"database/sql"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/snowflake"
)

// Stores bundles the domain stores that share one connection.
type Stores struct {
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
		Users:    &UserStore{conn: conn, q: q, idGen: idGen, now: now},
		Sessions: &SessionStore{q: q, idGen: idGen, now: now},
		Invites:  &InviteStore{q: q, idGen: idGen, now: now},
	}
}
