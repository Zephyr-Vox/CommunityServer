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

	// Users manages user accounts.
	Users *UserStore
	// Roles manages role definitions and server permission configuration.
	Roles *RoleStore
	// Installation manages the singleton bootstrap marker.
	Installation *InstallationStore
	// Channels manages persisted groups and channels without runtime membership.
	Channels *ChannelStore
	// Access manages group and channel ACL entries.
	Access *AccessStore
	// Configs manages local permission config snapshots.
	Configs *ConfigStore
	// Mutes manages persisted moderation mutes.
	Mutes *MuteStore
	// Sessions manages per-device login sessions and refresh token rotation.
	Sessions *SessionStore
	// Invites manages registration invite codes.
	Invites *InviteStore
}

// New builds the stores over a connection. The idGen supplies snowflake IDs
// for every new row; now returns Unix milliseconds and is injectable for tests.
func New(conn *sql.DB, idGen *snowflake.IDGenerator, now func() int64) *Stores {
	q := db.New(conn)
	roles := &RoleStore{q: q, idGen: idGen, now: now}
	return &Stores{
		conn:         conn,
		Users:        &UserStore{conn: conn, q: q, idGen: idGen, now: now},
		Roles:        roles,
		Installation: &InstallationStore{q: q},
		Channels:     &ChannelStore{q: q, idGen: idGen, now: now},
		Access:       &AccessStore{q: q, idGen: idGen, now: now},
		Configs:      &ConfigStore{q: q, roles: roles, now: now},
		Mutes:        &MuteStore{q: q, idGen: idGen, now: now},
		Sessions:     &SessionStore{q: q, idGen: idGen, now: now},
		Invites:      &InviteStore{q: q, idGen: idGen, now: now},
	}
}

// BeginTx starts a transaction on the root connection. Use WithTx to get
// stores bound to it; the caller owns Commit and Rollback.
func (s *Stores) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return s.conn.BeginTx(ctx, nil)
}

// BeginReadTx starts a read-only transaction for snapshots that must observe
// multiple related queries from one database view.
func (s *Stores) BeginReadTx(ctx context.Context) (*sql.Tx, error) {
	return s.conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
}

// WithTx returns stores bound to tx. The returned stores share idGen and clock
// but not the root conn.
func (s *Stores) WithTx(tx *sql.Tx) *Stores {
	q := db.New(tx)
	roles := &RoleStore{q: q, idGen: s.Roles.idGen, now: s.Roles.now}
	return &Stores{
		conn:         nil,
		Users:        &UserStore{conn: nil, q: q, idGen: s.Users.idGen, now: s.Users.now},
		Roles:        roles,
		Installation: &InstallationStore{q: q},
		Channels:     &ChannelStore{q: q, idGen: s.Channels.idGen, now: s.Channels.now},
		Access:       &AccessStore{q: q, idGen: s.Access.idGen, now: s.Access.now},
		Configs:      &ConfigStore{q: q, roles: roles, now: s.Configs.now},
		Mutes:        &MuteStore{q: q, idGen: s.Mutes.idGen, now: s.Mutes.now},
		Sessions:     &SessionStore{q: q, idGen: s.Sessions.idGen, now: s.Sessions.now},
		Invites:      &InviteStore{q: q, idGen: s.Invites.idGen, now: s.Invites.now},
	}
}
