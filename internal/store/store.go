// Package store provides business-facing data access on top of the
// sqlc-generated queries. It owns error mapping, null conversion, ID
// generation and transaction boundaries that stay inside one aggregate.
package store

import (
	"database/sql"
	"errors"
	"strings"

	"modernc.org/sqlite"
)

var (
	// ErrNotFound is returned when a single row lookup comes back empty.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when an insert or update violates a unique constraint.
	ErrConflict = errors.New("store: conflict")
	// ErrSessionReused is returned when a rotated refresh token is presented again.
	ErrSessionReused = errors.New("store: session token reuse detected")
)

// SQLite extended result code for SQLITE_CONSTRAINT_UNIQUE.
const sqliteConstraintUnique = 2067

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	return err
}

func isUniqueConstraint(err error) bool {
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		if sqliteErr.Code() == sqliteConstraintUnique {
			return true
		}
		return strings.Contains(sqliteErr.Error(), "UNIQUE constraint failed")
	}
	return false
}

func nullString(v *string) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *v, Valid: true}
}

func nullInt64(v *int64) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *v, Valid: true}
}
