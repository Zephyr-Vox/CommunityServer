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
	// ErrConflict is returned when a write violates a unique or referential
	// constraint that represents a conflicting persisted resource state.
	ErrConflict = errors.New("store: conflict")
	// ErrSessionReused is returned when a rotated refresh token is presented again.
	ErrSessionReused = errors.New("store: session token reuse detected")
	// ErrOwnerBindingProtected is returned when a generic binding operation
	// attempts to grant or revoke owner. First activation and owner transfer
	// are the only paths allowed to change the unique owner binding.
	ErrOwnerBindingProtected = errors.New("store: owner binding is protected")
	// ErrBuiltinRoleProtected is returned when a generic role mutation attempts
	// to delete a built-in role or change immutable owner fields.
	ErrBuiltinRoleProtected = errors.New("store: built-in role is protected")
	// ErrOwnerTransferForbidden is returned when a transfer caller is not the
	// current owner of an initialized installation.
	ErrOwnerTransferForbidden = errors.New("store: owner transfer forbidden")
	// ErrOwnerTransferTarget is returned when an owner transfer target is the
	// current owner or is banned.
	ErrOwnerTransferTarget = errors.New("store: invalid owner transfer target")
	// ErrInstallationInvariant is returned when persisted installation state
	// and owner bindings do not satisfy their required relationship.
	ErrInstallationInvariant = errors.New("store: installation invariant violated")
	// ErrTransactionRequired is returned when an internal owner mutation is
	// attempted outside a caller-owned transaction.
	ErrTransactionRequired = errors.New("store: transaction required")
	// ErrInvalidPermissionConfig is returned when a config references an
	// unknown role/permission or violates scope and owner constraints.
	ErrInvalidPermissionConfig = errors.New("store: invalid permission config")
	// ErrInvalidStore is returned when a store operation receives a nil Stores
	// receiver.
	ErrInvalidStore = errors.New("store: invalid stores")
)

// SQLite extended result code for SQLITE_CONSTRAINT_UNIQUE.
const sqliteConstraintUnique = 2067

// mapError translates database sentinel errors into store-level errors.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if isUniqueConstraint(err) || isForeignKeyConstraint(err) {
		return ErrConflict
	}
	return err
}

// isUniqueConstraint reports whether err represents SQLite's unique constraint.
func isUniqueConstraint(err error) bool {
	if sqliteErr, ok := errors.AsType[*sqlite.Error](err); ok {
		if sqliteErr.Code() == sqliteConstraintUnique {
			return true
		}
		return strings.Contains(sqliteErr.Error(), "UNIQUE constraint failed")
	}
	return false
}

// isForeignKeyConstraint reports whether err represents SQLite rejecting a
// referenced-row deletion or a missing foreign-key target. modernc.org/sqlite
// may surface this through SQLITE_CONSTRAINT_TRIGGER, so the stable driver text
// is also part of the narrow check.
func isForeignKeyConstraint(err error) bool {
	if sqliteErr, ok := errors.AsType[*sqlite.Error](err); ok {
		return strings.Contains(sqliteErr.Error(), "FOREIGN KEY constraint failed")
	}
	return false
}

// nullString converts an optional string to its SQL representation.
func nullString(v *string) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *v, Valid: true}
}

// nullInt64 converts an optional integer to its SQL representation.
func nullInt64(v *int64) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *v, Valid: true}
}
