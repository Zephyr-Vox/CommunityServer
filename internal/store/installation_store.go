package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"zephyr.vox/server/ce/internal/db"
)

// InstallationStore persists the singleton bootstrap marker and owner count.
type InstallationStore struct {
	q *db.Queries
}

// Get returns the singleton installation state, or ErrNotFound.
func (s *InstallationStore) Get(ctx context.Context) (*db.InstallationState, error) {
	state, err := s.q.GetInstallationState(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return &state, nil
}

// Seed creates the singleton marker when this is a new database and reports
// whether this call inserted it.
func (s *InstallationStore) Seed(ctx context.Context) (bool, error) {
	installationID, err := newInstallationID()
	if err != nil {
		return false, err
	}
	rows, err := s.q.SeedInstallationState(ctx, installationID)
	if err != nil {
		return false, mapError(err)
	}
	return rows == 1, nil
}

// newInstallationID returns the stable 128-bit identity stored with the
// singleton installation row. It is generated for every seed attempt, but
// INSERT OR IGNORE preserves the first value across restarts and retries.
func newInstallationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// SetInitialized changes the marker only when it still has expected value.
// This compare-and-set is used by first-owner activation inside its transaction.
func (s *InstallationStore) SetInitialized(ctx context.Context, from, to int64) error {
	rows, err := s.q.SetInstallationInitialized(ctx, db.SetInstallationInitializedParams{
		Initialized:   to,
		Initialized_2: from,
	})
	if err != nil {
		return mapError(err)
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

// CountOwners returns the number of owner bindings in the database.
func (s *InstallationStore) CountOwners(ctx context.Context) (int64, error) {
	count, err := s.q.CountOwners(ctx)
	if err != nil {
		return 0, mapError(err)
	}
	return count, nil
}

// ActivateFirstOwner adds the unique owner binding and marks an uninitialized
// installation initialized. It must run on Stores returned by WithTx so a
// failed account activation cannot leave either row committed by itself.
func (s *Stores) ActivateFirstOwner(ctx context.Context, userID int64) error {
	if s.conn != nil {
		return ErrTransactionRequired
	}
	state, err := s.Installation.Get(ctx)
	if err != nil {
		return err
	}
	owners, err := s.Installation.CountOwners(ctx)
	if err != nil {
		return err
	}
	if state.Initialized != 0 || owners != 0 {
		return ErrConflict
	}
	if _, err := s.Roles.insertOwnerBinding(ctx, userID); err != nil {
		return err
	}
	if err := s.Installation.SetInitialized(ctx, 0, 1); err != nil {
		return err
	}
	owners, err = s.Installation.CountOwners(ctx)
	if err != nil {
		return err
	}
	if owners != 1 {
		return ErrInstallationInvariant
	}
	return nil
}

// TransferOwner atomically replaces both users' server bindings, promotes the
// target to owner, demotes the previous owner to member, and clears the new
// owner's mutes. Scoped bindings are intentionally preserved.
func (s *Stores) TransferOwner(ctx context.Context, currentUserID, targetUserID int64) error {
	if s.conn == nil {
		return ErrTransactionRequired
	}
	if currentUserID == targetUserID {
		return ErrOwnerTransferTarget
	}
	tx, err := s.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.WithTx(tx).TransferOwnerInTx(ctx, currentUserID, targetUserID); err != nil {
		return err
	}
	return tx.Commit()
}

// TransferOwnerInTx performs the owner replacement inside a caller-owned
// transaction. The delete-before-insert order is required by the immediate
// owner unique index and deliberately permits zero owners only transiently.
func (s *Stores) TransferOwnerInTx(ctx context.Context, currentUserID, targetUserID int64) error {
	if s == nil || s.conn != nil {
		return ErrTransactionRequired
	}
	if currentUserID == targetUserID {
		return ErrOwnerTransferTarget
	}
	state, err := s.Installation.Get(ctx)
	if err != nil {
		return err
	}
	owners, err := s.Installation.CountOwners(ctx)
	if err != nil {
		return err
	}
	if state.Initialized != 1 || owners != 1 {
		return ErrInstallationInvariant
	}
	owner, err := s.Roles.q.GetOwnerBinding(ctx)
	if err != nil {
		return mapError(err)
	}
	if owner.UserID != currentUserID {
		return ErrOwnerTransferForbidden
	}
	target, err := s.Users.GetUserByID(ctx, targetUserID)
	if err != nil {
		return err
	}
	if target.BannedAt.Valid {
		return ErrOwnerTransferTarget
	}

	if err := s.Roles.q.DeleteServerRoleBindingsForUser(ctx, targetUserID); err != nil {
		return mapError(err)
	}
	if err := s.Roles.q.DeleteServerRoleBindingsForUser(ctx, currentUserID); err != nil {
		return mapError(err)
	}
	if _, err := s.Roles.insertBinding(ctx, currentUserID, "member", "server", nil, nil); err != nil {
		return err
	}
	if _, err := s.Roles.insertOwnerBinding(ctx, targetUserID); err != nil {
		return err
	}
	if err := s.Mutes.q.DeleteMutesForUser(ctx, targetUserID); err != nil {
		return mapError(err)
	}
	owners, err = s.Installation.CountOwners(ctx)
	if err != nil {
		return err
	}
	if owners != 1 {
		return ErrInstallationInvariant
	}
	return nil
}
