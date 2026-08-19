package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
)

const (
	ownerRole  = "owner"
	adminRole  = "admin"
	memberRole = "member"
)

// SeedAndVerify creates the built-in installation records on a new database
// and verifies every persisted bootstrap invariant before the server opens a
// listener. Existing editable role fields are never reset by a later startup.
func (s *Stores) SeedAndVerify(ctx context.Context) error {
	tx, err := s.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	txStores := s.WithTx(tx)

	created, err := txStores.Installation.Seed(ctx)
	if err != nil {
		return err
	}
	now := s.Users.now()
	for _, role := range []db.SeedRoleParams{
		{Key: ownerRole, DisplayName: "Owner", Rank: 1_000_000, Builtin: 1, Immutable: 1, CreatedAt: now, UpdatedAt: now, Version: 1},
		{Key: adminRole, DisplayName: "Admin", Rank: 1_000, Builtin: 1, Immutable: 0, CreatedAt: now, UpdatedAt: now, Version: 1},
		{Key: memberRole, DisplayName: "Member", Rank: 0, Builtin: 1, Immutable: 0, CreatedAt: now, UpdatedAt: now, Version: 1},
	} {
		if err := txStores.Roles.q.SeedRole(ctx, role); err != nil {
			return mapError(err)
		}
	}
	config, err := rbac.DefaultServerPermissionConfig()
	if err != nil {
		return fmt.Errorf("store: encode default permission config: %w", err)
	}
	if err := txStores.Roles.q.SeedServerPermissionConfig(ctx, db.SeedServerPermissionConfigParams{
		Config:    config,
		UpdatedAt: now,
	}); err != nil {
		return mapError(err)
	}
	if created {
		if _, err := txStores.Channels.Create(ctx, ChannelInput{
			Name:       "Announcements",
			Mode:       "announcement",
			Temporary:  0,
			Visibility: "public",
			Capacity:   256,
			Position:   0,
			Pinned:     0,
		}); err != nil {
			return err
		}
	}
	if err := verifyInstallation(ctx, txStores); err != nil {
		return err
	}
	return tx.Commit()
}

// VerifyInstallation checks the persisted bootstrap state without changing
// it. It is useful to re-check the invariant after direct test mutations.
func (s *Stores) VerifyInstallation(ctx context.Context) error {
	return verifyInstallation(ctx, s)
}

// verifyInstallation enforces the cross-row owner and built-in role rules
// that SQLite CHECK constraints cannot express by themselves.
func verifyInstallation(ctx context.Context, s *Stores) error {
	state, err := s.Installation.Get(ctx)
	if err != nil {
		return fmt.Errorf("store: installation state: %w", err)
	}
	roles, err := s.Roles.List(ctx)
	if err != nil {
		return fmt.Errorf("store: list roles: %w", err)
	}
	byKey := make(map[string]db.Role, len(roles))
	for _, role := range roles {
		byKey[role.Key] = role
	}
	owner, ok := byKey[ownerRole]
	if !ok || owner.Rank != 1_000_000 || owner.Builtin != 1 || owner.Immutable != 1 {
		return errors.New("store: owner role invariant violated")
	}
	for _, key := range []string{adminRole, memberRole} {
		role, ok := byKey[key]
		if !ok || role.Builtin != 1 || role.Immutable != 0 || role.Rank >= 1_000_000 {
			return fmt.Errorf("store: builtin role %q invariant violated", key)
		}
	}
	config, err := s.Configs.Server(ctx)
	if err != nil {
		return fmt.Errorf("store: server permission config: %w", err)
	}
	if err := validatePermissionConfig(config, byKey); err != nil {
		return err
	}
	owners, err := s.Installation.CountOwners(ctx)
	if err != nil {
		return fmt.Errorf("store: count owners: %w", err)
	}
	if state.Initialized == 0 && owners != 0 {
		return fmt.Errorf("store: uninitialized installation has %d owners", owners)
	}
	if state.Initialized == 1 && owners != 1 {
		return fmt.Errorf("store: initialized installation has %d owners", owners)
	}
	if state.Initialized != 0 && state.Initialized != 1 {
		return errors.New("store: invalid installation state")
	}
	return nil
}

// validatePermissionConfig checks references and rejects wildcard grants on
// non-owner roles before a server can start using the config.
func validatePermissionConfig(raw string, roles map[string]db.Role) error {
	var config map[string][]string
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return fmt.Errorf("store: invalid server permission config: %w", err)
	}
	for key, permissions := range config {
		if _, ok := roles[key]; !ok {
			return fmt.Errorf("store: permission config references unknown role %q", key)
		}
		for _, permission := range permissions {
			if permission == string(rbac.Wildcard) {
				if key != ownerRole {
					return fmt.Errorf("store: non-owner role %q grants wildcard", key)
				}
				continue
			}
			if !rbac.IsKnown(rbac.Permission(permission)) {
				return fmt.Errorf("store: permission config references unknown permission %q", permission)
			}
		}
	}
	for _, key := range []string{ownerRole, adminRole, memberRole} {
		if _, ok := config[key]; !ok {
			return fmt.Errorf("store: permission config is missing role %q", key)
		}
	}
	ownerPermissions := config[ownerRole]
	if len(ownerPermissions) != 1 || ownerPermissions[0] != string(rbac.Wildcard) {
		return errors.New("store: owner permission config must grant only wildcard")
	}
	return nil
}
