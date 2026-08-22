package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
)

// ConfigStore persists local permission-config snapshots. Inheritance is
// represented by the absence of a group/channel row.
type ConfigStore struct {
	q     *db.Queries
	roles *RoleStore
	now   func() int64
}

// ConfigScope identifies the server root or one local group/channel config.
// ID is nil only for the server scope.
type ConfigScope struct {
	Type string
	ID   *int64
}

// EffectiveConfig reports the requested scope's optional local snapshot and
// the nearest persisted snapshot that supplies its effective permissions.
type EffectiveConfig struct {
	Scope  ConfigScope
	Local  *db.ScopePermissionConfig
	Source db.ScopePermissionConfig
}

// Server returns the mandatory server root config.
func (s *ConfigStore) Server(ctx context.Context) (string, error) {
	config, err := s.q.GetServerPermissionConfig(ctx)
	if err != nil {
		return "", mapError(err)
	}
	return config, nil
}

// ServerRow returns the mandatory server root permission configuration.
func (s *ConfigStore) ServerRow(ctx context.Context) (*db.ScopePermissionConfig, error) {
	config, err := s.q.GetServerPermissionConfigRow(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return &config, nil
}

// Group returns a local group config, or ErrNotFound when it inherits.
func (s *ConfigStore) Group(ctx context.Context, groupID int64) (*db.ScopePermissionConfig, error) {
	config, err := s.q.GetGroupPermissionConfig(ctx, sql.NullInt64{Int64: groupID, Valid: true})
	if err != nil {
		return nil, mapError(err)
	}
	return &config, nil
}

// Channel returns a local channel config, or ErrNotFound when it inherits.
func (s *ConfigStore) Channel(ctx context.Context, channelID int64) (*db.ScopePermissionConfig, error) {
	config, err := s.q.GetChannelPermissionConfig(ctx, sql.NullInt64{Int64: channelID, Valid: true})
	if err != nil {
		return nil, mapError(err)
	}
	return &config, nil
}

// ListAll returns every local permission configuration in deterministic scope
// order for an internal state projection.
func (s *ConfigStore) ListAll(ctx context.Context) ([]db.ScopePermissionConfig, error) {
	configs, err := s.q.ListPermissionConfigs(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return configs, nil
}

// PutGroup stores a local group config snapshot.
func (s *ConfigStore) PutGroup(ctx context.Context, groupID int64, config string, version, now int64) (*db.ScopePermissionConfig, error) {
	config, err := s.normalize(ctx, "group", config)
	if err != nil {
		return nil, err
	}
	row, err := s.q.UpsertGroupPermissionConfig(ctx, db.UpsertGroupPermissionConfigParams{
		GroupID:   sql.NullInt64{Int64: groupID, Valid: true},
		Config:    config,
		UpdatedAt: now,
		Version:   version,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &row, nil
}

// PutChannel stores a local channel config snapshot.
func (s *ConfigStore) PutChannel(ctx context.Context, channelID int64, config string, version, now int64) (*db.ScopePermissionConfig, error) {
	config, err := s.normalize(ctx, "channel", config)
	if err != nil {
		return nil, err
	}
	row, err := s.q.UpsertChannelPermissionConfig(ctx, db.UpsertChannelPermissionConfigParams{
		ChannelID: sql.NullInt64{Int64: channelID, Valid: true},
		Config:    config,
		UpdatedAt: now,
		Version:   version,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &row, nil
}

// ResetGroup removes a local group snapshot and restores inheritance.
func (s *ConfigStore) ResetGroup(ctx context.Context, groupID int64) error {
	_, err := s.q.DeleteGroupPermissionConfig(ctx, sql.NullInt64{Int64: groupID, Valid: true})
	return mapError(err)
}

// ResetChannel removes a local channel snapshot and restores inheritance.
func (s *ConfigStore) ResetChannel(ctx context.Context, channelID int64) error {
	_, err := s.q.DeleteChannelPermissionConfig(ctx, sql.NullInt64{Int64: channelID, Valid: true})
	return mapError(err)
}

// Effective resolves the requested scope's effective config. Group and channel
// rows are local snapshots only; their absence means inherit from the nearest
// parent, ultimately the mandatory server root.
func (s *ConfigStore) Effective(ctx context.Context, scope ConfigScope) (*EffectiveConfig, error) {
	if err := validateConfigScope(scope); err != nil {
		return nil, err
	}
	root, err := s.ServerRow(ctx)
	if err != nil {
		return nil, err
	}
	if scope.Type == "server" {
		return &EffectiveConfig{Scope: scope, Local: root, Source: *root}, nil
	}
	if scope.Type == "group" {
		if _, err := s.q.GetChannelGroup(ctx, *scope.ID); err != nil {
			return nil, mapError(err)
		}
		local, err := s.Group(ctx, *scope.ID)
		if errors.Is(err, ErrNotFound) {
			return &EffectiveConfig{Scope: scope, Source: *root}, nil
		}
		if err != nil {
			return nil, err
		}
		return &EffectiveConfig{Scope: scope, Local: local, Source: *local}, nil
	}

	channel, err := s.q.GetChannel(ctx, *scope.ID)
	if err != nil {
		return nil, mapError(err)
	}
	local, err := s.Channel(ctx, *scope.ID)
	if err == nil {
		return &EffectiveConfig{Scope: scope, Local: local, Source: *local}, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if channel.GroupID.Valid {
		group, err := s.Group(ctx, channel.GroupID.Int64)
		if err == nil {
			return &EffectiveConfig{Scope: scope, Source: *group}, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	return &EffectiveConfig{Scope: scope, Source: *root}, nil
}

// Update stores a complete local snapshot, or replaces the server root config.
// The resulting row is always the local and effective source for scope.
func (s *ConfigStore) Update(ctx context.Context, scope ConfigScope, raw string) (*EffectiveConfig, error) {
	if err := validateConfigScope(scope); err != nil {
		return nil, err
	}
	if scope.Type == "server" {
		config, err := s.normalize(ctx, "server", raw)
		if err != nil {
			return nil, err
		}
		if err := validateRootConfig(config); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidPermissionConfig, err)
		}
		row, err := s.q.UpdateServerPermissionConfig(ctx, db.UpdateServerPermissionConfigParams{
			Config:    config,
			UpdatedAt: s.now(),
		})
		if err != nil {
			return nil, mapError(err)
		}
		return &EffectiveConfig{Scope: scope, Local: &row, Source: row}, nil
	}
	if _, err := s.Effective(ctx, scope); err != nil {
		return nil, err
	}
	var localVersion int64
	if scope.Type == "group" {
		local, err := s.Group(ctx, *scope.ID)
		if err == nil {
			localVersion = local.Version
		} else if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		row, err := s.PutGroup(ctx, *scope.ID, raw, localVersion+1, s.now())
		if err != nil {
			return nil, err
		}
		return &EffectiveConfig{Scope: scope, Local: row, Source: *row}, nil
	}
	local, err := s.Channel(ctx, *scope.ID)
	if err == nil {
		localVersion = local.Version
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	row, err := s.PutChannel(ctx, *scope.ID, raw, localVersion+1, s.now())
	if err != nil {
		return nil, err
	}
	return &EffectiveConfig{Scope: scope, Local: row, Source: *row}, nil
}

// Reset removes a group/channel local snapshot and restores inheritance. A
// server reset replaces the root row with the default built-in permission map.
func (s *ConfigStore) Reset(ctx context.Context, scope ConfigScope) (*EffectiveConfig, error) {
	if err := validateConfigScope(scope); err != nil {
		return nil, err
	}
	if scope.Type == "server" {
		config, err := rbac.DefaultServerPermissionConfig()
		if err != nil {
			return nil, err
		}
		return s.Update(ctx, scope, config)
	}
	if _, err := s.Effective(ctx, scope); err != nil {
		return nil, err
	}
	if scope.Type == "group" {
		if err := s.ResetGroup(ctx, *scope.ID); err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	} else if err := s.ResetChannel(ctx, *scope.ID); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return s.Effective(ctx, scope)
}

// normalize validates references and scope-compatible permissions, removes
// duplicates and returns canonical JSON for persisted local snapshots.
func (s *ConfigStore) normalize(ctx context.Context, scopeType, raw string) (string, error) {
	var config map[string][]string
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return "", fmt.Errorf("%w: decode: %w", ErrInvalidPermissionConfig, err)
	}
	if config == nil {
		return "", fmt.Errorf("%w: config must be a JSON object", ErrInvalidPermissionConfig)
	}
	canonical := make(map[string][]string, len(config))
	for roleKey, rawPermissions := range config {
		if _, err := s.roles.Get(ctx, roleKey); err != nil {
			return "", fmt.Errorf("%w: role %q: %w", ErrInvalidPermissionConfig, roleKey, err)
		}
		seen := make(map[string]struct{}, len(rawPermissions))
		permissions := make([]string, 0, len(rawPermissions))
		for _, rawPermission := range rawPermissions {
			if rawPermission == string(rbac.Wildcard) {
				if roleKey != ownerRole {
					return "", fmt.Errorf("%w: non-owner role %q grants wildcard", ErrInvalidPermissionConfig, roleKey)
				}
			} else if !rbac.IsKnown(rbac.Permission(rawPermission)) || !rbac.AllowedAtScope(scopeType, rbac.Permission(rawPermission)) {
				return "", fmt.Errorf("%w: permission %q is invalid at %s scope", ErrInvalidPermissionConfig, rawPermission, scopeType)
			}
			if _, duplicate := seen[rawPermission]; duplicate {
				continue
			}
			seen[rawPermission] = struct{}{}
			permissions = append(permissions, rawPermission)
		}
		if roleKey == ownerRole && (len(permissions) != 1 || permissions[0] != string(rbac.Wildcard)) {
			return "", fmt.Errorf("%w: owner config must grant only wildcard", ErrInvalidPermissionConfig)
		}
		slices.Sort(permissions)
		canonical[roleKey] = permissions
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("%w: encode: %w", ErrInvalidPermissionConfig, err)
	}
	return string(encoded), nil
}

// validateConfigScope checks exact scope ID nullness before querying rows.
func validateConfigScope(scope ConfigScope) error {
	if scope.Type == "server" && scope.ID == nil {
		return nil
	}
	if (scope.Type == "group" || scope.Type == "channel") && scope.ID != nil && *scope.ID > 0 {
		return nil
	}
	return errors.New("store: invalid permission config scope")
}

// validateRootConfig preserves the bootstrap requirement that every built-in
// role remains represented and owner stays an explicit wildcard grant.
func validateRootConfig(raw string) error {
	var config map[string][]string
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return fmt.Errorf("%w: decode root config: %w", ErrInvalidPermissionConfig, err)
	}
	for _, role := range []string{ownerRole, adminRole, memberRole} {
		if _, ok := config[role]; !ok {
			return fmt.Errorf("%w: root config is missing role %q", ErrInvalidPermissionConfig, role)
		}
	}
	if permissions := config[ownerRole]; len(permissions) != 1 || permissions[0] != string(rbac.Wildcard) {
		return fmt.Errorf("%w: root owner config must grant only wildcard", ErrInvalidPermissionConfig)
	}
	return nil
}
