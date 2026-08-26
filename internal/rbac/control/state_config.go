package control

import (
	"context"
	"database/sql"
	"errors"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
	rbacscope "zephyr.vox/server/ce/internal/rbac/scope"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

// currentState returns the process's immutable projection while rejecting a
// partially assembled or already stopped RBAC command runtime.
func (s *Service) currentState() (*realtime.StateVersion, error) {
	if s == nil || s.state == nil || s.visibility == nil || s.scopedAuth == nil {
		return nil, ErrRealtimeUnavailable
	}
	version := s.state.Current()
	if version == nil {
		return nil, ErrRealtimeUnavailable
	}
	return version, nil
}

// visibleConfigScope applies the privacy boundary for a config's concrete group
// or channel scope. It returns the actor's server authority so callers can
// apply an authorization check after preserving private-resource 404 semantics.
func (s *Service) visibleConfigScope(actorID int64, scope store.ConfigScope, version *realtime.StateVersion) (rbacscope.Authority, error) {
	target, err := configScopeToRealtime(scope)
	if err != nil {
		return rbacscope.Authority{}, ErrInvalidScope
	}
	user, exists := version.User(actorID)
	if !exists || user.Banned {
		return rbacscope.Authority{}, ErrRoleManageRequired
	}
	authority, err := s.scopedAuth.Authority(actorID, realtime.Scope{Type: "server"}, version)
	if err != nil {
		return rbacscope.Authority{}, err
	}
	if !authority.Owner {
		switch target.Type {
		case "group":
			if !s.visibility.CanSeeGroup(actorID, target.ID, version) {
				return rbacscope.Authority{}, store.ErrNotFound
			}
		case "channel":
			if !s.visibility.CanAccessChannel(actorID, target.ID, version) {
				return rbacscope.Authority{}, store.ErrNotFound
			}
		}
	}
	return authority, nil
}

// authorizeConfigScope verifies server role.manage after applying the scope
// privacy boundary. Read handlers use it without a transaction; mutations also
// recheck the same permission from their transaction-bound database view.
func (s *Service) authorizeConfigScope(_ context.Context, actorID int64, scope store.ConfigScope, version *realtime.StateVersion) error {
	if _, err := s.visibleConfigScope(actorID, scope, version); err != nil {
		return err
	}
	decision, err := s.scopedAuth.Decide(actorID, realtime.Scope{Type: "server"}, rbac.PermRoleManage, version)
	if err != nil {
		return err
	}
	if !decision.Allow {
		return ErrRoleManageRequired
	}
	return nil
}

// configScopeToRealtime converts one validated store scope to the immutable
// StateStore form and rejects mismatched nullable IDs before any lookup.
func configScopeToRealtime(scope store.ConfigScope) (realtime.Scope, error) {
	if scope.Type == "server" && scope.ID == nil {
		return realtime.Scope{Type: "server"}, nil
	}
	if (scope.Type == "group" || scope.Type == "channel") && scope.ID != nil && *scope.ID > 0 {
		return realtime.Scope{Type: scope.Type, ID: *scope.ID}, nil
	}
	return realtime.Scope{}, errors.New("rbac control: invalid config scope")
}

// effectiveConfigFromState resolves a config from one immutable StateVersion.
// It mirrors ConfigStore inheritance without querying SQLite, ensuring HTTP GET
// cannot observe a committed database row before its publication is visible.
func effectiveConfigFromState(scope store.ConfigScope, version *realtime.StateVersion) (*store.EffectiveConfig, error) {
	target, err := configScopeToRealtime(scope)
	if err != nil || version == nil {
		return nil, ErrInvalidScope
	}
	if target.Type == "group" {
		if _, exists := version.Group(target.ID); !exists {
			return nil, store.ErrNotFound
		}
	}
	if target.Type == "channel" {
		if _, exists := version.Channel(target.ID); !exists {
			return nil, store.ErrNotFound
		}
	}
	root, exists := version.Config(realtime.Scope{Type: "server"})
	if !exists {
		return nil, ErrRealtimeUnavailable
	}
	if local, exists := version.Config(target); exists {
		row := configRowFromState(local)
		return &store.EffectiveConfig{Scope: scope, Local: &row, Source: row}, nil
	}
	if target.Type == "channel" {
		channel, _ := version.Channel(target.ID)
		if channel.GroupID != nil {
			if parent, exists := version.Config(realtime.Scope{Type: "group", ID: *channel.GroupID}); exists {
				return &store.EffectiveConfig{Scope: scope, Source: configRowFromState(parent)}, nil
			}
		}
	}
	return &store.EffectiveConfig{Scope: scope, Source: configRowFromState(root)}, nil
}

// configRowFromState converts a published permission config into the store DTO
// consumed by the existing response and ETag helpers.
func configRowFromState(config realtime.PermissionConfig) db.ScopePermissionConfig {
	row := db.ScopePermissionConfig{
		ScopeType: config.Scope.Type,
		Config:    config.Config,
		UpdatedAt: config.UpdatedAt,
		Version:   config.Version,
	}
	if config.Scope.Type == "group" {
		row.GroupID = sql.NullInt64{Int64: config.Scope.ID, Valid: true}
	}
	if config.Scope.Type == "channel" {
		row.ChannelID = sql.NullInt64{Int64: config.Scope.ID, Valid: true}
	}
	return row
}

// effectiveConfigETag returns the quoted ETag for the exact local/inherited
// config fact represented by config.
func effectiveConfigETag(config *store.EffectiveConfig) (string, error) {
	if config == nil {
		return "", ErrRealtimeUnavailable
	}
	target, err := configScopeToRealtime(config.Scope)
	if err != nil {
		return "", err
	}
	source, err := configRowScope(config.Source)
	if err != nil {
		return "", err
	}
	return realtime.EffectiveConfigETag(realtime.EffectiveConfigETagInput{
		Target:        target,
		Local:         config.Local != nil,
		Source:        source,
		SourceVersion: config.Source.Version,
		Config:        config.Source.Config,
	})
}

// configRowScope extracts one validated immutable scope from a store config row.
func configRowScope(config db.ScopePermissionConfig) (realtime.Scope, error) {
	if config.ScopeType == "server" && !config.GroupID.Valid && !config.ChannelID.Valid {
		return realtime.Scope{Type: "server"}, nil
	}
	if config.ScopeType == "group" && config.GroupID.Valid && !config.ChannelID.Valid && config.GroupID.Int64 > 0 {
		return realtime.Scope{Type: "group", ID: config.GroupID.Int64}, nil
	}
	if config.ScopeType == "channel" && !config.GroupID.Valid && config.ChannelID.Valid && config.ChannelID.Int64 > 0 {
		return realtime.Scope{Type: "channel", ID: config.ChannelID.Int64}, nil
	}
	return realtime.Scope{}, ErrRealtimeUnavailable
}
