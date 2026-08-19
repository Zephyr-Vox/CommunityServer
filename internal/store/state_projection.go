package store

import (
	"context"

	"zephyr.vox/server/ce/internal/db"
)

// StateProjection is the complete persisted input to the in-memory StateStore.
// It intentionally excludes sessions, invites and objects because those
// records are not part of the synchronized server state. The StateStore drops
// credential fields while converting the user rows into its immutable view.
type StateProjection struct {
	// Users contains source account rows; StateStore removes credential and
	// login-session fields while building its immutable view.
	Users []db.User
	// Roles contains every role definition.
	Roles []db.Role
	// Groups contains every channel group.
	Groups []db.ChannelGroup
	// Channels contains every persisted channel.
	Channels []db.Channel
	// GroupAccess contains every group ACL entry.
	GroupAccess []db.GroupAccess
	// ChannelAccess contains every channel ACL entry.
	ChannelAccess []db.ChannelAccess
	// Bindings contains every scoped role binding.
	Bindings []db.UserRoleBinding
	// Configs contains every local permission configuration, including server.
	Configs []db.ScopePermissionConfig
	// Mutes contains every persisted moderation mute.
	Mutes []db.ModerationMute
}

// LoadStateProjection reads all persistent state from one read transaction.
// The returned database rows are copied by the StateStore before publication,
// so callers must not retain them as mutable shared state.
func (s *Stores) LoadStateProjection(ctx context.Context) (*StateProjection, error) {
	tx, err := s.BeginReadTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txStores := s.WithTx(tx)

	users, err := txStores.Users.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := txStores.Roles.List(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := txStores.Channels.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	channels, err := txStores.Channels.List(ctx)
	if err != nil {
		return nil, err
	}
	groupAccess, err := txStores.Access.ListAllGroups(ctx)
	if err != nil {
		return nil, err
	}
	channelAccess, err := txStores.Access.ListAllChannels(ctx)
	if err != nil {
		return nil, err
	}
	bindings, err := txStores.Roles.ListEveryBinding(ctx)
	if err != nil {
		return nil, err
	}
	configs, err := txStores.Configs.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	mutes, err := txStores.Mutes.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &StateProjection{
		Users:         users,
		Roles:         roles,
		Groups:        groups,
		Channels:      channels,
		GroupAccess:   groupAccess,
		ChannelAccess: channelAccess,
		Bindings:      bindings,
		Configs:       configs,
		Mutes:         mutes,
	}, nil
}
