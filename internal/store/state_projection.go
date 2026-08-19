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

// LoadStateProjection reads all persistent state from one coherent transaction
// view. Root stores open a read transaction, while transaction-bound stores
// read their caller-owned view including its uncommitted writes. The returned
// rows are copied by the StateStore before publication.
func (s *Stores) LoadStateProjection(ctx context.Context) (*StateProjection, error) {
	if s == nil {
		return nil, ErrInvalidStore
	}
	if s.conn == nil {
		return s.loadStateProjection(ctx)
	}
	tx, err := s.BeginReadTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txStores := s.WithTx(tx)

	projection, err := txStores.loadStateProjection(ctx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return projection, nil
}

// loadStateProjection reads every synchronized table through s's existing
// connection or transaction. Transaction-bound callers observe their own
// uncommitted mutation, which lets realtime reserve a durable result before
// committing that same transaction.
func (s *Stores) loadStateProjection(ctx context.Context) (*StateProjection, error) {
	users, err := s.Users.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := s.Roles.List(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := s.Channels.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	channels, err := s.Channels.List(ctx)
	if err != nil {
		return nil, err
	}
	groupAccess, err := s.Access.ListAllGroups(ctx)
	if err != nil {
		return nil, err
	}
	channelAccess, err := s.Access.ListAllChannels(ctx)
	if err != nil {
		return nil, err
	}
	bindings, err := s.Roles.ListEveryBinding(ctx)
	if err != nil {
		return nil, err
	}
	configs, err := s.Configs.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	mutes, err := s.Mutes.ListAll(ctx)
	if err != nil {
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
