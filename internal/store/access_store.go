package store

import (
	"context"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/snowflake"
)

// AccessStore persists user and role ACL entries for groups and channels.
type AccessStore struct {
	q     *db.Queries
	idGen *snowflake.IDGenerator
	now   func() int64
}

// AccessPrincipal describes exactly one user or role ACL principal.
type AccessPrincipal struct {
	Type    string
	UserID  *int64
	RoleKey *string
}

// AddGroup inserts a group ACL entry. The database CHECK and partial indexes
// reject malformed principals and duplicate entries.
func (s *AccessStore) AddGroup(ctx context.Context, groupID int64, principal AccessPrincipal) (*db.GroupAccess, error) {
	id, err := s.idGen.Next()
	if err != nil {
		return nil, err
	}
	entry, err := s.q.InsertGroupAccess(ctx, db.InsertGroupAccessParams{
		ID:            id,
		GroupID:       groupID,
		PrincipalType: principal.Type,
		UserID:        nullInt64(principal.UserID),
		RoleKey:       nullString(principal.RoleKey),
		CreatedAt:     s.now(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &entry, nil
}

// ListGroup returns all ACL entries for a group.
func (s *AccessStore) ListGroup(ctx context.Context, groupID int64) ([]db.GroupAccess, error) {
	entries, err := s.q.ListGroupAccess(ctx, groupID)
	if err != nil {
		return nil, mapError(err)
	}
	return entries, nil
}

// CountGroup returns the number of ACL entries attached to groupID.
func (s *AccessStore) CountGroup(ctx context.Context, groupID int64) (int64, error) {
	count, err := s.q.CountGroupAccess(ctx, groupID)
	return count, mapError(err)
}

// DeleteGroup removes accessID only when it belongs to groupID. A missing or
// mismatched entry returns ErrNotFound without revealing another group's ACL.
func (s *AccessStore) DeleteGroup(ctx context.Context, groupID, accessID int64) (*db.GroupAccess, error) {
	entry, err := s.q.DeleteGroupAccess(ctx, db.DeleteGroupAccessParams{GroupID: groupID, ID: accessID})
	if err != nil {
		return nil, mapError(err)
	}
	return &entry, nil
}

// ListAllGroups returns every group ACL entry in ascending ID order for an
// internal state projection.
func (s *AccessStore) ListAllGroups(ctx context.Context) ([]db.GroupAccess, error) {
	entries, err := s.q.ListAllGroupAccess(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return entries, nil
}

// AddChannel inserts a channel ACL entry. The database validates the
// principal shape and uniqueness.
func (s *AccessStore) AddChannel(ctx context.Context, channelID int64, principal AccessPrincipal) (*db.ChannelAccess, error) {
	id, err := s.idGen.Next()
	if err != nil {
		return nil, err
	}
	entry, err := s.q.InsertChannelAccess(ctx, db.InsertChannelAccessParams{
		ID:            id,
		ChannelID:     channelID,
		PrincipalType: principal.Type,
		UserID:        nullInt64(principal.UserID),
		RoleKey:       nullString(principal.RoleKey),
		CreatedAt:     s.now(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &entry, nil
}

// ListChannel returns all ACL entries for a channel.
func (s *AccessStore) ListChannel(ctx context.Context, channelID int64) ([]db.ChannelAccess, error) {
	entries, err := s.q.ListChannelAccess(ctx, channelID)
	if err != nil {
		return nil, mapError(err)
	}
	return entries, nil
}

// CountChannel returns the number of ACL entries attached to channelID.
func (s *AccessStore) CountChannel(ctx context.Context, channelID int64) (int64, error) {
	count, err := s.q.CountChannelAccess(ctx, channelID)
	return count, mapError(err)
}

// DeleteChannel removes accessID only when it belongs to channelID. A missing
// or mismatched entry returns ErrNotFound without revealing another channel's
// ACL.
func (s *AccessStore) DeleteChannel(ctx context.Context, channelID, accessID int64) (*db.ChannelAccess, error) {
	entry, err := s.q.DeleteChannelAccess(ctx, db.DeleteChannelAccessParams{ChannelID: channelID, ID: accessID})
	if err != nil {
		return nil, mapError(err)
	}
	return &entry, nil
}

// ListAllChannels returns every channel ACL entry in ascending ID order for
// an internal state projection.
func (s *AccessStore) ListAllChannels(ctx context.Context) ([]db.ChannelAccess, error) {
	entries, err := s.q.ListAllChannelAccess(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return entries, nil
}
