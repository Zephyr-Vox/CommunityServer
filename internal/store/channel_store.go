package store

import (
	"context"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/snowflake"
)

// ChannelStore persists channel groups and channels. It deliberately contains
// no HTTP or runtime membership behavior.
type ChannelStore struct {
	q     *db.Queries
	idGen *snowflake.IDGenerator
	now   func() int64
}

// CreateGroup creates a version-one channel group.
func (s *ChannelStore) CreateGroup(ctx context.Context, name string, position int64, visibility string) (*db.ChannelGroup, error) {
	id, err := s.idGen.Next()
	if err != nil {
		return nil, err
	}
	now := s.now()
	group, err := s.q.CreateChannelGroup(ctx, db.CreateChannelGroupParams{
		ID:         id,
		Name:       name,
		Position:   position,
		Visibility: visibility,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &group, nil
}

// GetGroup returns a channel group by ID, or ErrNotFound.
func (s *ChannelStore) GetGroup(ctx context.Context, id int64) (*db.ChannelGroup, error) {
	group, err := s.q.GetChannelGroup(ctx, id)
	if err != nil {
		return nil, mapError(err)
	}
	return &group, nil
}

// ListGroups returns all channel groups in stable display order.
func (s *ChannelStore) ListGroups(ctx context.Context) ([]db.ChannelGroup, error) {
	groups, err := s.q.ListChannelGroups(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return groups, nil
}

// CountGroups returns the number of persisted channel groups.
func (s *ChannelStore) CountGroups(ctx context.Context) (int64, error) {
	count, err := s.q.CountChannelGroups(ctx)
	return count, mapError(err)
}

// UpdateGroup replaces one group resource's mutable fields and increments its
// entity version. Callers must compare the prior version in their sequenced
// transaction before invoking this method.
func (s *ChannelStore) UpdateGroup(ctx context.Context, id int64, name string, position int64, visibility string) (*db.ChannelGroup, error) {
	group, err := s.q.UpdateChannelGroup(ctx, db.UpdateChannelGroupParams{
		Name:       name,
		Position:   position,
		Visibility: visibility,
		UpdatedAt:  s.now(),
		ID:         id,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &group, nil
}

// DeleteGroup removes an empty group. The schema rejects a deletion while any
// channel still references the group, preserving the application's explicit
// voice teardown path.
func (s *ChannelStore) DeleteGroup(ctx context.Context, id int64) error {
	_, err := s.q.DeleteChannelGroup(ctx, id)
	return mapError(err)
}

// Create creates a version-one channel. The schema enforces mode, lifecycle,
// capacity, visibility and parent foreign-key invariants.
func (s *ChannelStore) Create(ctx context.Context, input ChannelInput) (*db.Channel, error) {
	id, err := s.idGen.Next()
	if err != nil {
		return nil, err
	}
	now := s.now()
	channel, err := s.q.CreateChannel(ctx, db.CreateChannelParams{
		ID:         id,
		GroupID:    nullInt64(input.GroupID),
		Name:       input.Name,
		Mode:       input.Mode,
		Temporary:  input.Temporary,
		Visibility: input.Visibility,
		Capacity:   input.Capacity,
		Position:   input.Position,
		Pinned:     input.Pinned,
		CreatedBy:  nullInt64(input.CreatedBy),
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &channel, nil
}

// ChannelInput contains the persisted fields for creating a channel.
type ChannelInput struct {
	GroupID    *int64
	Name       string
	Mode       string
	Temporary  int64
	Visibility string
	Capacity   int64
	Position   int64
	Pinned     int64
	CreatedBy  *int64
}

// ChannelUpdate contains the mutable channel fields. Mode, temporary, and
// creator are omitted because the channel protocol keeps them immutable.
type ChannelUpdate struct {
	GroupID    *int64
	Name       string
	Visibility string
	Capacity   int64
	Position   int64
	Pinned     int64
}

// Get returns a channel by ID, or ErrNotFound.
func (s *ChannelStore) Get(ctx context.Context, id int64) (*db.Channel, error) {
	channel, err := s.q.GetChannel(ctx, id)
	if err != nil {
		return nil, mapError(err)
	}
	return &channel, nil
}

// List returns all channels in stable display order.
func (s *ChannelStore) List(ctx context.Context) ([]db.Channel, error) {
	channels, err := s.q.ListChannels(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return channels, nil
}

// Count returns the number of persisted channels of every lifecycle.
func (s *ChannelStore) Count(ctx context.Context) (int64, error) {
	count, err := s.q.CountChannels(ctx)
	return count, mapError(err)
}

// CountTemporary returns the number of persisted temporary voice channels.
func (s *ChannelStore) CountTemporary(ctx context.Context) (int64, error) {
	count, err := s.q.CountTemporaryChannels(ctx)
	return count, mapError(err)
}

// CountTemporaryForCreator returns one creator's temporary voice-channel count.
// A nil creator cannot own a temporary channel and therefore always counts zero.
func (s *ChannelStore) CountTemporaryForCreator(ctx context.Context, creatorID *int64) (int64, error) {
	if creatorID == nil {
		return 0, nil
	}
	count, err := s.q.CountTemporaryChannelsForCreator(ctx, nullInt64(creatorID))
	return count, mapError(err)
}

// Update replaces one channel's mutable fields and increments its entity
// version. Mode, temporary, and creator are deliberately immutable. Callers
// must compare the prior version in their sequenced transaction before calling.
func (s *ChannelStore) Update(ctx context.Context, id int64, input ChannelUpdate) (*db.Channel, error) {
	channel, err := s.q.UpdateChannel(ctx, db.UpdateChannelParams{
		GroupID:    nullInt64(input.GroupID),
		Name:       input.Name,
		Visibility: input.Visibility,
		Capacity:   input.Capacity,
		Position:   input.Position,
		Pinned:     input.Pinned,
		UpdatedAt:  s.now(),
		ID:         id,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &channel, nil
}

// Delete removes a channel and its dependent ACL/configuration/binding/mute
// rows through the schema's cascade rules.
func (s *ChannelStore) Delete(ctx context.Context, id int64) error {
	_, err := s.q.DeleteChannel(ctx, id)
	return mapError(err)
}
