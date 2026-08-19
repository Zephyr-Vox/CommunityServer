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

// Delete removes a channel and its dependent ACL/configuration/binding/mute
// rows through the schema's cascade rules.
func (s *ChannelStore) Delete(ctx context.Context, id int64) error {
	_, err := s.q.DeleteChannel(ctx, id)
	return mapError(err)
}
