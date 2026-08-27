package store

import (
	"context"
	"database/sql"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/snowflake"
)

// MuteStore persists moderation mute records. Expiry scheduling is owned by a
// later runtime moderation service; this store only enforces DB constraints.
type MuteStore struct {
	q     *db.Queries
	idGen *snowflake.IDGenerator
	now   func() int64
}

// MuteInput contains the scope and moderation fields for a new mute.
type MuteInput struct {
	ScopeType string
	GroupID   *int64
	ChannelID *int64
	UserID    int64
	Kind      string
	ExpiresAt *int64
	CreatedBy *int64
	Reason    string
}

// Create inserts a version-one mute. Scope, kind, expiry and uniqueness are
// checked by the schema.
func (s *MuteStore) Create(ctx context.Context, input MuteInput) (*db.ModerationMute, error) {
	id, err := s.idGen.Next()
	if err != nil {
		return nil, err
	}
	mute, err := s.q.InsertMute(ctx, db.InsertMuteParams{
		ID:        id,
		ScopeType: input.ScopeType,
		GroupID:   nullInt64(input.GroupID),
		ChannelID: nullInt64(input.ChannelID),
		UserID:    input.UserID,
		Kind:      input.Kind,
		ExpiresAt: nullInt64(input.ExpiresAt),
		CreatedBy: nullInt64(input.CreatedBy),
		Reason:    input.Reason,
		CreatedAt: s.now(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &mute, nil
}

// Now returns the store's injected Unix-millisecond clock. Sequenced moderation
// commands use it for expiry validation so tests and persisted rows agree.
func (s *MuteStore) Now() int64 { return s.now() }

// Get returns one mute by ID, or ErrNotFound.
func (s *MuteStore) Get(ctx context.Context, id int64) (*db.ModerationMute, error) {
	mute, err := s.q.GetMute(ctx, id)
	if err != nil {
		return nil, mapError(err)
	}
	return &mute, nil
}

// Delete removes one mute by ID, or returns ErrNotFound.
func (s *MuteStore) Delete(ctx context.Context, id int64) error {
	_, err := s.q.DeleteMute(ctx, id)
	return mapError(err)
}

// Update replaces a mute's expiry and reason, incrementing its entity version.
// Callers compare the previous version in their sequenced transaction.
func (s *MuteStore) Update(ctx context.Context, id int64, expiresAt *int64, reason string) (*db.ModerationMute, error) {
	mute, err := s.q.UpdateMute(ctx, db.UpdateMuteParams{
		ExpiresAt: nullInt64(expiresAt),
		Reason:    reason,
		ID:        id,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &mute, nil
}

// CountActive returns the number of currently enforced mutes. Expired rows are
// excluded because delayed timer cleanup must never consume the active hard cap.
func (s *MuteStore) CountActive(ctx context.Context) (int64, error) {
	count, err := s.q.CountActiveMutes(ctx, sql.NullInt64{Int64: s.now(), Valid: true})
	return count, mapError(err)
}

// ListForUser returns all mutes targeting a user.
func (s *MuteStore) ListForUser(ctx context.Context, userID int64) ([]db.ModerationMute, error) {
	mutes, err := s.q.ListMutesForUser(ctx, userID)
	if err != nil {
		return nil, mapError(err)
	}
	return mutes, nil
}

// ListAll returns every persisted mute in ascending ID order for an internal
// state projection.
func (s *MuteStore) ListAll(ctx context.Context) ([]db.ModerationMute, error) {
	mutes, err := s.q.ListAllMutes(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return mutes, nil
}
