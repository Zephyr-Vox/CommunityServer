package store

import (
	"context"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/snowflake"
)

// InviteStore provides persistence for registration invite codes.
type InviteStore struct {
	q     *db.Queries
	idGen *snowflake.IDGenerator
	now   func() int64
}

// Create inserts an invite and returns it. expiresAt and createdBy may be nil.
func (s *InviteStore) Create(ctx context.Context, codeHash, role string, usesLeft int64, expiresAt, createdBy *int64) (*db.Invite, error) {
	id, err := s.idGen.Next()
	if err != nil {
		return nil, err
	}
	inv, err := s.q.CreateInvite(ctx, db.CreateInviteParams{
		ID:        id,
		CodeHash:  codeHash,
		Role:      role,
		UsesLeft:  usesLeft,
		ExpiresAt: nullInt64(expiresAt),
		CreatedBy: nullInt64(createdBy),
		CreatedAt: s.now(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &inv, nil
}

// GetByCodeHash returns the invite for a code hash, or ErrNotFound.
func (s *InviteStore) GetByCodeHash(ctx context.Context, codeHash string) (*db.Invite, error) {
	inv, err := s.q.GetInviteByCodeHash(ctx, db.GetInviteByCodeHashParams{
		CodeHash: codeHash,
		Now:      s.now(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &inv, nil
}

// Consume atomically decrements uses_left. An exhausted or missing invite is
// reported as ErrNotFound.
func (s *InviteStore) Consume(ctx context.Context, id int64) (*db.Invite, error) {
	inv, err := s.q.ConsumeInvite(ctx, db.ConsumeInviteParams{
		ID:  id,
		Now: s.now(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &inv, nil
}

// Delete removes an invite by ID.
func (s *InviteStore) Delete(ctx context.Context, id int64) error {
	return mapError(s.q.DeleteInvite(ctx, id))
}
