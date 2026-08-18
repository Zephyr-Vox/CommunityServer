// Package oss provides a self-contained local object storage: files on disk
// plus an objects metadata table that the implementation maintains itself.
// Naming policy belongs to callers; the module only enforces filesystem-safe
// paths.
package oss

import (
	"context"
	"database/sql"
	"errors"

	"zephyr.vox/server/ce/internal/db"
)

// objectStore wraps the sqlc-generated objects queries and owns metadata
// error mapping.
type objectStore struct {
	q *db.Queries
}

// newObjectStore wraps object queries for the supplied database connection.
func newObjectStore(conn *sql.DB) *objectStore {
	return &objectStore{q: db.New(conn)}
}

// Upsert inserts or replaces one object metadata row.
func (s *objectStore) Upsert(ctx context.Context, o db.Object) (db.Object, error) {
	return s.q.UpsertObject(ctx, db.UpsertObjectParams{
		Bucket:       o.Bucket,
		Name:         o.Name,
		ContentType:  o.ContentType,
		Size:         o.Size,
		OriginalName: o.OriginalName,
		CreatedAt:    o.CreatedAt,
	})
}

// Get returns object metadata or ErrNotFound when its row is absent.
func (s *objectStore) Get(ctx context.Context, bucket, name string) (db.Object, error) {
	o, err := s.q.GetObject(ctx, db.GetObjectParams{Bucket: bucket, Name: name})
	if errors.Is(err, sql.ErrNoRows) {
		return db.Object{}, ErrNotFound
	}
	return o, err
}

// Delete removes one object metadata row.
func (s *objectStore) Delete(ctx context.Context, bucket, name string) error {
	return s.q.DeleteObject(ctx, db.DeleteObjectParams{Bucket: bucket, Name: name})
}
