package image

import (
	"bytes"
	"context"
	"io"

	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/oss"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
)

// AvatarBucket is the object storage bucket holding avatar files. The public
// GET route is mounted against it (see internal/server/router.go).
const AvatarBucket = "avatars"

// AvatarService implements the avatar feature: upload (transcode + store +
// update the user's avatar column) and reset. The users.avatar column stores
// only the object name ("<id>.jpg") — never a path — so the public base
// prefix can change without migrating data. Responses carry the raw name;
// clients build the full URL by joining it with the public prefix, which
// today is the fixed route /avatar/ (a server metadata endpoint publishing
// a configurable prefix is future work, not part of this module).
type AvatarService struct {
	users     *store.UserStore
	objects   *oss.LocalObjectStorage
	idGen     *snowflake.IDGenerator
	cfg       config.AvatarConfig
	conv      ImageConverter
	transcode func(src io.Reader, conv ImageConverter, size, maxDim int) ([]byte, error)
}

// AvatarOption configures an AvatarService after its defaults are applied.
// Options exist so tests can replace the converter or the transcode
// pipeline; production callers pass none.
type AvatarOption func(*AvatarService)

// WithConverter replaces the default JPEGConverter (configured quality).
func WithConverter(conv ImageConverter) AvatarOption {
	return func(s *AvatarService) { s.conv = conv }
}

// WithTranscode replaces the default Transcode pipeline.
func WithTranscode(fn func(src io.Reader, conv ImageConverter, size, maxDim int) ([]byte, error)) AvatarOption {
	return func(s *AvatarService) { s.transcode = fn }
}

// NewAvatarService returns an AvatarService using JPEGConverter at the
// configured quality and the standard Transcode pipeline. Options may
// replace either of those (mainly for tests).
func NewAvatarService(users *store.UserStore, objects *oss.LocalObjectStorage, idGen *snowflake.IDGenerator, cfg config.AvatarConfig, opts ...AvatarOption) *AvatarService {
	s := &AvatarService{
		users:     users,
		objects:   objects,
		idGen:     idGen,
		cfg:       cfg,
		conv:      JPEGConverter{Quality: cfg.Quality},
		transcode: Transcode,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Upload transcodes src into the configured target format and size, stores
// the object, and points the user's avatar column at the new name. The old
// object is deleted best-effort after the metadata commit; a failed metadata
// commit removes the freshly written object to avoid orphans.
//
// It returns the managed name ("<id>.jpg"). Errors: store.ErrNotFound when
// the user is gone, ErrImageTooLarge, ErrNotAnImage.
func (s *AvatarService) Upload(ctx context.Context, userID int64, src io.Reader) (string, error) {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}

	id, err := s.idGen.Next()
	if err != nil {
		return "", err
	}
	data, err := s.transcode(src, s.conv, s.cfg.TargetSize, s.cfg.MaxDimension)
	if err != nil {
		return "", err
	}

	name := oss.NewName(id, s.conv.Extension())
	if _, err := s.objects.Put(ctx, AvatarBucket, name, bytes.NewReader(data), oss.PutOptions{
		ContentType: s.conv.ContentType(),
	}); err != nil {
		return "", err
	}

	if _, err := s.users.SetAvatar(ctx, userID, &name); err != nil {
		_ = s.objects.Delete(ctx, AvatarBucket, name) // best-effort: no orphan objects
		return "", err
	}

	if user.Avatar.Valid && user.Avatar.String != name {
		_ = s.objects.Delete(ctx, AvatarBucket, user.Avatar.String) // best-effort: stale object
	}
	return name, nil
}

// Reset clears the user's avatar. The stored object, if any, is deleted
// best-effort after the metadata commit. Errors: store.ErrNotFound when the
// user is gone.
func (s *AvatarService) Reset(ctx context.Context, userID int64) error {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if _, err := s.users.SetAvatar(ctx, userID, nil); err != nil {
		return err
	}
	if user.Avatar.Valid {
		_ = s.objects.Delete(ctx, AvatarBucket, user.Avatar.String) // best-effort
	}
	return nil
}

// DeleteAvatar removes an avatar object by name without touching any user
// row. It satisfies auth.AvatarCleaner so account deletion can drop the
// user's avatar file. oss.Delete is idempotent: a missing object is silent
// success, while an invalid name (e.g. "../escape") returns ErrInvalidKey —
// callers treat the error as best-effort anyway.
func (s *AvatarService) DeleteAvatar(ctx context.Context, name string) error {
	return s.objects.Delete(ctx, AvatarBucket, name)
}
