package image

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

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
	users          *store.UserStore
	objects        *oss.LocalObjectStorage
	idGen          *snowflake.IDGenerator
	cfg            config.AvatarConfig
	conv           ImageConverter
	transcode      func(src io.Reader, conv ImageConverter, size, maxDim int) ([]byte, error)
	transcodeSlots chan struct{}
	userLocks      *avatarUserLocks
	afterMetadata  func()
	gate           MutationGate
	executeState   StateMutationExecutor
}

// MutationGate serializes avatar metadata writes with their following
// persistent StateStore publication.
type MutationGate interface {
	Acquire(context.Context) (func(), error)
}

// SetStateMutationGate installs the process-wide persistent mutation gate.
func (s *AvatarService) SetStateMutationGate(gate MutationGate) { s.gate = gate }

// StateMutationFunc applies one avatar metadata update to a transaction-bound
// store. It must not commit or perform object-storage cleanup.
type StateMutationFunc func(context.Context, *store.Stores) error

// StateMutationExecutor commits one avatar metadata update together with its
// account state projection. The object bytes are already durable when this
// callback runs, while the user-row update remains rollbackable.
type StateMutationExecutor func(context.Context, int64, StateMutationFunc) error

// SetStateMutationExecutor installs the application-owned ordered account
// mutation callback. It is configured before avatar routes are exposed.
func (s *AvatarService) SetStateMutationExecutor(executor StateMutationExecutor) {
	s.executeState = executor
}

var ErrTranscodeBusy = errors.New("image: transcode capacity exhausted")

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

// WithAfterMetadataCommit installs a callback invoked after SetAvatar commits
// and before Upload performs stale-object cleanup. It is intended for
// integration tests that need to hold the metadata-committed, upload-in-flight
// window; normal callers should leave it unset.
func WithAfterMetadataCommit(fn func()) AvatarOption {
	return func(s *AvatarService) { s.afterMetadata = fn }
}

// NewAvatarService returns an AvatarService using JPEGConverter at the
// configured quality and the standard Transcode pipeline. Options may
// replace either of those (mainly for tests).
func NewAvatarService(users *store.UserStore, objects *oss.LocalObjectStorage, idGen *snowflake.IDGenerator, cfg config.AvatarConfig, opts ...AvatarOption) *AvatarService {
	s := &AvatarService{
		users:          users,
		objects:        objects,
		idGen:          idGen,
		cfg:            cfg,
		conv:           JPEGConverter{Quality: cfg.Quality},
		transcode:      Transcode,
		transcodeSlots: make(chan struct{}, cfg.MaxConcurrentTranscodes),
		userLocks:      newAvatarUserLocks(),
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
// the user is gone, ErrImageTooLarge, ErrNotAnImage, or ErrTranscodeBusy.
//
// A per-user lock covers the read, storage write, metadata update, and stale
// cleanup, so concurrent upload/reset operations cannot delete a newly
// committed avatar. The bounded slot is acquired after that lock and covers
// only content sniffing, reads, decoding and transcoding; storage and metadata
// work immediately release it so slow I/O cannot exhaust transcode capacity.
func (s *AvatarService) Upload(ctx context.Context, userID int64, src io.Reader) (string, error) {
	return s.upload(ctx, userID, src, nil)
}

// upload performs Upload and calls beforeCommit after the bounded transcode
// finishes but before object or user metadata is changed. The HTTP adapter uses
// this gate to finish validating the multipart request body without buffering
// the selected file in memory.
func (s *AvatarService) upload(ctx context.Context, userID int64, src io.Reader, beforeCommit func() error) (string, error) {
	unlock := s.userLocks.lock(userID)
	defer unlock()
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}
	select {
	case s.transcodeSlots <- struct{}{}:
	default:
		return "", ErrTranscodeBusy
	}
	data, err := func() ([]byte, error) {
		// The slot bounds only the memory-heavy input and image pipeline. A
		// deferred release preserves that bound even if a decoder or converter
		// panics and the HTTP boundary recovers the request.
		defer func() { <-s.transcodeSlots }()
		contentType, reader, err := oss.DetectContentType(src)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(contentType, "image/") {
			return nil, ErrNotAnImage
		}
		return s.transcode(reader, s.conv, s.cfg.TargetSize, s.cfg.MaxDimension)
	}()
	if beforeCommit != nil {
		if commitErr := beforeCommit(); commitErr != nil {
			return "", commitErr
		}
	}
	if err != nil {
		return "", err
	}

	id, err := s.idGen.Next()
	if err != nil {
		return "", err
	}

	name := oss.NewName(id, s.conv.Extension())
	if _, err := s.objects.Put(ctx, AvatarBucket, name, bytes.NewReader(data), oss.PutOptions{
		ContentType: s.conv.ContentType(),
	}); err != nil {
		return "", err
	}

	if s.executeState != nil {
		if err := s.executeState(ctx, userID, func(commandCtx context.Context, txStores *store.Stores) error {
			_, err := txStores.Users.SetAvatar(commandCtx, userID, &name)
			return err
		}); err != nil {
			_ = s.objects.Delete(ctx, AvatarBucket, name) // best-effort: no orphan objects
			return "", err
		}
	} else {
		release, err := acquireMutation(ctx, s.gate)
		if err != nil {
			return "", err
		}
		defer release()
		if _, err := s.users.SetAvatar(ctx, userID, &name); err != nil {
			_ = s.objects.Delete(ctx, AvatarBucket, name) // best-effort: no orphan objects
			return "", err
		}
	}
	if s.afterMetadata != nil {
		s.afterMetadata()
	}

	if user.Avatar.Valid && user.Avatar.String != name {
		_ = s.objects.Delete(ctx, AvatarBucket, user.Avatar.String) // best-effort: stale object
	}
	return name, nil
}

// Reset clears the user's avatar. The stored object, if any, is deleted
// best-effort after the metadata commit. Errors: store.ErrNotFound when the
// user is gone. It uses the same per-user lock as Upload so reset cannot race
// an upload's metadata update or stale-object cleanup.
func (s *AvatarService) Reset(ctx context.Context, userID int64) error {
	unlock := s.userLocks.lock(userID)
	defer unlock()
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if s.executeState != nil {
		if err := s.executeState(ctx, userID, func(commandCtx context.Context, txStores *store.Stores) error {
			_, err := txStores.Users.SetAvatar(commandCtx, userID, nil)
			return err
		}); err != nil {
			return err
		}
	} else {
		release, err := acquireMutation(ctx, s.gate)
		if err != nil {
			return err
		}
		defer release()
		if _, err := s.users.SetAvatar(ctx, userID, nil); err != nil {
			return err
		}
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

// acquireMutation returns a no-op release for standalone avatar tests.
func acquireMutation(ctx context.Context, gate MutationGate) (func(), error) {
	if gate == nil {
		return func() {}, nil
	}
	return gate.Acquire(ctx)
}
