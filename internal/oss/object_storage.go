package oss

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"zephyr.vox/server/ce/internal/db"
)

var (
	// ErrNotFound is returned when an object's metadata row or file is missing.
	ErrNotFound = errors.New("oss: not found")
	// ErrInvalidKey is returned when a bucket or name is not a safe path segment.
	ErrInvalidKey = errors.New("oss: invalid key")
)

// Object describes one stored object.
type Object struct {
	Bucket       string
	Name         string
	Size         int64
	ContentType  string
	OriginalName string
	CreatedAt    int64 // Unix milliseconds (UTC)
}

// PutOptions configures a Put call.
type PutOptions struct {
	ContentType  string // empty means sniff from src; non-empty is normalized
	OriginalName string // display-only metadata, never part of the path
}

// LocalObjectStorage stores files under root/bucket/name and keeps its own
// metadata rows in the objects table. Operations on the same key are
// serialized by an in-memory per-key lock, so a concurrent Put/Delete can
// never leave a row pointing at the wrong file; different keys proceed
// independently.
type LocalObjectStorage struct {
	root    string
	objects *objectStore
	locks   *keyLocks
	now     func() int64 // Unix milliseconds, injectable for tests
}

// NewLocalObjectStorage returns a LocalObjectStorage rooted at root and
// backed by conn for metadata. now supplies Unix milliseconds and is
// injectable for deterministic tests.
func NewLocalObjectStorage(root string, conn *sql.DB, now func() int64) (*LocalObjectStorage, error) {
	if root == "" {
		return nil, errors.New("oss: root must not be empty")
	}
	root = filepath.Clean(root)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("oss: create root: %w", err)
	}
	return &LocalObjectStorage{root: root, objects: newObjectStore(conn), locks: newKeyLocks(), now: now}, nil
}

// Put streams src into bucket/name and upserts the metadata row. It writes
// to a same-directory temp file, fsyncs, atomically renames, and records the
// row last. An existing file is stashed aside first so a failed metadata
// commit restores the old file instead of leaving a row pointing at nothing.
// A stale backup left by a crashed overwrite is kept until the new file and
// its metadata are committed, so the last old copy is never discarded early.
func (s *LocalObjectStorage) Put(ctx context.Context, bucket, name string, src io.Reader, opts PutOptions) (Object, error) {
	if err := validateComponent(bucket); err != nil {
		return Object{}, err
	}
	if err := validateComponent(name); err != nil {
		return Object{}, err
	}
	unlock := s.locks.Lock(objectKey(bucket, name))
	defer unlock()

	dir := filepath.Join(s.root, bucket)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Object{}, fmt.Errorf("oss: create bucket directory: %w", err)
	}

	contentType := normalizeContentType(opts.ContentType)
	reader := src
	if contentType == "" {
		sniffed, rest, err := DetectContentType(src)
		if err != nil {
			return Object{}, err
		}
		reader = rest
		contentType = normalizeContentType(sniffed)
		if contentType == "" {
			contentType = "application/octet-stream"
		}
	}

	tmp, err := os.CreateTemp(dir, name+".tmp-*")
	if err != nil {
		return Object{}, fmt.Errorf("oss: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	size, err := io.Copy(tmp, reader)
	if err != nil {
		_ = tmp.Close()
		return Object{}, fmt.Errorf("oss: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return Object{}, fmt.Errorf("oss: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return Object{}, fmt.Errorf("oss: close temp file: %w", err)
	}

	path := filepath.Join(dir, name)
	backup := path + ".bak"
	hadOldFile := false
	if _, err := os.Lstat(path); err == nil {
		if err := os.Rename(path, backup); err != nil {
			return Object{}, fmt.Errorf("oss: stash old file: %w", err)
		}
		hadOldFile = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return Object{}, fmt.Errorf("oss: stat existing object: %w", err)
	} else if _, err := os.Lstat(backup); err == nil {
		// Crash recovery: the previous overwrite stashed the old file but
		// never finished. Keep this backup as the only old copy until the new
		// file and metadata are committed.
		hadOldFile = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return Object{}, fmt.Errorf("oss: stat backup file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		if hadOldFile {
			_ = os.Rename(backup, path)
		}
		return Object{}, fmt.Errorf("oss: rename temp file: %w", err)
	}
	tmpPath = "" // renamed; no longer needs cleanup

	row, err := s.objects.Upsert(ctx, db.Object{
		Bucket:       bucket,
		Name:         name,
		ContentType:  contentType,
		Size:         size,
		OriginalName: opts.OriginalName,
		CreatedAt:    s.now(),
	})
	if err != nil {
		_ = os.Remove(path)
		if hadOldFile {
			if restoreErr := os.Rename(backup, path); restoreErr != nil {
				return Object{}, fmt.Errorf("oss: record metadata: %w (restore old file: %v)", err, restoreErr)
			}
		}
		return Object{}, fmt.Errorf("oss: record metadata: %w", err)
	}
	if hadOldFile {
		_ = os.Remove(backup) // best-effort; the committed state is already consistent
	}
	return objectFromRow(row), nil
}

// Open returns the object metadata and a reader for its file. It looks up
// the metadata row first; a missing row or missing file both yield
// ErrNotFound. The returned reader is *os.File, which also implements
// io.ReadSeeker for Range-capable serving.
func (s *LocalObjectStorage) Open(ctx context.Context, bucket, name string) (Object, io.ReadCloser, error) {
	if err := validateComponent(bucket); err != nil {
		return Object{}, nil, err
	}
	if err := validateComponent(name); err != nil {
		return Object{}, nil, err
	}
	unlock := s.locks.Lock(objectKey(bucket, name))
	defer unlock()

	row, err := s.objects.Get(ctx, bucket, name)
	if err != nil {
		return Object{}, nil, err
	}
	path, err := s.filePath(bucket, name)
	if err != nil {
		return Object{}, nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Object{}, nil, ErrNotFound
		}
		return Object{}, nil, fmt.Errorf("oss: open object: %w", err)
	}
	return objectFromRow(row), f, nil
}

// Stat returns the metadata row without touching the file.
func (s *LocalObjectStorage) Stat(ctx context.Context, bucket, name string) (Object, error) {
	if err := validateComponent(bucket); err != nil {
		return Object{}, err
	}
	if err := validateComponent(name); err != nil {
		return Object{}, err
	}
	unlock := s.locks.Lock(objectKey(bucket, name))
	defer unlock()
	row, err := s.objects.Get(ctx, bucket, name)
	if err != nil {
		return Object{}, err
	}
	return objectFromRow(row), nil
}

// Delete removes the metadata row first and then the file. It is idempotent:
// a missing row is treated as success, and a leftover file without a row is
// invisible to readers.
func (s *LocalObjectStorage) Delete(ctx context.Context, bucket, name string) error {
	if err := validateComponent(bucket); err != nil {
		return err
	}
	if err := validateComponent(name); err != nil {
		return err
	}
	unlock := s.locks.Lock(objectKey(bucket, name))
	defer unlock()

	if err := s.objects.Delete(ctx, bucket, name); err != nil {
		return fmt.Errorf("oss: delete metadata: %w", err)
	}
	path, err := s.filePath(bucket, name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("oss: delete file: %w", err)
	}
	return nil
}

// filePath resolves bucket/name under root and, as a final defense, verifies
// the result still lives inside root.
func (s *LocalObjectStorage) filePath(bucket, name string) (string, error) {
	full := filepath.Join(s.root, bucket, name)
	if full != s.root && !strings.HasPrefix(full, s.root+string(os.PathSeparator)) {
		return "", ErrInvalidKey
	}
	return full, nil
}

// objectFromRow converts persisted metadata into the storage API model.
func objectFromRow(row db.Object) Object {
	return Object{
		Bucket:       row.Bucket,
		Name:         row.Name,
		Size:         row.Size,
		ContentType:  row.ContentType,
		OriginalName: row.OriginalName,
		CreatedAt:    row.CreatedAt,
	}
}
