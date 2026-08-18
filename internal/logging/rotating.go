package logging

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// liveLogName is the file that always receives the newest logs. Old
	// content is merged into dated archives, never appended to.
	liveLogName = "zephyr.log"

	// archivePrefix disambiguates our archives from unrelated files in the
	// configured directory so pruning can never delete something else.
	archivePrefix        = "zephyr"
	archiveExt           = ".zip"
	dateFormat           = "2006-01-02"
	pendingPrefix        = ".zephyr-pending-"
	pendingSuffix        = ".log"
	pendingArchiveSuffix = ".archive"
	freshPrefix          = ".zephyr-fresh-"

	// rotateDayCount mirrors MCDReforged's ROTATE_DAY_COUNT: the live log is
	// merged into an archive every 7 days. It is intentionally a constant:
	// there is no operational reason to tune it per deployment.
	rotateDayCount = 7
)

// RotatingWriterConfig configures NewRotatingWriter.
type RotatingWriterConfig struct {
	// Keep controls archive retention:
	//   - N > 0: keep the newest N archives, delete older ones;
	//   - 0: keep no archives at all — rotation only truncates the live file;
	//   - -1: keep every archive forever.
	Keep int

	// Now returns the current time and defaults to time.Now. Tests inject a
	// fake clock to drive rotation without sleeping.
	Now func() time.Time
	// ArchivePending replaces pending-file compression in deterministic tests.
	ArchivePending func(path, base string) error
	// RetryTicks drives worker retries in deterministic tests; nil uses 1m.
	RetryTicks <-chan time.Time
	// OnError receives runtime failures. Supplying it here ensures it is set
	// before the archive worker starts; it must return promptly and must not
	// write through this RotatingWriter.
	OnError func(error)
}

// RotatingWriter is an io.Writer that appends to liveLogName inside dir and,
// every rotateDayCount days, merges the accumulated file into a compressed
// zip archive before starting a fresh live file.
//
// The rotation schedule mirrors MCDReforged's ZippingDayRotatingFileHandler:
// a check happens lazily on Write (no background timer), and the archive is
// named after the last day that actually produced a log record, falling back
// to the file mtime for content written by a previous process.
type RotatingWriter struct {
	mu             sync.Mutex
	dir            string
	keep           int
	now            func() time.Time
	file           *os.File // live log, opened O_APPEND
	wake           chan struct{}
	workerDone     chan struct{}
	stop           chan struct{}
	closeOnce      sync.Once
	pendingSeq     uint64
	archivePending func(path, base string) error
	retryTicks     <-chan time.Time
	pruneRequested bool
	onError        func(error)

	// lastRotateDate is the calendar day of the most recent rotation; the
	// next rotation is due when dayDiff(now, lastRotateDate) >= rotateDayCount.
	lastRotateDate time.Time
	// lastRecordDate is the calendar day of the most recent Write and is
	// used as the archive base name (the logs really end that day).
	lastRecordDate time.Time
}

// NewRotatingWriter creates dir (0700), archives whatever the previous run
// left in liveLogName, and opens a fresh live file. Startup failures are
// returned as errors on purpose: a misconfigured log path should stop the
// server loudly instead of silently degrading.
func NewRotatingWriter(dir string, cfg RotatingWriterConfig) (*RotatingWriter, error) {
	if dir == "" {
		return nil, errors.New("logging: log dir must not be empty")
	}
	if cfg.Keep < -1 {
		return nil, errors.New("logging: archive_keep must be -1, 0, or a positive integer")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("logging: create log dir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("logging: secure log dir %s: %w", dir, err)
	}

	w := &RotatingWriter{dir: dir, keep: cfg.Keep, now: cfg.Now, wake: make(chan struct{}, 1), workerDone: make(chan struct{}), stop: make(chan struct{}), retryTicks: cfg.RetryTicks, onError: cfg.OnError}
	w.archivePending = w.archivePendingFile
	if cfg.ArchivePending != nil {
		w.archivePending = cfg.ArchivePending
	}
	if err := w.recoverPending(); err != nil {
		return nil, err
	}
	live := w.livePath()
	f, err := openPrivateAppend(live)
	if err != nil {
		return nil, fmt.Errorf("logging: open live log %s: %w", live, err)
	}
	w.file = f

	// Archive whatever the previous run left behind. The base name comes
	// from the file mtime because this process never saw those records.
	if fi, err := os.Stat(live); err == nil && fi.Size() > 0 {
		base := fi.ModTime().Format(dateFormat)
		if cfg.Keep != 0 {
			if err := w.archive(base); err != nil {
				f.Close()
				return nil, fmt.Errorf("logging: archive previous log: %w", err)
			}
		}
		// MCDR unlinks and reopens here; we truncate the open fd instead so
		// the inode and its permissions stay stable (single-instance server).
		if err := f.Truncate(0); err != nil {
			f.Close()
			return nil, fmt.Errorf("logging: truncate live log: %w", err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		f.Close()
		return nil, fmt.Errorf("logging: stat live log %s: %w", live, err)
	}

	w.lastRotateDate = w.now()
	if err := w.prune(); err != nil {
		f.Close()
		return nil, fmt.Errorf("logging: prune archives: %w", err)
	}
	go w.archiveWorker()
	return w, nil
}

// Write appends p to the live file, rotating first when the interval is due.
// A failed rotation never drops the line: the error is reported through
// OnError and the write still proceeds, so the data survives until the next
// rotation attempt.
func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	if w.file == nil {
		w.mu.Unlock()
		return 0, errors.New("logging: writer closed")
	}
	rotateErr := w.rotateIfDue()
	if rotateErr != nil {
		if w.file == nil {
			w.mu.Unlock()
			w.report(rotateErr)
			return 0, rotateErr
		}
	}
	n, err := w.file.Write(p)
	if err == nil {
		w.lastRecordDate = w.now()
	}
	w.mu.Unlock()
	if rotateErr != nil {
		w.report(rotateErr)
	}
	return n, err
}

// Close closes the live file, stops new worker work, and waits for the archive
// worker's final pending scan. The accumulated live log is intentionally not
// archived here: the next process startup gives it a meaningful end date.
func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	var err error
	if w.file != nil {
		err = w.file.Close()
		w.file = nil
	}
	w.closeOnce.Do(func() { close(w.stop) })
	w.mu.Unlock()
	<-w.workerDone
	return err
}

// rotateIfDue performs a rotation when at least rotateDayCount calendar days
// have passed since the last one. The check is lazy (on Write) on purpose:
// a daemon that only writes sporadically still rotates correctly, and there
// is no timer goroutine to leak or reschedule.
func (w *RotatingWriter) rotateIfDue() error {
	if dayDiff(w.now(), w.lastRotateDate) < rotateDayCount {
		return nil
	}
	if err := w.rotate(); err != nil {
		return err
	}
	w.lastRotateDate = w.now()
	return nil
}

// rotate switches the live file under the writer lock, then leaves expensive
// compression and pruning to the single background worker.
func (w *RotatingWriter) rotate() error {
	if w.keep == 0 {
		if err := w.file.Truncate(0); err != nil {
			return fmt.Errorf("logging: truncate live log: %w", err)
		}
		w.pruneRequested = true
		w.notifyWorker()
		return nil
	}
	// Create and secure the replacement before disturbing the current live
	// path. A creation failure therefore leaves the existing writer intact.
	fresh, err := os.CreateTemp(w.dir, freshPrefix+"*"+pendingSuffix)
	if err != nil {
		return fmt.Errorf("logging: create fresh live log: %w", err)
	}
	freshPath := fresh.Name()
	keepFresh := false
	defer func() {
		if !keepFresh {
			_ = fresh.Close()
			_ = os.Remove(freshPath)
		}
	}()
	if err := fresh.Chmod(0o600); err != nil {
		return fmt.Errorf("logging: secure fresh live log: %w", err)
	}
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("logging: close live log: %w", err)
	}
	w.file = nil
	reopenLive := func() error {
		f, err := openPrivateAppend(w.livePath())
		if err != nil {
			return err
		}
		w.file = f
		return nil
	}
	pending := filepath.Join(w.dir, fmt.Sprintf("%s%013d-%06d%s", pendingPrefix, w.now().UnixMilli(), w.pendingSeq, pendingSuffix))
	w.pendingSeq++
	if err := os.Rename(w.livePath(), pending); err != nil {
		return errors.Join(fmt.Errorf("logging: stage pending log: %w", err), reopenLive())
	}
	if !w.lastRecordDate.IsZero() {
		if err := os.Chtimes(pending, w.lastRecordDate, w.lastRecordDate); err != nil {
			_ = os.Rename(pending, w.livePath())
			return errors.Join(fmt.Errorf("logging: timestamp pending log: %w", err), reopenLive())
		}
	}
	if err := os.Rename(freshPath, w.livePath()); err != nil {
		_ = os.Rename(pending, w.livePath())
		return errors.Join(fmt.Errorf("logging: publish fresh live log: %w", err), reopenLive())
	}
	keepFresh = true
	w.file = fresh
	w.pruneRequested = true
	w.notifyWorker()
	return nil
}

// archive merges the live log into zephyr-<base>-<NN>.zip with a single
// DEFLATE entry named zephyr.log. The live file is only truncated by the
// caller after a successful archive, so a failed archive loses nothing.
func (w *RotatingWriter) archive(base string) error {
	return w.archiveFile(w.livePath(), base)
}

// archivePendingFile compresses one staged pending log with its original date.
func (w *RotatingWriter) archivePendingFile(path, base string) error {
	marker := path + pendingArchiveSuffix
	markerData, err := os.ReadFile(marker)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("logging: read pending archive marker: %w", err)
	}
	var target string
	if errors.Is(err, os.ErrNotExist) {
		target, err = w.reservePendingArchive(marker, path, base)
		if err != nil {
			return err
		}
	} else {
		targetName, digest, ok, parseErr := parsePendingMarker(markerData, path)
		if parseErr != nil {
			return parseErr
		}
		if ok {
			target = filepath.Join(w.dir, targetName)
			if _, err := os.Stat(target); err == nil {
				matches, err := archiveMatchesDigest(target, digest)
				if err != nil {
					return err
				}
				if matches {
					// The archive committed before a prior pending-file cleanup failed
					// or the process crashed. The digest binds this marker to this
					// pending file, so cleanup cannot discard unarchived data.
					return nil
				}
				ok = false
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("logging: stat pending archive target: %w", err)
			}
		}
		if !ok {
			// A torn, foreign, or mismatched marker never identifies an archive.
			// Remove only the marker and reserve a new target; an existing archive
			// with the same name is preserved for manual inspection and pruning.
			if err := os.Remove(marker); err != nil {
				return fmt.Errorf("logging: remove invalid pending archive marker: %w", err)
			}
			target, err = w.reservePendingArchive(marker, path, base)
			if err != nil {
				return err
			}
		}
	}
	return w.archiveFileTo(path, target)
}

// reservePendingArchive assigns marker a new valid archive name for base and
// returns its full path. Markers only ever persist archive basenames, never
// arbitrary paths, so recovery cannot redirect file operations elsewhere.
func (w *RotatingWriter) reservePendingArchive(marker, pending, base string) (string, error) {
	target, err := w.nextArchivePath(base)
	if err != nil {
		return "", err
	}
	digest, err := fileDigest(pending)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(marker, []byte(filepath.Base(target)+"\n"+digest), 0o600); err != nil {
		return "", fmt.Errorf("logging: write pending archive marker: %w", err)
	}
	return target, nil
}

// parsePendingMarker validates marker's archive name and binds its digest to
// pending. A false result means recovery must reserve a new archive target.
func parsePendingMarker(marker []byte, pending string) (name, digest string, ok bool, err error) {
	parts := strings.Split(string(marker), "\n")
	if len(parts) != 2 || !validArchiveName(parts[0]) || len(parts[1]) != sha256.Size*2 {
		return "", "", false, nil
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", "", false, nil
	}
	actual, err := fileDigest(pending)
	if err != nil {
		return "", "", false, err
	}
	return parts[0], parts[1], actual == parts[1], nil
}

// fileDigest returns the SHA-256 digest of one pending log as lowercase hex.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("logging: open pending log for digest: %w", err)
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", fmt.Errorf("logging: digest pending log: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// archiveMatchesDigest reports whether target is a complete one-entry archive
// whose zephyr.log content matches the digest stored for its pending source.
func archiveMatchesDigest(target, want string) (bool, error) {
	zr, err := zip.OpenReader(target)
	if err != nil {
		return false, nil
	}
	defer zr.Close()
	if len(zr.File) != 1 || zr.File[0].Name != liveLogName {
		return false, nil
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		return false, nil
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, rc)
	closeErr := rc.Close()
	if copyErr != nil || closeErr != nil {
		return false, nil
	}
	return hex.EncodeToString(hash.Sum(nil)) == want, nil
}

// validArchiveName reports whether name is an archive basename emitted by
// nextArchivePath. Pending markers must pass this check before their target is
// inspected or removed, preventing corrupt marker content from naming a live
// log or unrelated file in the logging directory.
func validArchiveName(name string) bool {
	prefix := archivePrefix + "-"
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, archiveExt) {
		return false
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(name, prefix), archiveExt)
	if len(rest) < len("2006-01-02-01") || rest[10] != '-' {
		return false
	}
	date := rest[:10]
	if parsed, err := time.Parse(dateFormat, date); err != nil || parsed.Format(dateFormat) != date {
		return false
	}
	sequence := rest[11:]
	if len(sequence) < 2 || len(sequence) > 4 {
		return false
	}
	value := 0
	for _, r := range sequence {
		if r < '0' || r > '9' {
			return false
		}
		value = value*10 + int(r-'0')
	}
	return value >= 1 && value <= 9999
}

// removeOrphanedMarkers deletes marker files whose pending log has already
// disappeared. They are crash leftovers from the small window after pending
// removal and before marker cleanup, and cannot represent recoverable work.
func (w *RotatingWriter) removeOrphanedMarkers() error {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return fmt.Errorf("logging: read pending markers: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasPrefix(name, pendingPrefix) || !strings.HasSuffix(name, pendingSuffix+pendingArchiveSuffix) {
			continue
		}
		pendingName := strings.TrimSuffix(name, pendingArchiveSuffix)
		if _, err := os.Stat(filepath.Join(w.dir, pendingName)); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("logging: stat pending log for marker: %w", err)
		}
		if err := os.Remove(filepath.Join(w.dir, name)); err != nil {
			return fmt.Errorf("logging: remove orphaned pending archive marker: %w", err)
		}
	}
	return nil
}

// removeOrphanedFreshFiles removes empty replacement files left if a process
// stopped between pre-creating a fresh live file and publishing it.
func (w *RotatingWriter) removeOrphanedFreshFiles() error {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return fmt.Errorf("logging: read fresh live files: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasPrefix(name, freshPrefix) || !strings.HasSuffix(name, pendingSuffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("logging: stat orphaned fresh live file: %w", err)
		}
		if info.Size() != 0 {
			continue
		}
		if err := os.Remove(filepath.Join(w.dir, name)); err != nil {
			return fmt.Errorf("logging: remove orphaned fresh live file: %w", err)
		}
	}
	return nil
}

// archiveFile merges path into the next dated archive without mutating path.
func (w *RotatingWriter) archiveFile(path, base string) error {
	src, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("logging: open live log: %w", err)
	}
	defer src.Close()
	fi, err := src.Stat()
	if err != nil {
		return fmt.Errorf("logging: stat live log: %w", err)
	}
	if fi.Size() == 0 {
		// Nothing to merge; skipping avoids empty zip files. The caller
		// still truncates (a no-op) and updates the rotation date.
		return nil
	}

	archivePath, err := w.nextArchivePath(base)
	if err != nil {
		return err
	}
	return w.archiveFileTo(path, archivePath)
}

// archiveFileTo writes path into the already-reserved archivePath.
func (w *RotatingWriter) archiveFileTo(path, archivePath string) error {
	src, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("logging: open live log: %w", err)
	}
	defer src.Close()
	fi, err := src.Stat()
	if err != nil {
		return fmt.Errorf("logging: stat live log: %w", err)
	}
	if fi.Size() == 0 {
		return nil
	}
	dst, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("logging: create archive %s: %w", path, err)
	}

	zw := zip.NewWriter(dst)
	hdr := &zip.FileHeader{
		Name:   liveLogName,
		Method: zip.Deflate,
	}
	hdr.Modified = fi.ModTime()
	hdr.SetMode(0o600)
	entry, err := zw.CreateHeader(hdr)
	if err == nil {
		_, err = io.Copy(entry, src)
	}
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		dst.Close()
		// A partial zip is worse than no archive: remove it so the next
		// rotation can retry with the full content.
		os.Remove(archivePath)
		return fmt.Errorf("logging: write archive %s: %w", archivePath, err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("logging: close archive %s: %w", archivePath, err)
	}
	return nil
}

// notifyWorker coalesces pending archive and prune work without blocking Write.
func (w *RotatingWriter) notifyWorker() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// archiveWorker serializes archive naming and pruning. Failed pending files
// remain on disk and are retried on the next wake or retry tick.
func (w *RotatingWriter) archiveWorker() {
	var ticker *time.Ticker
	retry := w.retryTicks
	if retry == nil {
		ticker = time.NewTicker(time.Minute)
		retry = ticker.C
		defer ticker.Stop()
	}
	defer close(w.workerDone)
	for {
		select {
		case <-w.wake:
			w.processPending()
		case <-retry:
			w.processPending()
		case <-w.stop:
			w.processPending()
			return
		}
	}
}

// processPending drains staged logs in lexical creation order, then prunes
// only when a rotation requested it. It never holds the Write mutex while zip
// compression or directory I/O runs.
func (w *RotatingWriter) processPending() {
	if err := w.removeOrphanedMarkers(); err != nil {
		w.report(err)
		return
	}
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		w.report(fmt.Errorf("logging: read pending logs: %w", err))
		return
	}
	var pending []string
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), pendingPrefix) && strings.HasSuffix(entry.Name(), pendingSuffix) {
			pending = append(pending, entry.Name())
		}
	}
	slices.Sort(pending)
	for _, name := range pending {
		path := filepath.Join(w.dir, name)
		if w.keep == 0 {
			if err := os.Remove(path); err != nil {
				w.report(fmt.Errorf("logging: remove pending log: %w", err))
				return
			}
			if err := os.Remove(path + pendingArchiveSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
				w.report(fmt.Errorf("logging: remove pending archive marker: %w", err))
				return
			}
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			w.report(fmt.Errorf("logging: stat pending log: %w", err))
			return
		}
		if err := w.archivePending(path, info.ModTime().Format(dateFormat)); err != nil {
			w.report(err)
			return
		}
		if err := os.Remove(path); err != nil {
			w.report(fmt.Errorf("logging: remove archived pending log: %w", err))
			return
		}
		if err := os.Remove(path + pendingArchiveSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			w.report(fmt.Errorf("logging: remove pending archive marker: %w", err))
			return
		}
	}
	w.mu.Lock()
	prune := w.pruneRequested
	w.pruneRequested = false
	w.mu.Unlock()
	if prune {
		if err := w.prune(); err != nil {
			w.report(err)
		}
	}
}

// recoverPending synchronously finishes files staged by a previous process.
// Startup has no request hot path, so a failure remains fail-fast.
func (w *RotatingWriter) recoverPending() error {
	if err := w.removeOrphanedFreshFiles(); err != nil {
		return err
	}
	if err := w.removeOrphanedMarkers(); err != nil {
		return err
	}
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return fmt.Errorf("logging: read pending logs: %w", err)
	}
	var pending []string
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), pendingPrefix) && strings.HasSuffix(entry.Name(), pendingSuffix) {
			pending = append(pending, entry.Name())
		}
	}
	slices.Sort(pending)
	for _, name := range pending {
		path := filepath.Join(w.dir, name)
		if w.keep == 0 {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("logging: remove pending log: %w", err)
			}
			if err := os.Remove(path + pendingArchiveSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("logging: remove pending archive marker: %w", err)
			}
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("logging: stat pending log: %w", err)
		}
		if err := w.archivePending(path, info.ModTime().Format(dateFormat)); err != nil {
			return fmt.Errorf("logging: recover pending log: %w", err)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("logging: remove recovered pending log: %w", err)
		}
		if err := os.Remove(path + pendingArchiveSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("logging: remove pending archive marker: %w", err)
		}
	}
	return nil
}

// nextArchivePath finds the first free zephyr-<base>-<NN>.zip name. The
// counter is zero-padded to two digits so plain lexicographic sorting equals
// chronological order, which pruning relies on.
func (w *RotatingWriter) nextArchivePath(base string) (string, error) {
	for i := 1; i <= 9999; i++ {
		p := filepath.Join(w.dir, fmt.Sprintf("%s-%s-%02d%s", archivePrefix, base, i, archiveExt))
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			return p, nil
		} else if err != nil {
			return "", fmt.Errorf("logging: stat archive %s: %w", p, err)
		}
	}
	return "", errors.New("logging: too many archives for one day")
}

// prune deletes the oldest archives so that at most keep remain. keep == 0
// removes every archive (the directory then only holds the live log), while
// keep == -1 skips pruning entirely. Only zephyr-*.zip files are considered.
func (w *RotatingWriter) prune() error {
	if w.keep < 0 {
		return nil
	}
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return fmt.Errorf("logging: read log dir: %w", err)
	}
	var archives []string
	for _, e := range entries {
		name := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(name, archivePrefix+"-") && strings.HasSuffix(name, archiveExt) {
			archives = append(archives, name)
		}
	}
	slices.Sort(archives)
	drop := len(archives) - w.keep
	if drop <= 0 {
		return nil
	}
	for _, name := range archives[:drop] {
		if err := os.Remove(filepath.Join(w.dir, name)); err != nil {
			return fmt.Errorf("logging: remove archive %s: %w", name, err)
		}
	}
	return nil
}

// livePath returns the full path of the live log file.
func (w *RotatingWriter) livePath() string {
	return filepath.Join(w.dir, liveLogName)
}

// openPrivateAppend opens path for append and tightens existing files to 0600.
func openPrivateAppend(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// report forwards a runtime failure to the constructor-supplied callback
// without the writer mutex. The callback may run concurrently from Write and
// archiveWorker.
func (w *RotatingWriter) report(err error) {
	if w.onError != nil {
		w.onError(err)
	}
}

// ReportTo returns a callback suitable for RotatingWriterConfig.OnError that
// routes log-file failures to handler h. Wire it to the console handler: using
// the combined logger there would recurse through the file writer that just
// failed.
func ReportTo(h slog.Handler) func(error) {
	return func(err error) {
		// Build a minimal ERROR record; module is omitted because this is
		// internal plumbing, not application logging.
		rec := slog.NewRecord(time.Now(), slog.LevelError, "log file error: "+err.Error(), 0)
		_ = h.Handle(context.Background(), rec)
	}
}

// dayDiff returns the number of calendar days between prev and now. Both
// dates are rebuilt as UTC midnights from their local calendar components,
// so daylight-saving transitions (23/25-hour days) cannot skew the count.
func dayDiff(now, prev time.Time) int {
	y1, m1, d1 := now.Date()
	y2, m2, d2 := prev.Date()
	t := time.Date(y1, m1, d1, 0, 0, 0, 0, time.UTC)
	p := time.Date(y2, m2, d2, 0, 0, 0, 0, time.UTC)
	return int(t.Sub(p) / (24 * time.Hour))
}
