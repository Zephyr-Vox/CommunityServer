package logging

import (
	"archive/zip"
	"context"
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

	// lastRotateDate is the calendar day of the most recent rotation; the
	// next rotation is due when dayDiff(now, lastRotateDate) >= rotateDayCount.
	lastRotateDate time.Time
	// lastRecordDate is the calendar day of the most recent Write and is
	// used as the archive base name (the logs really end that day).
	lastRecordDate time.Time

	// OnError, when set, receives runtime failures (rotation, archive, prune).
	// Write and the archive worker may invoke it concurrently and neither holds
	// the writer mutex while calling it. It must return promptly, be safe for
	// concurrent calls, and must not write through this RotatingWriter; wire it
	// to the console handler rather than the combined logger to avoid recursion.
	OnError func(error)
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

	w := &RotatingWriter{dir: dir, keep: cfg.Keep, now: cfg.Now, wake: make(chan struct{}, 1), workerDone: make(chan struct{}), stop: make(chan struct{}), retryTicks: cfg.RetryTicks}
	w.archivePending = w.archivePendingFile
	if cfg.ArchivePending != nil {
		w.archivePending = cfg.ArchivePending
	}
	if err := w.recoverPending(); err != nil {
		return nil, err
	}
	live := w.livePath()
	f, err := os.OpenFile(live, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
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
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("logging: close live log: %w", err)
	}
	w.file = nil
	reopenLive := func() error {
		f, err := os.OpenFile(w.livePath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
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
	f, err := os.OpenFile(w.livePath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		_ = os.Rename(pending, w.livePath())
		return errors.Join(fmt.Errorf("logging: open fresh live log: %w", err), reopenLive())
	}
	w.file = f
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
	targetName, err := os.ReadFile(marker)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("logging: read pending archive marker: %w", err)
	}
	var target string
	if errors.Is(err, os.ErrNotExist) {
		target, err = w.nextArchivePath(base)
		if err != nil {
			return err
		}
		if err := os.WriteFile(marker, []byte(filepath.Base(target)), 0o600); err != nil {
			return fmt.Errorf("logging: write pending archive marker: %w", err)
		}
	} else {
		target = filepath.Join(w.dir, string(targetName))
		if filepath.Base(target) != string(targetName) {
			return errors.New("logging: invalid pending archive marker")
		}
	}
	if _, err := os.Stat(target); err == nil {
		valid, validateErr := validArchive(target)
		if validateErr != nil {
			return validateErr
		}
		if valid {
			// The archive committed before a prior pending-file cleanup failed or
			// the process crashed. Returning success makes the caller retry only
			// cleanup, never compression into a second zip.
			return nil
		}
		if err := os.Remove(target); err != nil {
			return fmt.Errorf("logging: remove incomplete pending archive: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("logging: stat pending archive target: %w", err)
	}
	return w.archiveFileTo(path, target)
}

// validArchive verifies that target is a complete one-entry log archive before
// pending cleanup can trust a marker left by a previous process.
func validArchive(target string) (bool, error) {
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
	_, copyErr := io.Copy(io.Discard, rc)
	closeErr := rc.Close()
	if copyErr != nil || closeErr != nil {
		return false, nil
	}
	return true, nil
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

// report forwards a runtime failure to OnError without the writer mutex. The
// callback may run concurrently from Write and archiveWorker.
func (w *RotatingWriter) report(err error) {
	if w.OnError != nil {
		w.OnError(err)
	}
}

// ReportTo returns a callback suitable for RotatingWriter.OnError that routes
// log-file failures to handler h. Wire it to the console handler: using the
// combined logger there would recurse through the file writer that just
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
