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
	archivePrefix = "zephyr"
	archiveExt    = ".zip"
	dateFormat    = "2006-01-02"

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
	mu   sync.Mutex
	dir  string
	keep int
	now  func() time.Time
	file *os.File // live log, opened O_APPEND

	// lastRotateDate is the calendar day of the most recent rotation; the
	// next rotation is due when dayDiff(now, lastRotateDate) >= rotateDayCount.
	lastRotateDate time.Time
	// lastRecordDate is the calendar day of the most recent Write and is
	// used as the archive base name (the logs really end that day).
	lastRecordDate time.Time

	// OnError, when set, receives runtime failures (archive/prune errors).
	// It is called synchronously while the writer lock is held, and must not
	// call back into the writer — wire it to the console handler, not the
	// combined logger, to avoid recursion through a failing file sink.
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

	w := &RotatingWriter{dir: dir, keep: cfg.Keep, now: cfg.Now}
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
	return w, nil
}

// Write appends p to the live file, rotating first when the interval is due.
// A failed rotation never drops the line: the error is reported through
// OnError and the write still proceeds, so the data survives until the next
// rotation attempt.
func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, errors.New("logging: writer closed")
	}
	if err := w.rotateIfDue(); err != nil {
		w.report(err)
	}
	n, err := w.file.Write(p)
	if err == nil {
		w.lastRecordDate = w.now()
	}
	return n, err
}

// Close closes the live file. The accumulated log is intentionally NOT
// archived here: like MCDR, the next process startup performs that archive,
// which also gives the archive a meaningful end date (mtime).
func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
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

// rotate archives the live file (unless Keep is 0) and starts fresh.
func (w *RotatingWriter) rotate() error {
	if w.keep != 0 {
		base := w.lastRecordDate.Format(dateFormat)
		if w.lastRecordDate.IsZero() {
			// No record was written by this process yet; fall back to the
			// live file mtime like the startup path does.
			fi, err := os.Stat(w.livePath())
			if err != nil {
				return fmt.Errorf("logging: stat live log: %w", err)
			}
			base = fi.ModTime().Format(dateFormat)
		}
		if err := w.archive(base); err != nil {
			return err
		}
	}
	// Keep == 0 means "no archives": truncating is the whole rotation.
	if err := w.file.Truncate(0); err != nil {
		return fmt.Errorf("logging: truncate live log: %w", err)
	}
	return w.prune()
}

// archive merges the live log into zephyr-<base>-<NN>.zip with a single
// DEFLATE entry named zephyr.log. The live file is only truncated by the
// caller after a successful archive, so a failed archive loses nothing.
func (w *RotatingWriter) archive(base string) error {
	src, err := os.Open(w.livePath())
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

	path, err := w.nextArchivePath(base)
	if err != nil {
		return err
	}
	dst, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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
		os.Remove(path)
		return fmt.Errorf("logging: write archive %s: %w", path, err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("logging: close archive %s: %w", path, err)
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

// report forwards a runtime failure to OnError, if set.
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
