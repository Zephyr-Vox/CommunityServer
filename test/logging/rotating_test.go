package logging_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/logging"
)

func newWriter(t *testing.T, dir string, keep int, now func() time.Time) *logging.RotatingWriter {
	t.Helper()
	w, err := logging.NewRotatingWriter(dir, logging.RotatingWriterConfig{Keep: keep, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

func writeLine(t *testing.T, w *logging.RotatingWriter, s string) {
	t.Helper()
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
}

func readLive(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "zephyr.log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func listArchives(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "zephyr-") && strings.HasSuffix(e.Name(), ".zip") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	return names
}

func waitArchives(t *testing.T, dir string, want int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		archives := listArchives(t, dir)
		if len(archives) == want {
			complete := true
			for _, name := range archives {
				zr, err := zip.OpenReader(filepath.Join(dir, name))
				if err != nil {
					complete = false
					break
				}
				_ = zr.Close()
			}
			if complete {
				return archives
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("archives = %v, want %d entries", archives, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func listPending(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".zephyr-pending-") && strings.HasSuffix(entry.Name(), ".log") {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	return names
}

func zipContent(t *testing.T, path string) string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if len(zr.File) != 1 {
		t.Fatalf("%s: %d entries, want 1", path, len(zr.File))
	}
	if zr.File[0].Name != "zephyr.log" {
		t.Fatalf("%s: entry %q, want zephyr.log", path, zr.File[0].Name)
	}
	f, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeOldLive(t *testing.T, dir, content string, mtime time.Time) {
	t.Helper()
	path := filepath.Join(dir, "zephyr.log")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func writeZip(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeZipContent(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	entry, err := zw.Create("zephyr.log")
	if err == nil {
		_, err = io.WriteString(entry, content)
	}
	if closeErr := zw.Close(); err == nil {
		err = closeErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
}

func validMarker(target, content string) []byte {
	sum := sha256.Sum256([]byte(content))
	return []byte(fmt.Sprintf("%s\n%x", target, sum))
}

func TestRotatingWriterStartupArchivesExistingFile(t *testing.T) {
	dir := t.TempDir()
	old := time.Date(2026, 8, 12, 23, 0, 0, 0, time.Local)
	writeOldLive(t, dir, "old line\n", old)
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.Local)

	w := newWriter(t, dir, -1, func() time.Time { return now })
	writeLine(t, w, "new line\n")

	archives := waitArchives(t, dir, 1)
	if len(archives) != 1 || archives[0] != "zephyr-2026-08-12-01.zip" {
		t.Fatalf("archives = %v, want [zephyr-2026-08-12-01.zip]", archives)
	}
	if got := zipContent(t, filepath.Join(dir, archives[0])); got != "old line\n" {
		t.Fatalf("archive content = %q, want old line", got)
	}
	if got := readLive(t, dir); got != "new line\n" {
		t.Fatalf("live content = %q, want new line", got)
	}
}

func TestRotatingWriterStartupRecoversPendingLog(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, ".zephyr-pending-0175560000000-000000.log")
	date := time.Date(2026, 8, 12, 23, 0, 0, 0, time.Local)
	if err := os.WriteFile(pending, []byte("pending line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(pending, date, date); err != nil {
		t.Fatal(err)
	}
	newWriter(t, dir, -1, func() time.Time { return date.Add(time.Hour) })
	archives := listArchives(t, dir)
	if len(archives) != 1 || zipContent(t, filepath.Join(dir, archives[0])) != "pending line\n" {
		t.Fatalf("pending recovery archives = %v", archives)
	}
	if pending := listPending(t, dir); len(pending) != 0 {
		t.Fatalf("pending files after recovery = %v", pending)
	}
}

func TestRotatingWriterRecoveryAcceptsCommittedDigestMarker(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, ".zephyr-pending-0175560000000-000000.log")
	content := "committed before crash\n"
	target := "zephyr-2026-08-12-01.zip"
	if err := os.WriteFile(pending, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	writeZipContent(t, filepath.Join(dir, target), content)
	if err := os.WriteFile(pending+".archive", validMarker(target, content), 0o600); err != nil {
		t.Fatal(err)
	}

	newWriter(t, dir, -1, func() time.Time { return time.Date(2026, 8, 13, 10, 0, 0, 0, time.Local) })
	if got := zipContent(t, filepath.Join(dir, target)); got != content {
		t.Fatalf("committed archive content = %q, want %q", got, content)
	}
	if pending := listPending(t, dir); len(pending) != 0 {
		t.Fatalf("pending files after committed-marker recovery = %v", pending)
	}
	if _, err := os.Stat(pending + ".archive"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed marker remained after recovery: %v", err)
	}
}

func TestRotatingWriterRecoveryRejectsForeignMarkerWithoutDeletingTarget(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, ".zephyr-pending-0175560000000-000000.log")
	if err := os.WriteFile(pending, []byte("pending line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pending+".archive", []byte("unrelated.txt"), 0o600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, "unrelated.txt")
	if err := os.WriteFile(unrelated, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	newWriter(t, dir, -1, func() time.Time { return time.Date(2026, 8, 13, 10, 0, 0, 0, time.Local) })
	data, err := os.ReadFile(unrelated)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep me" {
		t.Fatalf("foreign marker target changed to %q", data)
	}
	if _, err := os.Stat(pending + ".archive"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid marker remained after recovery: %v", err)
	}
}

func TestRotatingWriterStartupRemovesOrphanedMarker(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, ".zephyr-pending-0175560000000-000000.log.archive")
	if err := os.WriteFile(marker, []byte("zephyr-2026-08-12-01.zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	newWriter(t, dir, -1, func() time.Time { return time.Date(2026, 8, 13, 10, 0, 0, 0, time.Local) })
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned marker remained after startup: %v", err)
	}
}

func TestRotatingWriterRecoveryPreservesMismatchedMarkedArchive(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, ".zephyr-pending-0175560000000-000000.log")
	date := time.Date(2026, 8, 12, 23, 0, 0, 0, time.Local)
	if err := os.WriteFile(pending, []byte("recover me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(pending, date, date); err != nil {
		t.Fatal(err)
	}
	target := "zephyr-2026-08-12-01.zip"
	if err := os.WriteFile(filepath.Join(dir, target), []byte("partial zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pending+".archive", validMarker(target, "recover me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newWriter(t, dir, -1, func() time.Time { return date.Add(time.Hour) })
	if data, err := os.ReadFile(filepath.Join(dir, target)); err != nil || string(data) != "partial zip" {
		t.Fatalf("mismatched archive changed to %q, err=%v", data, err)
	}
	if got := zipContent(t, filepath.Join(dir, "zephyr-2026-08-12-02.zip")); got != "recover me\n" {
		t.Fatalf("recovered archive = %q, want pending content", got)
	}
	if pending := listPending(t, dir); len(pending) != 0 {
		t.Fatalf("pending files after recovery = %v", pending)
	}
}

func TestRotatingWriterWriteDoesNotWaitForArchiveAndCloseWaitsWorker(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 8, 1, 10, 0, 0, 0, time.Local)
	current := start
	started := make(chan struct{})
	release := make(chan struct{})
	w, err := logging.NewRotatingWriter(dir, logging.RotatingWriterConfig{
		Keep: -1,
		Now:  func() time.Time { return current },
		ArchivePending: func(string, string) error {
			close(started)
			<-release
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeLine(t, w, "before\n")
	current = current.AddDate(0, 0, 7)
	writeDone := make(chan error, 1)
	go func() { _, err := w.Write([]byte("after\n")); writeDone <- err }()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("rotation Write = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write waited for archive worker")
	}
	<-started
	closeDone := make(chan error, 1)
	go func() { closeDone <- w.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before worker archive completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close = %v", err)
	}
}

func TestRotatingWriterRotatesAfterSevenDays(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 8, 1, 10, 0, 0, 0, time.Local)
	current := start
	w := newWriter(t, dir, -1, func() time.Time { return current })

	writeLine(t, w, "a\n") // 2026-08-01
	current = start.AddDate(0, 0, 6)
	writeLine(t, w, "b\n") // 2026-08-07, still within the interval
	current = start.AddDate(0, 0, 7)
	writeLine(t, w, "c\n") // 2026-08-08: rotation due

	archives := waitArchives(t, dir, 1)
	if len(archives) != 1 || archives[0] != "zephyr-2026-08-07-01.zip" {
		t.Fatalf("archives = %v, want [zephyr-2026-08-07-01.zip] (base = last record date)", archives)
	}
	if got := zipContent(t, filepath.Join(dir, archives[0])); got != "a\nb\n" {
		t.Fatalf("archive content = %q, want a+b merged", got)
	}
	if got := readLive(t, dir); got != "c\n" {
		t.Fatalf("live content = %q, want only c", got)
	}
}

func TestRotatingWriterSameDayCounterIncrements(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 8, 1, 10, 0, 0, 0, time.Local)
	writeOldLive(t, dir, "seed\n", start.Add(-time.Hour))
	current := start
	w := newWriter(t, dir, -1, func() time.Time { return current })

	writeLine(t, w, "a\n")
	current = start.AddDate(0, 0, 7)
	writeLine(t, w, "b\n")

	archives := waitArchives(t, dir, 2)
	want := []string{"zephyr-2026-08-01-01.zip", "zephyr-2026-08-01-02.zip"}
	if !slices.Equal(archives, want) {
		t.Fatalf("archives = %v, want %v", archives, want)
	}
	// The startup archive holds the previous run's seed; the interval
	// archive holds the records written after that, both named by 08-01.
	if got := zipContent(t, filepath.Join(dir, archives[1])); got != "a\n" {
		t.Fatalf("second archive content = %q, want a", got)
	}
}

func TestRotatingWriterKeepZeroNoArchives(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 8, 1, 10, 0, 0, 0, time.Local)
	writeOldLive(t, dir, "old\n", start.Add(-time.Hour))
	writeZip(t, filepath.Join(dir, "zephyr-2026-08-01-01.zip"))
	current := start
	w := newWriter(t, dir, 0, func() time.Time { return current })

	// Startup truncated the old live file and pruned the existing archive.
	if archives := listArchives(t, dir); len(archives) != 0 {
		t.Fatalf("archives after startup = %v, want none", archives)
	}
	if got := readLive(t, dir); got != "" {
		t.Fatalf("live after startup = %q, want empty", got)
	}

	writeLine(t, w, "new\n")
	current = start.AddDate(0, 0, 7)
	writeLine(t, w, "after rotation\n")
	time.Sleep(10 * time.Millisecond)

	if archives := listArchives(t, dir); len(archives) != 0 {
		t.Fatalf("archives after rotation = %v, want none (keep=0)", archives)
	}
	if got := readLive(t, dir); got != "after rotation\n" {
		t.Fatalf("live = %q, want only the latest line", got)
	}
}

func TestRotatingWriterKeepZeroRemovesPendingMarker(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, ".zephyr-pending-0175560000000-000000.log")
	if err := os.WriteFile(pending, []byte("stale pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pending+".archive", []byte("zephyr-2026-08-12-01.zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	newWriter(t, dir, 0, func() time.Time { return time.Date(2026, 8, 13, 10, 0, 0, 0, time.Local) })
	if pending := listPending(t, dir); len(pending) != 0 {
		t.Fatalf("pending after keep=0 startup = %v", pending)
	}
	if _, err := os.Stat(pending + ".archive"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending marker after keep=0 startup = %v, want removed", err)
	}
}

func TestRotatingWriterKeepZeroWorkerRemovesPendingMarker(t *testing.T) {
	dir := t.TempDir()
	retry := make(chan time.Time, 1)
	w, err := logging.NewRotatingWriter(dir, logging.RotatingWriterConfig{Keep: 0, RetryTicks: retry})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	pending := filepath.Join(dir, ".zephyr-pending-0175560000000-000000.log")
	if err := os.WriteFile(pending, []byte("stale pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pending+".archive", []byte("zephyr-2026-08-12-01.zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	retry <- time.Now()
	deadline := time.Now().Add(time.Second)
	for {
		_, logErr := os.Stat(pending)
		_, markerErr := os.Stat(pending + ".archive")
		if errors.Is(logErr, os.ErrNotExist) && errors.Is(markerErr, os.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("keep=0 worker cleanup log=%v marker=%v", logErr, markerErr)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRotatingWriterKeepPrunesOldest(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"zephyr-2026-08-01-01.zip", "zephyr-2026-08-02-01.zip", "zephyr-2026-08-03-01.zip"} {
		writeZip(t, filepath.Join(dir, name))
	}
	newWriter(t, dir, 2, func() time.Time { return time.Date(2026, 8, 4, 0, 0, 0, 0, time.Local) })

	archives := listArchives(t, dir)
	want := []string{"zephyr-2026-08-02-01.zip", "zephyr-2026-08-03-01.zip"}
	if !slices.Equal(archives, want) {
		t.Fatalf("archives = %v, want %v", archives, want)
	}
}

func TestRotatingWriterKeepMinusOneKeepsAll(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"zephyr-2026-08-01-01.zip", "zephyr-2026-08-02-01.zip", "zephyr-2026-08-03-01.zip"} {
		writeZip(t, filepath.Join(dir, name))
	}
	newWriter(t, dir, -1, func() time.Time { return time.Date(2026, 8, 4, 0, 0, 0, 0, time.Local) })

	if archives := listArchives(t, dir); len(archives) != 3 {
		t.Fatalf("archives = %v, want all 3 kept", archives)
	}
}

func TestRotatingWriterSkipsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "zephyr.log"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	newWriter(t, dir, -1, func() time.Time { return time.Date(2026, 8, 13, 10, 0, 0, 0, time.Local) })

	if archives := listArchives(t, dir); len(archives) != 0 {
		t.Fatalf("archives = %v, want none for an empty live file", archives)
	}
}

func TestRotatingWriterCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "logs")
	w := newWriter(t, dir, -1, func() time.Time { return time.Date(2026, 8, 13, 10, 0, 0, 0, time.Local) })
	writeLine(t, w, "x\n")

	if got := readLive(t, dir); got != "x\n" {
		t.Fatalf("live = %q, want x", got)
	}
}

func TestRotatingWriterFilePermissions(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "zephyr.log")
	if err := os.WriteFile(live, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(live, 0o644); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 8, 1, 10, 0, 0, 0, time.Local)
	current := start
	w := newWriter(t, dir, -1, func() time.Time { return current })
	writeLine(t, w, "before\n")
	current = current.AddDate(0, 0, 7)
	writeLine(t, w, "after\n")
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("log directory mode = %o, want 700", info.Mode().Perm())
	}
	info, err = os.Stat(filepath.Join(dir, "zephyr.log"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("live log mode = %o, want 600", info.Mode().Perm())
	}
	archives := waitArchives(t, dir, 1)
	archivePath := filepath.Join(dir, archives[0])
	info, err = os.Stat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode = %o, want 600", info.Mode().Perm())
	}
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if mode := zr.File[0].Mode().Perm(); mode != 0o600 {
		t.Fatalf("zip entry mode = %o, want 600", mode)
	}
}

func TestRotatingWriterArchiveFailureKeepsLiveLog(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 8, 1, 10, 0, 0, 0, time.Local)
	current := start
	reported := make(chan error, 1)
	w, err := logging.NewRotatingWriter(dir, logging.RotatingWriterConfig{
		Keep: -1,
		Now:  func() time.Time { return current },
		OnError: func(err error) {
			reported <- err
		},
		ArchivePending: func(string, string) error {
			return errors.New("archive blocked")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	writeLine(t, w, "new1\n")

	current = start.AddDate(0, 0, 7)
	writeLine(t, w, "new2\n")

	select {
	case <-reported:
	case <-time.After(time.Second):
		t.Fatal("rotation failure was not reported through OnError")
	}
	if got := readLive(t, dir); got != "new2\n" {
		t.Fatalf("live = %q, want fresh live line after failed archive", got)
	}
	if pending := listPending(t, dir); len(pending) != 1 {
		t.Fatalf("pending = %v, want failed archive retained", pending)
	}
	archives := listArchives(t, dir)
	if len(archives) != 0 {
		t.Fatalf("archives = %v, want no partial archive", archives)
	}
}

func TestRotatingWriterRetriesFailedPendingOnTick(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 8, 1, 10, 0, 0, 0, time.Local)
	current := start
	retry := make(chan time.Time, 1)
	firstFailure := make(chan struct{})
	completed := make(chan struct{})
	attempts := 0
	w, err := logging.NewRotatingWriter(dir, logging.RotatingWriterConfig{
		Keep:       -1,
		Now:        func() time.Time { return current },
		RetryTicks: retry,
		ArchivePending: func(string, string) error {
			attempts++
			if attempts == 1 {
				close(firstFailure)
				return errors.New("archive failed once")
			}
			close(completed)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	writeLine(t, w, "before\n")
	current = current.AddDate(0, 0, 7)
	writeLine(t, w, "after\n")
	select {
	case <-firstFailure:
	case <-time.After(time.Second):
		t.Fatal("first archive attempt did not run")
	}
	if pending := listPending(t, dir); len(pending) != 1 {
		t.Fatalf("pending after failed archive = %v", pending)
	}
	retry <- current
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("retry tick did not archive pending log")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if pending := listPending(t, dir); len(pending) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending after retry = %v", listPending(t, dir))
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRotatingWriterReopensLiveAfterRotationStagingFailure(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 8, 1, 10, 0, 0, 0, time.Local)
	current := start
	reported := make(chan error, 1)
	w, err := logging.NewRotatingWriter(dir, logging.RotatingWriterConfig{
		Keep: -1,
		Now:  func() time.Time { return current },
		OnError: func(err error) {
			reported <- err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	writeLine(t, w, "before\n")

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	current = current.AddDate(0, 0, 7)
	writeLine(t, w, "survives\n")
	select {
	case <-reported:
	case <-time.After(time.Second):
		t.Fatal("staging failure was not reported")
	}
	if got := readLive(t, dir); got != "before\nsurvives\n" {
		t.Fatalf("live after failed rotation = %q", got)
	}
}

func TestRotatingWriterConcurrentClose(t *testing.T) {
	w, err := logging.NewRotatingWriter(t.TempDir(), logging.RotatingWriterConfig{Keep: -1})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() { errs <- w.Close() })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Close = %v", err)
		}
	}
	if _, err := w.Write([]byte("after close\n")); err == nil {
		t.Fatal("Write after concurrent Close unexpectedly succeeded")
	}
}

func TestRotatingWriterConcurrentWriteAndClose(t *testing.T) {
	dir := t.TempDir()
	startTime := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	var current atomic.Int64
	current.Store(startTime.UnixNano())
	w, err := logging.NewRotatingWriter(dir, logging.RotatingWriterConfig{
		Keep: -1,
		Now:  func() time.Time { return time.Unix(0, current.Load()) },
	})
	if err != nil {
		t.Fatal(err)
	}
	writeLine(t, w, "before rotation\n")
	current.Store(startTime.AddDate(0, 0, 7).UnixNano())
	const writers = 4
	const writesPerWriter = 10000
	start := make(chan struct{})
	ready := make(chan struct{}, writers)
	firstWrite := make(chan struct{}, writers)
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			<-start
			ready <- struct{}{}
			for i := range writesPerWriter {
				if _, err := w.Write([]byte("line\n")); err != nil {
					errs <- err
					return
				}
				if i == 0 {
					firstWrite <- struct{}{}
				}
			}
			errs <- nil
		})
	}
	close(start)
	for range writers {
		<-ready
	}
	for range writers {
		<-firstWrite
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && err.Error() != "logging: writer closed" {
			t.Fatalf("Write racing Close = %v", err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "zephyr.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line != "line" {
			t.Fatalf("partial or interleaved log line %q", line)
		}
	}
}

func TestRotatingWriterWriteAfterClose(t *testing.T) {
	w := newWriter(t, t.TempDir(), -1, func() time.Time { return time.Date(2026, 8, 13, 10, 0, 0, 0, time.Local) })
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("Write after Close must fail")
	}
}

func TestReportToRoutesToConsoleHandler(t *testing.T) {
	var buf bytes.Buffer
	console := logging.NewTextHandler(&buf, nil)
	logging.ReportTo(console)(errors.New("disk full"))

	if got := buf.String(); !strings.Contains(got, "[ERROR]") || !strings.Contains(got, "log file error") || !strings.Contains(got, "disk full") {
		t.Fatalf("console output = %q, want log-file error report", got)
	}
}

func TestNewRotatingWriterRejectsBadConfig(t *testing.T) {
	if _, err := logging.NewRotatingWriter("", logging.RotatingWriterConfig{}); err == nil {
		t.Fatal("empty dir must fail")
	}
	if _, err := logging.NewRotatingWriter(t.TempDir(), logging.RotatingWriterConfig{Keep: -2}); err == nil {
		t.Fatal("keep < -1 must fail")
	}
}
