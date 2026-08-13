package logging_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func TestRotatingWriterStartupArchivesExistingFile(t *testing.T) {
	dir := t.TempDir()
	old := time.Date(2026, 8, 12, 23, 0, 0, 0, time.Local)
	writeOldLive(t, dir, "old line\n", old)
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.Local)

	w := newWriter(t, dir, -1, func() time.Time { return now })
	writeLine(t, w, "new line\n")

	archives := listArchives(t, dir)
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

	archives := listArchives(t, dir)
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

	archives := listArchives(t, dir)
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

	if archives := listArchives(t, dir); len(archives) != 0 {
		t.Fatalf("archives after rotation = %v, want none (keep=0)", archives)
	}
	if got := readLive(t, dir); got != "after rotation\n" {
		t.Fatalf("live = %q, want only the latest line", got)
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

func TestRotatingWriterArchiveFailureKeepsLiveLog(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 8, 1, 10, 0, 0, 0, time.Local)
	writeOldLive(t, dir, "old\n", start.Add(-time.Hour))
	current := start
	w := newWriter(t, dir, -1, func() time.Time { return current })
	writeLine(t, w, "new1\n")

	// Remove directory write permission so creating the archive zip fails.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	var reported error
	w.OnError = func(err error) { reported = err }
	current = start.AddDate(0, 0, 7)
	writeLine(t, w, "new2\n")

	if reported == nil {
		t.Fatal("rotation failure was not reported through OnError")
	}
	if got := readLive(t, dir); got != "new1\nnew2\n" {
		t.Fatalf("live = %q, want both lines preserved after failed archive", got)
	}
	// Only the startup archive exists; the failed rotation must not have
	// left a partial zip behind.
	archives := listArchives(t, dir)
	if len(archives) != 1 || archives[0] != "zephyr-2026-08-01-01.zip" {
		t.Fatalf("archives = %v, want only the startup archive", archives)
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
