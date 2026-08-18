package oss_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"zephyr.vox/server/ce/internal/oss"
	"zephyr.vox/server/ce/internal/store"
)

func TestPutOpenStatDeleteRoundTrip(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	obj, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader("hello"),
		oss.PutOptions{ContentType: "image/png", OriginalName: "hi.png"})
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 5 {
		t.Fatalf("size = %d, want 5", obj.Size)
	}

	stat, err := e.objects.Stat(ctx, "avatars", "1.png")
	if err != nil {
		t.Fatal(err)
	}
	if stat.ContentType != "image/png" || stat.OriginalName != "hi.png" {
		t.Fatalf("stat = %+v", stat)
	}

	got, rc, err := e.objects.Open(ctx, "avatars", "1.png")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" || got.Size != 5 {
		t.Fatalf("open = %q size %d", data, got.Size)
	}

	if err := e.objects.Delete(ctx, "avatars", "1.png"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.objects.Stat(ctx, "avatars", "1.png"); !errors.Is(err, oss.ErrNotFound) {
		t.Fatalf("Stat after Delete = %v, want ErrNotFound", err)
	}
}

func TestOpenMissingFileIsNotFound(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader("x"),
		oss.PutOptions{ContentType: "image/png"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.root, "avatars", "1.png")); err != nil {
		t.Fatal(err)
	}

	if _, _, err := e.objects.Open(ctx, "avatars", "1.png"); !errors.Is(err, oss.ErrNotFound) {
		t.Fatalf("Open with missing file = %v, want ErrNotFound", err)
	}
	// Stat only reads metadata and therefore still succeeds.
	if _, err := e.objects.Stat(ctx, "avatars", "1.png"); err != nil {
		t.Fatalf("Stat with missing file = %v, want metadata", err)
	}
}

func TestRejectsUnsafeComponents(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	cases := [][2]string{
		{"..", "x"},
		{"avatars", ".."},
		{"avatars", "../x"},
		{"avatars", "a/b"},
		{"", "x"},
		{"avatars", ""},
		{"avatars", "."},
	}
	for _, tc := range cases {
		if _, err := e.objects.Put(ctx, tc[0], tc[1], strings.NewReader("x"), oss.PutOptions{}); !errors.Is(err, oss.ErrInvalidKey) {
			t.Fatalf("Put(%q, %q) = %v, want ErrInvalidKey", tc[0], tc[1], err)
		}
		if _, err := e.objects.Stat(ctx, tc[0], tc[1]); !errors.Is(err, oss.ErrInvalidKey) {
			t.Fatalf("Stat(%q, %q) = %v, want ErrInvalidKey", tc[0], tc[1], err)
		}
		if err := e.objects.Delete(ctx, tc[0], tc[1]); !errors.Is(err, oss.ErrInvalidKey) {
			t.Fatalf("Delete(%q, %q) = %v, want ErrInvalidKey", tc[0], tc[1], err)
		}
		if _, rc, err := e.objects.Open(ctx, tc[0], tc[1]); !errors.Is(err, oss.ErrInvalidKey) {
			if rc != nil {
				_ = rc.Close()
			}
			t.Fatalf("Open(%q, %q) = %v, want ErrInvalidKey", tc[0], tc[1], err)
		}
	}
	if _, err := e.objects.Put(ctx, "avatars", ".zephyr-internal", strings.NewReader("x"), oss.PutOptions{}); !errors.Is(err, oss.ErrInvalidKey) {
		t.Fatalf("Put reserved name = %v, want ErrInvalidKey", err)
	}
	if _, err := e.objects.Stat(ctx, "avatars", ".zephyr-internal"); !errors.Is(err, oss.ErrInvalidKey) {
		t.Fatalf("Stat reserved name = %v, want ErrInvalidKey", err)
	}
	if err := e.objects.Delete(ctx, "avatars", ".zephyr-internal"); !errors.Is(err, oss.ErrInvalidKey) {
		t.Fatalf("Delete reserved name = %v, want ErrInvalidKey", err)
	}
	if _, rc, err := e.objects.Open(ctx, "avatars", ".zephyr-internal"); !errors.Is(err, oss.ErrInvalidKey) {
		if rc != nil {
			_ = rc.Close()
		}
		t.Fatalf("Open reserved name = %v, want ErrInvalidKey", err)
	}
}

func TestPutKeepsPublicBackupSuffixObjectsIndependent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for name, content := range map[string]string{"foo": "one", "foo.bak": "two"} {
		if _, err := e.objects.Put(ctx, "avatars", name, strings.NewReader(content), oss.PutOptions{ContentType: "text/plain"}); err != nil {
			t.Fatalf("Put(%q) = %v", name, err)
		}
	}
	if _, err := e.objects.Put(ctx, "avatars", "foo", strings.NewReader("three"), oss.PutOptions{ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	_, rc, err := e.objects.Open(ctx, "avatars", "foo.bak")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "two" {
		t.Fatalf("foo.bak content = %q, want two", data)
	}
}

func TestAcceptsFilesystemFlexibleNames(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	bucket, name := "user content", "头像 1.png"
	if _, err := e.objects.Put(ctx, bucket, name, strings.NewReader("x"),
		oss.PutOptions{ContentType: "image/png"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.objects.Stat(ctx, bucket, name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.root, bucket, name)); err != nil {
		t.Fatalf("file not on disk: %v", err)
	}
}

func TestContentTypeNormalizationAndSniffing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01}
	if _, err := e.objects.Put(ctx, "avatars", "a.png", strings.NewReader(string(png)),
		oss.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	obj, err := e.objects.Stat(ctx, "avatars", "a.png")
	if err != nil {
		t.Fatal(err)
	}
	if obj.ContentType != "image/png" {
		t.Fatalf("sniffed content_type = %q, want image/png", obj.ContentType)
	}

	if _, err := e.objects.Put(ctx, "avatars", "b.png", strings.NewReader("x"),
		oss.PutOptions{ContentType: "IMAGE/PNG"}); err != nil {
		t.Fatal(err)
	}
	obj, err = e.objects.Stat(ctx, "avatars", "b.png")
	if err != nil {
		t.Fatal(err)
	}
	if obj.ContentType != "image/png" {
		t.Fatalf("normalized content_type = %q, want image/png", obj.ContentType)
	}
}

func TestConcurrentPuts(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = e.objects.Put(ctx, "avatars", fmt.Sprintf("%d.png", i),
				strings.NewReader("x"), oss.PutOptions{ContentType: "image/png"})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
		if _, err := e.objects.Stat(ctx, "avatars", fmt.Sprintf("%d.png", i)); err != nil {
			t.Fatalf("Stat %d: %v", i, err)
		}
	}
}

func TestConcurrentSameKeyPutsEndConsistent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	payloads := []struct {
		content     string
		contentType string
	}{
		{"A", "image/png"},
		{"BB", "text/plain"},
		{"CCC", "image/jpeg"},
	}

	const writers = 8
	const rounds = 10
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				p := payloads[(w+i)%len(payloads)]
				if _, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader(p.content),
					oss.PutOptions{ContentType: p.contentType}); err != nil {
					t.Errorf("Put: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	obj, err := e.objects.Stat(ctx, "avatars", "1.png")
	if err != nil {
		t.Fatal(err)
	}
	_, rc, err := e.objects.Open(ctx, "avatars", "1.png")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}

	wantType := ""
	for _, p := range payloads {
		if string(data) == p.content {
			wantType = p.contentType
			break
		}
	}
	if wantType == "" {
		t.Fatalf("content %q matches no payload", data)
	}
	if obj.ContentType != wantType || obj.Size != int64(len(data)) {
		t.Fatalf("metadata %+v inconsistent with content %q", obj, data)
	}
}

func TestConcurrentFooAndBackupSuffixRemainIndependent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	payloads := map[string][]struct {
		content     string
		contentType string
	}{
		"foo":     {{"A", "image/png"}, {"BB", "text/plain"}, {"CCC", "image/jpeg"}},
		"foo.bak": {{"one", "application/octet-stream"}, {"two", "text/plain"}, {"three", "image/png"}},
	}

	var wg sync.WaitGroup
	for name, values := range payloads {
		for worker := range 8 {
			wg.Go(func() {
				for round := range 20 {
					value := values[(worker+round)%len(values)]
					if _, err := e.objects.Put(ctx, "avatars", name, strings.NewReader(value.content), oss.PutOptions{ContentType: value.contentType}); err != nil {
						t.Errorf("Put(%q): %v", name, err)
						return
					}
				}
			})
		}
	}
	wg.Wait()

	for name, values := range payloads {
		obj, err := e.objects.Stat(ctx, "avatars", name)
		if err != nil {
			t.Fatalf("Stat(%q): %v", name, err)
		}
		_, rc, err := e.objects.Open(ctx, "avatars", name)
		if err != nil {
			t.Fatalf("Open(%q): %v", name, err)
		}
		data, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		matched := false
		for _, value := range values {
			if string(data) == value.content {
				matched = true
				if obj.ContentType != value.contentType || obj.Size != int64(len(data)) {
					t.Fatalf("%s metadata %+v inconsistent with %q", name, obj, data)
				}
				break
			}
		}
		if !matched {
			t.Fatalf("%s content %q matches no writer payload", name, data)
		}
	}
}

func TestConcurrentFooAndBackupSuffixPutDeleteRemainIndependent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, name := range []string{"foo", "foo.bak"} {
		if _, err := e.objects.Put(ctx, "avatars", name, strings.NewReader("initial"), oss.PutOptions{ContentType: "text/plain"}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for _, name := range []string{"foo", "foo.bak"} {
		name := name
		wg.Go(func() {
			for range 20 {
				if _, err := e.objects.Put(ctx, "avatars", name, strings.NewReader("put-"+name), oss.PutOptions{ContentType: "text/plain"}); err != nil {
					t.Errorf("Put(%q): %v", name, err)
					return
				}
			}
		})
		wg.Go(func() {
			for range 20 {
				if err := e.objects.Delete(ctx, "avatars", name); err != nil {
					t.Errorf("Delete(%q): %v", name, err)
					return
				}
			}
		})
	}
	wg.Wait()
	for _, name := range []string{"foo", "foo.bak"} {
		want := "final-" + name
		if _, err := e.objects.Put(ctx, "avatars", name, strings.NewReader(want), oss.PutOptions{ContentType: "text/plain"}); err != nil {
			t.Fatal(err)
		}
		obj, rc, err := e.objects.Open(ctx, "avatars", name)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(data) != want || obj.Size != int64(len(want)) {
			t.Fatalf("final %q state = %q %+v", name, data, obj)
		}
	}
}

func TestSuccessfulOverwriteCleansInternalTempAndBackupFiles(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	internal := filepath.Join(e.root, "avatars", ".zephyr-internal")
	for _, dir := range []string{internal, filepath.Join(internal, "tmp"), filepath.Join(internal, "backup")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.objects.Put(ctx, "avatars", "foo", strings.NewReader("old"), oss.PutOptions{ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.objects.Put(ctx, "avatars", "foo", strings.NewReader("new"), oss.PutOptions{ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"", "tmp", "backup"} {
		path := filepath.Join(internal, dir)
		internalInfo, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if internalInfo.Mode().Perm() != 0o700 {
			t.Fatalf("internal directory %q mode = %o, want 700", dir, internalInfo.Mode().Perm())
		}
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("internal %s files after successful overwrite = %v", dir, entries)
		}
	}
}

func TestConcurrentPutDeleteSameKeyEndConsistent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	const rounds = 20
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if _, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader("data"),
				oss.PutOptions{ContentType: "text/plain"}); err != nil {
				t.Errorf("Put: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if err := e.objects.Delete(ctx, "avatars", "1.png"); err != nil {
				t.Errorf("Delete: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	if _, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader("final"),
		oss.PutOptions{ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	obj, err := e.objects.Stat(ctx, "avatars", "1.png")
	if err != nil {
		t.Fatal(err)
	}
	_, rc, err := e.objects.Open(ctx, "avatars", "1.png")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "final" || obj.Size != 5 {
		t.Fatalf("final state inconsistent: content %q, metadata %+v", data, obj)
	}
}

func TestPutOverwriteFailureRestoresOldFile(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader("old"),
		oss.PutOptions{ContentType: "image/png"}); err != nil {
		t.Fatal(err)
	}

	// Break the metadata connection so the upsert after the file swap fails.
	if err := e.conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader("new content"),
		oss.PutOptions{ContentType: "image/jpeg"}); err == nil {
		t.Fatal("want metadata failure")
	}

	// The old file must be back in place, with no new or backup leftovers.
	data, err := os.ReadFile(filepath.Join(e.root, "avatars", "1.png"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Fatalf("file content = %q, want old", data)
	}
	if _, err := os.Stat(filepath.Join(e.root, "avatars", "1.png.bak")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup file should not remain, stat err = %v", err)
	}
	for _, dir := range []string{"tmp", "backup"} {
		entries, err := os.ReadDir(filepath.Join(e.root, "avatars", ".zephyr-internal", dir))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("internal %s files after failed overwrite = %v", dir, entries)
		}
	}

	// Reopen the database: the old metadata row must match the old file.
	conn, err := store.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	objects, err := oss.NewLocalObjectStorage(e.root, conn, e.clock.get)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := objects.Stat(ctx, "avatars", "1.png")
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 3 || obj.ContentType != "image/png" {
		t.Fatalf("metadata = %+v, want old row", obj)
	}
}

func TestPutKeepsStaleBackupUntilCommit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader("old"),
		oss.PutOptions{ContentType: "image/png"}); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash between stashing the old file and renaming the new one.
	path := filepath.Join(e.root, "avatars", "1.png")
	sum := sha256.Sum256([]byte("1.png"))
	backup := filepath.Join(e.root, "avatars", ".zephyr-internal", "backup", fmt.Sprintf("%x", sum[:]))
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}

	// Break the metadata connection so the upsert after the file swap fails.
	if err := e.conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader("new content"),
		oss.PutOptions{ContentType: "image/jpeg"}); err == nil {
		t.Fatal("want metadata failure")
	}

	// The old copy must be restored to path, and the backup consumed.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Fatalf("file content = %q, want old after failed commit", data)
	}
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup should be consumed by the restore, stat err = %v", err)
	}

	// Reopen the database: the old metadata row must match the restored file.
	conn, err := store.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	objects, err := oss.NewLocalObjectStorage(e.root, conn, e.clock.get)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := objects.Stat(ctx, "avatars", "1.png")
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 3 || obj.ContentType != "image/png" {
		t.Fatalf("metadata = %+v, want old row", obj)
	}

	// A later successful Put must commit the new file, then remove the backup.
	if _, err := objects.Put(ctx, "avatars", "1.png", strings.NewReader("new"),
		oss.PutOptions{ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("file content = %q, want new", data)
	}
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup should be cleaned after commit, stat err = %v", err)
	}
	obj, err = objects.Stat(ctx, "avatars", "1.png")
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 3 || obj.ContentType != "text/plain" {
		t.Fatalf("metadata = %+v, want committed row", obj)
	}
}

func TestNewLocalObjectStorageRejectsEmptyRoot(t *testing.T) {
	e := newEnv(t)
	if _, err := oss.NewLocalObjectStorage("", e.conn, e.clock.get); err == nil {
		t.Fatal("want error for empty root")
	}
}
