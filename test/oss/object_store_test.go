package oss_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"zephyr.vox/server/ce/internal/oss"
)

func TestUpsertUpdatesMetadataOnOverwrite(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	e.clock.set(1_000)
	if _, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader("old"),
		oss.PutOptions{ContentType: "image/png", OriginalName: "a.png"}); err != nil {
		t.Fatal(err)
	}

	e.clock.set(2_000)
	if _, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader("newer"),
		oss.PutOptions{ContentType: "image/JPEG", OriginalName: "b.jpg"}); err != nil {
		t.Fatal(err)
	}

	obj, err := e.objects.Stat(ctx, "avatars", "1.png")
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 5 {
		t.Fatalf("size = %d, want 5", obj.Size)
	}
	if obj.ContentType != "image/jpeg" {
		t.Fatalf("content_type = %q, want image/jpeg", obj.ContentType)
	}
	if obj.OriginalName != "b.jpg" {
		t.Fatalf("original_name = %q, want b.jpg", obj.OriginalName)
	}
	if obj.CreatedAt != 2_000 {
		t.Fatalf("created_at = %d, want 2000", obj.CreatedAt)
	}
}

func TestDeleteRemovesMetadata(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.objects.Put(ctx, "avatars", "1.png", strings.NewReader("x"),
		oss.PutOptions{ContentType: "image/png"}); err != nil {
		t.Fatal(err)
	}
	if err := e.objects.Delete(ctx, "avatars", "1.png"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.objects.Stat(ctx, "avatars", "1.png"); !errors.Is(err, oss.ErrNotFound) {
		t.Fatalf("Stat after Delete = %v, want ErrNotFound", err)
	}
	if err := e.objects.Delete(ctx, "avatars", "1.png"); err != nil {
		t.Fatalf("second Delete = %v, want nil (idempotent)", err)
	}
}
