package oss_test

import (
	"io"
	"strings"
	"testing"

	"zephyr.vox/server/ce/internal/oss"
)

func TestDetectContentTypeReplaysAllBytes(t *testing.T) {
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01, 0x02, 0x03}
	contentType, rest, err := oss.DetectContentType(strings.NewReader(string(png)))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "image/png" {
		t.Fatalf("content_type = %q, want image/png", contentType)
	}
	replayed, err := io.ReadAll(rest)
	if err != nil {
		t.Fatal(err)
	}
	if string(replayed) != string(png) {
		t.Fatalf("replayed %q, want %q", replayed, png)
	}
}

func TestDetectContentTypeText(t *testing.T) {
	contentType, _, err := oss.DetectContentType(strings.NewReader("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "text/plain; charset=utf-8" {
		t.Fatalf("content_type = %q, want text/plain", contentType)
	}
}

func TestDetectContentTypeEmptyStream(t *testing.T) {
	contentType, _, err := oss.DetectContentType(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "application/octet-stream" {
		t.Fatalf("content_type = %q, want application/octet-stream", contentType)
	}
}
