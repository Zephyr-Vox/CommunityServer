package oss_test

import (
	"testing"

	"zephyr.vox/server/ce/internal/oss"
)

func TestNewName(t *testing.T) {
	if got := oss.NewName(123, "png"); got != "123.png" {
		t.Fatalf("NewName(123, png) = %q, want 123.png", got)
	}
	if got := oss.NewName(123, ""); got != "123" {
		t.Fatalf("NewName(123, \"\") = %q, want 123", got)
	}
}

func TestExtensionFor(t *testing.T) {
	cases := map[string]string{
		"image/jpeg":            "jpg",
		"IMAGE/PNG":             "png",
		"image/jpeg; charset=x": "jpg",
		"audio/mpeg":            "mp3",
		"application/ogg":       "ogg",
	}
	for in, want := range cases {
		got, ok := oss.ExtensionFor(in)
		if !ok || got != want {
			t.Fatalf("ExtensionFor(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if _, ok := oss.ExtensionFor("application/x-unknown"); ok {
		t.Fatal("ExtensionFor(unknown) should report false")
	}
	if _, ok := oss.ExtensionFor("not a mime"); ok {
		t.Fatal("ExtensionFor(invalid) should report false")
	}
}
