package oss

import (
	"fmt"
	"mime"
	"strconv"
	"strings"
)

const internalDirName = ".zephyr-internal"

// validateComponent checks that a bucket or name is a single path segment
// the filesystem accepts: non-empty, no slash, not "." or "..", no NUL.
// Spaces, Unicode, dots and dashes are allowed; naming policy belongs to
// the caller.
func validateComponent(s string) error {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\x00") {
		return ErrInvalidKey
	}
	return nil
}

// validateObjectName applies component validation and reserves the internal
// storage directory from every public object operation.
func validateObjectName(name string) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	if name == internalDirName {
		return ErrInvalidKey
	}
	return nil
}

// objectKey maps a bucket/name pair to the per-key lock identity. NUL cannot
// appear in either component, so it is a safe separator.
func objectKey(bucket, name string) string {
	return bucket + "\x00" + name
}

// NewName builds a conventional "<id>.<ext>" object name. It is a convenience
// helper only; the storage layer does not enforce any naming scheme.
func NewName(id int64, ext string) string {
	if ext == "" {
		return strconv.FormatInt(id, 10)
	}
	return fmt.Sprintf("%d.%s", id, ext)
}

var extensionByType = map[string]string{
	"image/jpeg":      "jpg",
	"image/png":       "png",
	"image/webp":      "webp",
	"image/gif":       "gif",
	"audio/mpeg":      "mp3",
	"audio/mp4":       "m4a",
	"audio/ogg":       "ogg",
	"application/ogg": "ogg",
	"audio/wav":       "wav",
	"audio/wave":      "wav",
	"audio/x-wav":     "wav",
	"video/mp4":       "mp4",
	"video/webm":      "webm",
	"application/pdf": "pdf",
}

// ExtensionFor maps a MIME type to a conventional file extension. Parameters
// are ignored; the media type itself is parsed and lowercased by the
// standard library. The second result is false when no mapping exists.
func ExtensionFor(contentType string) (string, bool) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", false
	}
	ext, ok := extensionByType[mediaType]
	return ext, ok
}
