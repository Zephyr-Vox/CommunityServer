package oss

import (
	"bufio"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

const sniffHeaderBytes = 512

// DetectContentType reads up to sniffHeaderBytes bytes from src, sniffs the
// content type with http.DetectContentType, and returns a reader that replays
// every byte read. An empty stream is reported as application/octet-stream.
func DetectContentType(src io.Reader) (string, io.Reader, error) {
	br := bufio.NewReader(src)
	head, err := br.Peek(sniffHeaderBytes)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", nil, err
	}
	if len(head) == 0 {
		return "application/octet-stream", br, nil
	}
	return http.DetectContentType(head), br, nil
}

// normalizeContentType canonicalizes a MIME type through the standard
// library: the media type is lowercased and parameters are re-formatted.
// Invalid or empty input returns "".
func normalizeContentType(raw string) string {
	if raw == "" {
		return ""
	}
	mediaType, params, err := mime.ParseMediaType(raw)
	if err != nil {
		return ""
	}
	return mime.FormatMediaType(strings.ToLower(mediaType), params)
}
