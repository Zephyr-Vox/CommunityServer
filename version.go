// Package version exposes the repository version embedded from the VERSION
// file at the module root. Keeping the file at the root (not inside a
// package directory) forces this tiny root package: go:embed paths cannot
// escape their package directory.
package version

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version is the trimmed VERSION content, e.g. "0.0.1-pre1".
var Version = strings.TrimSpace(versionFile)
