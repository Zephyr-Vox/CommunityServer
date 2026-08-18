// Package servercard generates ZephyrVox join URLs.
//
// A join URL carries everything a client needs to bootstrap a server
// connection: the control-plane address, the transport scheme, the server's
// SPKI fingerprint (for TLS) and an optional invite code. The fingerprint is
// the trust anchor: the URL is just a machine-readable envelope that the
// client verifies byte-for-byte, so no human comparison step is involved.
//
// The server only ever generates these URLs (startup log, admin docs); URL
// parsing is a client-side concern and deliberately does not live here.
// Keeping this package server-side still matters: it defines the exact query
// ordering and escaping that the client parsing contract must accept.
//
// Two schemes exist on purpose:
//
//	zephyrvox://  plaintext; must NOT carry fp
//	zephyrvoxs:// TLS; must carry fp
//
// The scheme is the client's transport decision. A TLS URL that fails to
// connect must never fall back to plaintext, and a plaintext URL for a server
// that requires TLS must be rejected by the client.
//
// This package is pure: no Echo, no config, no network I/O. Server code uses
// it to emit join URLs; the client codebase implements the same parsing
// contract independently.
package servercard

import (
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	// SchemePlain is the plaintext join URL scheme.
	SchemePlain = "zephyrvox"
	// SchemeTLS is the TLS join URL scheme. It requires a fingerprint.
	SchemeTLS = "zephyrvoxs"
	// protocolVersion is the current join URL layout version. Bumping it
	// lets clients reject future incompatible URLs instead of guessing.
	protocolVersion = "1"
)

// Card is a constructed join URL. Host is stored without IPv6 brackets
// ("::1", not "[::1]"); String re-adds them when needed.
type Card struct {
	Scheme      string // SchemePlain or SchemeTLS
	Host        string // bare hostname or IP, no brackets
	Port        int    // control-plane HTTP port, 1-65535
	Fingerprint string // SPKI SHA-256 hex, 64 chars; only for TLS
	Invite      string // optional invite code; empty means absent
}

// New validates join parameters and returns a canonical Card. Server code
// uses it to emit join URLs, so invalid combinations fail here instead of
// producing a URL that clients would reject.
func New(host string, port int, fingerprint, invite string, tls bool) (Card, error) {
	host = strings.TrimSpace(host)
	// Accept "[::1]" as a convenience for users copying an address, but store
	// the bare form so net.JoinHostPort does not double-bracket it.
	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") || len(host) < 3 {
			return Card{}, errors.New("servercard: malformed IPv6 host")
		}
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return Card{}, errors.New("servercard: host is required")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return Card{}, errors.New("servercard: host must not contain a port")
	}
	if port < 1 || port > 65535 {
		return Card{}, errors.New("servercard: port must be 1-65535")
	}
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if tls {
		if err := validateFingerprint(fingerprint); err != nil {
			return Card{}, err
		}
	} else if fingerprint != "" {
		return Card{}, errors.New("servercard: plaintext URLs must not carry a fingerprint")
	}
	invite = strings.TrimSpace(invite)
	scheme := SchemePlain
	if tls {
		scheme = SchemeTLS
	}
	return Card{Scheme: scheme, Host: host, Port: port, Fingerprint: fingerprint, Invite: invite}, nil
}

// String renders the canonical join URL with the fixed query order
// v -> fp -> invite. This exact form is the client parsing contract.
func (c Card) String() string {
	// Build the query in a fixed, human-friendly order (v, fp, invite) rather
	// than relying on url.Values.Encode's alphabetical sort, so logs and docs
	// match the canonical examples.
	query := make([]string, 0, 3)
	query = append(query, "v="+protocolVersion)
	if c.Scheme == SchemeTLS {
		query = append(query, "fp="+url.QueryEscape(c.Fingerprint))
	}
	if c.Invite != "" {
		query = append(query, "invite="+url.QueryEscape(c.Invite))
	}
	return (&url.URL{
		Scheme:   c.Scheme,
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		RawQuery: strings.Join(query, "&"),
	}).String()
}

// TLS reports whether this card pins a fingerprint and must use TLS.
func (c Card) TLS() bool {
	return c.Scheme == SchemeTLS
}

// validateFingerprint rejects non-canonical SPKI SHA-256 fingerprint strings.
func validateFingerprint(fp string) error {
	if len(fp) != 64 {
		return errors.New("servercard: fp must be 64 hex characters")
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return errors.New("servercard: fp must be 64 hex characters")
	}
	return nil
}
