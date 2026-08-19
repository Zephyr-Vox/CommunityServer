package realtime

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

var (
	// ErrInvalidCursor is returned when a cursor is malformed or its signature
	// does not authenticate its payload.
	ErrInvalidCursor = errors.New("realtime: invalid cursor")
	// ErrCursorPrincipal is returned when an otherwise valid cursor belongs to
	// another authenticated user.
	ErrCursorPrincipal = errors.New("realtime: cursor principal mismatch")
	// ErrCursorEpoch is returned when an otherwise valid cursor belongs to a
	// different process stream epoch.
	ErrCursorEpoch = errors.New("realtime: cursor stream epoch mismatch")
	// ErrCursorSchema is returned when a cursor uses an unsupported snapshot
	// schema version.
	ErrCursorSchema = errors.New("realtime: cursor schema mismatch")
)

const (
	// SnapshotSchemaVersion is bound into every cursor so incompatible snapshot
	// DTO changes force a full resynchronization.
	SnapshotSchemaVersion uint16 = 1
	cursorKeyBytes               = 32
)

// Cursor contains the authenticated state checkpoint and visibility epoch
// recovered from an opaque cursor.
type Cursor struct {
	Checkpoint      Checkpoint
	VisibilityEpoch uint64
	SchemaVersion   uint16
}

type cursorPayload struct {
	UserID          string `json:"u"`
	StreamEpoch     string `json:"e"`
	GEID            string `json:"g"`
	VisibilityEpoch string `json:"v"`
	SchemaVersion   uint16 `json:"s"`
}

// CursorSigner issues and validates process-local opaque cursors. Its random
// signing key is intentionally not persisted: any process restart invalidates
// old cursors and requires a full snapshot under the new stream epoch.
type CursorSigner struct {
	streamEpoch string
	key         []byte
}

// NewCursorSigner creates a signer with a new random 256-bit process key.
func NewCursorSigner(streamEpoch string) (*CursorSigner, error) {
	key := make([]byte, cursorKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("realtime: generate cursor key: %w", err)
	}
	return NewCursorSignerWithKey(streamEpoch, key)
}

// NewCursorSignerWithKey creates a signer with key. It is intended for
// deterministic tests and startup assembly that receives key material from a
// secure process-local source.
func NewCursorSignerWithKey(streamEpoch string, key []byte) (*CursorSigner, error) {
	if err := validateStreamEpoch(streamEpoch); err != nil {
		return nil, err
	}
	if len(key) != cursorKeyBytes {
		return nil, errors.New("realtime: cursor key must be 32 bytes")
	}
	return &CursorSigner{streamEpoch: streamEpoch, key: append([]byte(nil), key...)}, nil
}

// Issue creates a cursor bound to userID, checkpoint and visibilityEpoch.
func (s *CursorSigner) Issue(userID int64, checkpoint Checkpoint, visibilityEpoch uint64) (string, error) {
	if userID <= 0 || checkpoint.StreamEpoch != s.streamEpoch {
		return "", ErrInvalidCursor
	}
	payload, err := json.Marshal(cursorPayload{
		UserID:          strconv.FormatInt(userID, 10),
		StreamEpoch:     checkpoint.StreamEpoch,
		GEID:            strconv.FormatUint(checkpoint.GEID, 10),
		VisibilityEpoch: strconv.FormatUint(visibilityEpoch, 10),
		SchemaVersion:   SnapshotSchemaVersion,
	})
	if err != nil {
		return "", fmt.Errorf("realtime: encode cursor: %w", err)
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(payload)
	signature := mac.Sum(nil)
	token := append(payload, signature...)
	return base64.RawURLEncoding.EncodeToString(token), nil
}

// Parse validates token for userID and returns its authenticated cursor fields.
func (s *CursorSigner) Parse(userID int64, token string) (Cursor, error) {
	payload, signature, err := splitCursor(token)
	if err != nil {
		return Cursor{}, err
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return Cursor{}, ErrInvalidCursor
	}
	var decoded cursorPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return Cursor{}, ErrInvalidCursor
	}
	parsedUserID, err := strconv.ParseInt(decoded.UserID, 10, 64)
	if err != nil || parsedUserID <= 0 {
		return Cursor{}, ErrInvalidCursor
	}
	if parsedUserID != userID {
		return Cursor{}, ErrCursorPrincipal
	}
	if decoded.StreamEpoch != s.streamEpoch {
		return Cursor{}, ErrCursorEpoch
	}
	if decoded.SchemaVersion != SnapshotSchemaVersion {
		return Cursor{}, ErrCursorSchema
	}
	geid, err := strconv.ParseUint(decoded.GEID, 10, 64)
	if err != nil {
		return Cursor{}, ErrInvalidCursor
	}
	visibilityEpoch, err := strconv.ParseUint(decoded.VisibilityEpoch, 10, 64)
	if err != nil {
		return Cursor{}, ErrInvalidCursor
	}
	return Cursor{
		Checkpoint:      Checkpoint{StreamEpoch: decoded.StreamEpoch, GEID: geid},
		VisibilityEpoch: visibilityEpoch,
		SchemaVersion:   decoded.SchemaVersion,
	}, nil
}

// splitCursor decodes one opaque base64url token into its payload and HMAC.
func splitCursor(token string) ([]byte, []byte, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, nil, ErrInvalidCursor
	}
	if len(encoded) <= sha256.Size {
		return nil, nil, ErrInvalidCursor
	}
	payload := encoded[:len(encoded)-sha256.Size]
	signature := encoded[len(encoded)-sha256.Size:]
	return payload, signature, nil
}
