package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"zephyr.vox/server/ce/internal/db"
)

const (
	// CommandIdempotencyTTL is the durable retry window for completed HTTP
	// commands. Runtime-only secrets stay in the shorter realtime cache instead.
	CommandIdempotencyTTL = 24 * time.Hour
	// MaxCommandIdempotencyRecords bounds durable records across the one server.
	MaxCommandIdempotencyRecords = 100_000
)

var (
	// ErrInvalidIdempotencyRecord is returned when a caller tries to persist a
	// result that cannot be safely replayed as a canonical HTTP command result.
	ErrInvalidIdempotencyRecord = errors.New("store: invalid idempotency record")
	idempotencyKeyRE            = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
)

// IdempotencyHeaders contains the only resource response headers retained for
// durable HTTP replay. State checkpoint headers are stored separately because
// they must be suppressed after a process epoch change.
type IdempotencyHeaders struct {
	ETag         string
	Location     string
	CacheControl string
	Pragma       string
}

// CommandIdempotencyRecord is a completed durable command result. RequestHMAC
// is the stable HMAC of the canonical authenticated request identity; its key
// is owned by the realtime/application layer and never stored in this record.
type CommandIdempotencyRecord struct {
	PrincipalID    int64
	IdempotencyKey string
	Endpoint       string
	RequestHMAC    string
	CommandID      int64
	Status         int64
	ResultBody     json.RawMessage
	Headers        IdempotencyHeaders
	StreamEpoch    string
	GEID           uint64
	StateCursor    string
	CreatedAt      int64
	ExpiresAt      int64
}

// IdempotencyStore provides durable completed-command lookup and persistence.
// Save requires a transaction-bound store so callers write the result inside
// the same transaction as the domain mutation it makes replay-safe.
type IdempotencyStore struct {
	q             *db.Queries
	now           func() int64
	transactional bool
}

// Lookup returns a non-expired completed record for one principal and key, or
// ErrNotFound. It does not delete expired rows because read paths need not take
// the SQLite writer lock; Save and Prune perform bounded cleanup instead.
func (s *IdempotencyStore) Lookup(ctx context.Context, principalID int64, idempotencyKey string) (*CommandIdempotencyRecord, error) {
	if principalID <= 0 || !idempotencyKeyRE.MatchString(idempotencyKey) {
		return nil, ErrInvalidIdempotencyRecord
	}
	row, err := s.q.GetCommandIdempotency(ctx, db.GetCommandIdempotencyParams{
		PrincipalID:    principalID,
		IdempotencyKey: idempotencyKey,
		ExpiresAt:      s.now(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return commandIdempotencyRecordFromDB(row)
}

// Save prunes expired records, evicts enough oldest records to retain the hard
// global cap, then stores record. The caller must use Stores.WithTx so this
// insert rolls back with an unsuccessful domain mutation.
func (s *IdempotencyStore) Save(ctx context.Context, record CommandIdempotencyRecord) error {
	if !s.transactional {
		return ErrInvalidIdempotencyRecord
	}
	now := s.now()
	if _, err := s.q.DeleteExpiredCommandIdempotency(ctx, now); err != nil {
		return mapError(err)
	}
	count, err := s.q.CountCommandIdempotency(ctx)
	if err != nil {
		return mapError(err)
	}
	if count >= MaxCommandIdempotencyRecords {
		if _, err := s.q.DeleteOldestCommandIdempotency(ctx, count-MaxCommandIdempotencyRecords+1); err != nil {
			return mapError(err)
		}
	}
	if record.CreatedAt == 0 {
		record.CreatedAt = now
	}
	if record.ExpiresAt == 0 {
		record.ExpiresAt = record.CreatedAt + CommandIdempotencyTTL.Milliseconds()
	}
	if !validCommandIdempotencyRecord(record) {
		return ErrInvalidIdempotencyRecord
	}
	if err := s.q.InsertCommandIdempotency(ctx, db.InsertCommandIdempotencyParams{
		PrincipalID:    record.PrincipalID,
		IdempotencyKey: record.IdempotencyKey,
		Endpoint:       record.Endpoint,
		RequestHmac:    record.RequestHMAC,
		CommandID:      record.CommandID,
		Status:         record.Status,
		ResultBody:     string(record.ResultBody),
		Etag:           nullString(optionalNonEmpty(record.Headers.ETag)),
		Location:       nullString(optionalNonEmpty(record.Headers.Location)),
		CacheControl:   nullString(optionalNonEmpty(record.Headers.CacheControl)),
		Pragma:         nullString(optionalNonEmpty(record.Headers.Pragma)),
		StreamEpoch:    record.StreamEpoch,
		Geid:           int64(record.GEID),
		StateCursor:    record.StateCursor,
		CreatedAt:      record.CreatedAt,
		ExpiresAt:      record.ExpiresAt,
	}); err != nil {
		return mapError(err)
	}
	return nil
}

// Prune removes all records whose durable retry window has expired and returns
// the number removed. It may be called by bounded maintenance work.
func (s *IdempotencyStore) Prune(ctx context.Context) (int64, error) {
	n, err := s.q.DeleteExpiredCommandIdempotency(ctx, s.now())
	if err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// commandIdempotencyRecordFromDB converts generated nullable resource headers
// and preserves the canonical JSON result as an independent byte slice.
func commandIdempotencyRecordFromDB(row db.CommandIdempotency) (*CommandIdempotencyRecord, error) {
	if row.Geid < 0 {
		return nil, ErrInvalidIdempotencyRecord
	}
	return &CommandIdempotencyRecord{
		PrincipalID:    row.PrincipalID,
		IdempotencyKey: row.IdempotencyKey,
		Endpoint:       row.Endpoint,
		RequestHMAC:    row.RequestHmac,
		CommandID:      row.CommandID,
		Status:         row.Status,
		ResultBody:     append(json.RawMessage(nil), row.ResultBody...),
		Headers: IdempotencyHeaders{
			ETag:         optionalStringValue(row.Etag),
			Location:     optionalStringValue(row.Location),
			CacheControl: optionalStringValue(row.CacheControl),
			Pragma:       optionalStringValue(row.Pragma),
		},
		StreamEpoch: row.StreamEpoch,
		GEID:        uint64(row.Geid),
		StateCursor: row.StateCursor,
		CreatedAt:   row.CreatedAt,
		ExpiresAt:   row.ExpiresAt,
	}, nil
}

// validCommandIdempotencyRecord rejects malformed stable identities and replay
// data before SQLite sees it. Full stream-epoch validation belongs to realtime,
// but the store still enforces the fixed persisted representation length.
func validCommandIdempotencyRecord(record CommandIdempotencyRecord) bool {
	if record.PrincipalID <= 0 || !idempotencyKeyRE.MatchString(record.IdempotencyKey) || len(record.Endpoint) == 0 || len(record.Endpoint) > 256 || hasHeaderLineBreak(record.Endpoint) || record.CommandID <= 0 || record.Status < 100 || record.Status > 599 || !streamEpochRE.MatchString(record.StreamEpoch) || record.StateCursor == "" || record.CreatedAt < 0 || record.ExpiresAt != record.CreatedAt+CommandIdempotencyTTL.Milliseconds() {
		return false
	}
	if len(record.RequestHMAC) != 64 {
		return false
	}
	if _, err := hex.DecodeString(record.RequestHMAC); err != nil {
		return false
	}
	if !json.Valid(record.ResultBody) || hasInvalidHeaderValue(record.Headers.ETag) || hasInvalidHeaderValue(record.Headers.Location) || hasInvalidHeaderValue(record.Headers.CacheControl) || hasInvalidHeaderValue(record.Headers.Pragma) {
		return false
	}
	return record.GEID <= uint64(^uint64(0)>>1)
}

// streamEpochRE matches the persisted lower-case 128-bit process epoch form.
var streamEpochRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// optionalNonEmpty maps an optional header value to the store's SQL helper.
func optionalNonEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// optionalStringValue maps a generated nullable text column to an empty absent
// header value; empty headers are never persisted as present values.
func optionalStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

// hasInvalidHeaderValue rejects CR/LF injection into replayed HTTP headers.
func hasInvalidHeaderValue(value string) bool {
	return hasHeaderLineBreak(value)
}

// hasHeaderLineBreak detects text unsafe for replayed HTTP resource headers.
func hasHeaderLineBreak(value string) bool {
	return strings.ContainsAny(value, "\r\n")
}
