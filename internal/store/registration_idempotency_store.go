package store

import (
	"context"
	"encoding/json"

	"zephyr.vox/server/ce/internal/db"
)

// RegistrationIdempotencyRecord is a completed public registration result.
// It has no principal or activation-code identity because registration is its
// own installation-scoped durable command contract.
type RegistrationIdempotencyRecord struct {
	InstallationID string
	IdempotencyKey string
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

// RegistrationIdempotencyStore persists completed registration responses in
// the same transaction as user creation and invite consumption.
type RegistrationIdempotencyStore struct {
	q             *db.Queries
	now           func() int64
	transactional bool
	admitted      bool
	saved         bool
}

// Lookup returns an unexpired registration result by installation and retry
// key. The realtime layer compares the request HMAC for key-reuse detection.
func (s *RegistrationIdempotencyStore) Lookup(ctx context.Context, installationID, idempotencyKey string) (*RegistrationIdempotencyRecord, error) {
	if !validActivationIdentity(installationID) || !idempotencyKeyRE.MatchString(idempotencyKey) {
		return nil, ErrInvalidIdempotencyRecord
	}
	row, err := s.q.GetRegistrationIdempotency(ctx, db.GetRegistrationIdempotencyParams{
		InstallationID: installationID,
		IdempotencyKey: idempotencyKey,
		ExpiresAt:      s.now(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return registrationIdempotencyRecordFromDB(row)
}

// Admit reserves one shared durable retry slot before registration mutates the
// database. Live results are never evicted.
func (s *RegistrationIdempotencyStore) Admit(ctx context.Context) error {
	if err := admitDurableIdempotency(ctx, s.q, s.now, s.transactional, s.admitted, s.saved); err != nil {
		return err
	}
	s.admitted = true
	return nil
}

// Save stores one completed registration result after Admit in the same
// transaction as the account mutation.
func (s *RegistrationIdempotencyStore) Save(ctx context.Context, record RegistrationIdempotencyRecord) error {
	if !s.transactional || !s.admitted || s.saved {
		return ErrCommandIdempotencyAdmission
	}
	if record.CreatedAt == 0 {
		record.CreatedAt = s.now()
	}
	if record.ExpiresAt == 0 {
		record.ExpiresAt = record.CreatedAt + CommandIdempotencyTTL.Milliseconds()
	}
	if !validRegistrationRecord(record) {
		return ErrInvalidIdempotencyRecord
	}
	if err := s.q.InsertRegistrationIdempotency(ctx, db.InsertRegistrationIdempotencyParams{
		InstallationID: record.InstallationID,
		IdempotencyKey: record.IdempotencyKey,
		RequestHmac:    record.RequestHMAC,
		CommandID:      record.CommandID,
		Status:         record.Status,
		ResultBody:     string(record.ResultBody),
		Etag:           nullString(optionalNonEmpty(record.Headers.ETag)),
		ParentEtag:     nullString(optionalNonEmpty(record.Headers.ParentETag)),
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
	s.saved = true
	return nil
}

// registrationIdempotencyRecordFromDB converts one generated row and rejects
// malformed persisted replay data before it reaches the HTTP adapter.
func registrationIdempotencyRecordFromDB(row db.RegistrationIdempotency) (*RegistrationIdempotencyRecord, error) {
	if row.Geid < 0 {
		return nil, ErrInvalidIdempotencyRecord
	}
	record := &RegistrationIdempotencyRecord{
		InstallationID: row.InstallationID,
		IdempotencyKey: row.IdempotencyKey,
		RequestHMAC:    row.RequestHmac,
		CommandID:      row.CommandID,
		Status:         row.Status,
		ResultBody:     append(json.RawMessage(nil), row.ResultBody...),
		Headers: IdempotencyHeaders{
			ETag:         optionalStringValue(row.Etag),
			ParentETag:   optionalStringValue(row.ParentEtag),
			Location:     optionalStringValue(row.Location),
			CacheControl: optionalStringValue(row.CacheControl),
			Pragma:       optionalStringValue(row.Pragma),
		},
		StreamEpoch: row.StreamEpoch,
		GEID:        uint64(row.Geid),
		StateCursor: row.StateCursor,
		CreatedAt:   row.CreatedAt,
		ExpiresAt:   row.ExpiresAt,
	}
	if !validRegistrationRecord(*record) {
		return nil, ErrInvalidIdempotencyRecord
	}
	return record, nil
}

// validRegistrationRecord rejects malformed installation identities and
// replay data before it reaches SQLite or an HTTP response.
func validRegistrationRecord(record RegistrationIdempotencyRecord) bool {
	if !validActivationIdentity(record.InstallationID) || !idempotencyKeyRE.MatchString(record.IdempotencyKey) || !validHex(record.RequestHMAC, 32) || record.CommandID <= 0 || record.Status < 100 || record.Status > 599 || !streamEpochRE.MatchString(record.StreamEpoch) || record.StateCursor == "" || record.CreatedAt < 0 || record.ExpiresAt != record.CreatedAt+CommandIdempotencyTTL.Milliseconds() || !json.Valid(record.ResultBody) || record.GEID > uint64(^uint64(0)>>1) {
		return false
	}
	return !hasInvalidHeaderValue(record.Headers.ETag) && !hasInvalidHeaderValue(record.Headers.ParentETag) && !hasInvalidHeaderValue(record.Headers.Location) && !hasInvalidHeaderValue(record.Headers.CacheControl) && !hasInvalidHeaderValue(record.Headers.Pragma)
}
