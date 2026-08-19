package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	"zephyr.vox/server/ce/internal/db"
)

var activationIdentityRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ActivationIdempotencyRecord is a completed first-owner activation result.
// It deliberately has no principal foreign key because the command creates
// the first principal; its installation and activation-code identity remains
// stable after the process forgets the plaintext code.
type ActivationIdempotencyRecord struct {
	InstallationID     string
	IdempotencyKey     string
	ActivationCodeHash string
	RequestHMAC        string
	CommandID          int64
	Status             int64
	ResultBody         json.RawMessage
	Headers            IdempotencyHeaders
	CreatedAt          int64
	ExpiresAt          int64
}

// ActivationIdempotencyStore persists completed first-owner activation
// responses in a transaction that also creates the user and owner binding.
type ActivationIdempotencyStore struct {
	q             *db.Queries
	now           func() int64
	transactional bool
	admitted      bool
	saved         bool
}

// Lookup returns an unexpired activation result by installation and retry key.
// The caller compares the stored code hash and request HMAC to distinguish a
// matching replay from reuse of the key with a different activation request.
func (s *ActivationIdempotencyStore) Lookup(ctx context.Context, installationID, idempotencyKey string) (*ActivationIdempotencyRecord, error) {
	if !validActivationIdentity(installationID) || !idempotencyKeyRE.MatchString(idempotencyKey) {
		return nil, ErrInvalidIdempotencyRecord
	}
	row, err := s.q.GetActivationIdempotency(ctx, db.GetActivationIdempotencyParams{
		InstallationID: installationID,
		IdempotencyKey: idempotencyKey,
		ExpiresAt:      s.now(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return activationIdempotencyRecordFromDB(row)
}

// Admit reserves one shared durable retry slot before activation mutates the
// database. It never evicts a live principal or activation result.
func (s *ActivationIdempotencyStore) Admit(ctx context.Context) error {
	if err := admitDurableIdempotency(ctx, s.q, s.now, s.transactional, s.admitted, s.saved); err != nil {
		return err
	}
	s.admitted = true
	return nil
}

// Save stores one completed activation result after Admit in the same
// transaction as the first-owner database mutation.
func (s *ActivationIdempotencyStore) Save(ctx context.Context, record ActivationIdempotencyRecord) error {
	if !s.transactional || !s.admitted || s.saved {
		return ErrCommandIdempotencyAdmission
	}
	if record.CreatedAt == 0 {
		record.CreatedAt = s.now()
	}
	if record.ExpiresAt == 0 {
		record.ExpiresAt = record.CreatedAt + CommandIdempotencyTTL.Milliseconds()
	}
	if !validActivationRecord(record) {
		return ErrInvalidIdempotencyRecord
	}
	if err := s.q.InsertActivationIdempotency(ctx, db.InsertActivationIdempotencyParams{
		InstallationID:     record.InstallationID,
		IdempotencyKey:     record.IdempotencyKey,
		ActivationCodeHash: record.ActivationCodeHash,
		RequestHmac:        record.RequestHMAC,
		CommandID:          record.CommandID,
		Status:             record.Status,
		ResultBody:         string(record.ResultBody),
		Etag:               nullString(optionalNonEmpty(record.Headers.ETag)),
		Location:           nullString(optionalNonEmpty(record.Headers.Location)),
		CacheControl:       nullString(optionalNonEmpty(record.Headers.CacheControl)),
		Pragma:             nullString(optionalNonEmpty(record.Headers.Pragma)),
		CreatedAt:          record.CreatedAt,
		ExpiresAt:          record.ExpiresAt,
	}); err != nil {
		return mapError(err)
	}
	s.saved = true
	return nil
}

// activationIdempotencyRecordFromDB converts generated nullable header fields
// into the store record while copying the JSON response bytes.
func activationIdempotencyRecordFromDB(row db.ActivationIdempotency) (*ActivationIdempotencyRecord, error) {
	record := &ActivationIdempotencyRecord{
		InstallationID:     row.InstallationID,
		IdempotencyKey:     row.IdempotencyKey,
		ActivationCodeHash: row.ActivationCodeHash,
		RequestHMAC:        row.RequestHmac,
		CommandID:          row.CommandID,
		Status:             row.Status,
		ResultBody:         append(json.RawMessage(nil), row.ResultBody...),
		Headers: IdempotencyHeaders{
			ETag:         optionalStringValue(row.Etag),
			Location:     optionalStringValue(row.Location),
			CacheControl: optionalStringValue(row.CacheControl),
			Pragma:       optionalStringValue(row.Pragma),
		},
		CreatedAt: row.CreatedAt,
		ExpiresAt: row.ExpiresAt,
	}
	if !validActivationRecord(*record) {
		return nil, ErrInvalidIdempotencyRecord
	}
	return record, nil
}

// validActivationIdentity validates the persisted installation identity form.
func validActivationIdentity(value string) bool {
	return activationIdentityRE.MatchString(value)
}

// validActivationRecord rejects malformed activation identities and unsafe
// replay data before it reaches SQLite or an HTTP response.
func validActivationRecord(record ActivationIdempotencyRecord) bool {
	if !validActivationIdentity(record.InstallationID) || !idempotencyKeyRE.MatchString(record.IdempotencyKey) || !validHex(record.ActivationCodeHash, 32) || !validHex(record.RequestHMAC, 32) || record.CommandID <= 0 || record.Status < 100 || record.Status > 599 || record.CreatedAt < 0 || record.ExpiresAt != record.CreatedAt+CommandIdempotencyTTL.Milliseconds() || !json.Valid(record.ResultBody) {
		return false
	}
	return !hasInvalidHeaderValue(record.Headers.ETag) && !hasInvalidHeaderValue(record.Headers.Location) && !hasInvalidHeaderValue(record.Headers.CacheControl) && !hasInvalidHeaderValue(record.Headers.Pragma)
}

// validHex validates one fixed-size lowercase hexadecimal digest.
func validHex(value string, bytes int) bool {
	if len(value) != bytes*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
