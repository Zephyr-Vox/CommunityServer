-- name: GetCommandIdempotency :one
SELECT * FROM command_idempotency
WHERE principal_id = ? AND idempotency_key = ? AND expires_at > ?;

-- name: InsertCommandIdempotency :exec
INSERT INTO command_idempotency (
    principal_id, idempotency_key, endpoint, request_hmac, command_id, status,
    result_body, etag, location, cache_control, pragma, stream_epoch, geid,
    state_cursor, created_at, expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteExpiredCommandIdempotency :execrows
DELETE FROM command_idempotency WHERE expires_at <= ?;

-- name: CountDurableIdempotency :one
SELECT
    (SELECT COUNT(*) FROM command_idempotency) +
    (SELECT COUNT(*) FROM activation_idempotency);

-- name: DeleteExpiredActivationIdempotency :execrows
DELETE FROM activation_idempotency WHERE expires_at <= ?;

-- name: GetActivationIdempotency :one
SELECT installation_id, idempotency_key, activation_code_hash, request_hmac,
       command_id, status, result_body, etag, location, cache_control, "pragma",
       created_at, expires_at
FROM activation_idempotency
WHERE installation_id = ? AND idempotency_key = ? AND expires_at > ?;

-- name: InsertActivationIdempotency :exec
INSERT INTO activation_idempotency (
    installation_id, idempotency_key, activation_code_hash, request_hmac,
    command_id, status, result_body, etag, location, cache_control, pragma,
    created_at, expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
