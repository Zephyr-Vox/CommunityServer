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

-- name: CountCommandIdempotency :one
SELECT COUNT(*) FROM command_idempotency;

-- name: DeleteOldestCommandIdempotency :execrows
DELETE FROM command_idempotency
WHERE (principal_id, idempotency_key) IN (
    SELECT principal_id, idempotency_key
    FROM command_idempotency
    ORDER BY created_at ASC, principal_id ASC, idempotency_key ASC
    LIMIT ?
);
