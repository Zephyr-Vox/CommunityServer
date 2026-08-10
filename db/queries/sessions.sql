-- name: UpsertSession :one
INSERT INTO sessions (id, user_id, device_id, token_hash, prev_token_hash, expires_at, last_used_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (user_id, device_id) DO UPDATE SET
    token_hash = excluded.token_hash,
    prev_token_hash = sessions.token_hash,
    expires_at = excluded.expires_at,
    last_used_at = excluded.last_used_at
RETURNING *;

-- name: GetSessionByTokenHash :one
SELECT * FROM sessions WHERE token_hash = ?;

-- name: GetSessionByID :one
SELECT * FROM sessions WHERE id = ?;

-- name: RotateSession :one
UPDATE sessions
SET token_hash = ?, prev_token_hash = token_hash, last_used_at = ?, expires_at = ?
WHERE id = ?
RETURNING *;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = ?;

-- name: DeleteSessionByTokenHash :exec
DELETE FROM sessions WHERE token_hash = ?;

-- name: ListSessionsByUser :many
SELECT * FROM sessions
WHERE user_id = ?
ORDER BY last_used_at DESC;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < ?;
