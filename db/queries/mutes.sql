-- name: InsertMute :one
INSERT INTO moderation_mutes
    (id, scope_type, group_id, channel_id, user_id, kind, expires_at,
     created_by, reason, created_at, version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
RETURNING *;

-- name: GetMute :one
SELECT * FROM moderation_mutes WHERE id = ?;

-- name: DeleteMute :one
DELETE FROM moderation_mutes WHERE id = ? RETURNING id;

-- name: DeleteMutesForUser :exec
DELETE FROM moderation_mutes WHERE user_id = ?;

-- name: ListMutesForUser :many
SELECT * FROM moderation_mutes WHERE user_id = ? ORDER BY id;
