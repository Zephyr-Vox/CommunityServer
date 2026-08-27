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

-- name: UpdateMute :one
UPDATE moderation_mutes
SET expires_at = ?,
    reason = ?,
    version = version + 1
WHERE id = ?
RETURNING *;

-- name: CountActiveMutes :one
SELECT COUNT(*) FROM moderation_mutes
WHERE expires_at IS NULL OR expires_at > ?;

-- name: DeleteMutesForUser :exec
DELETE FROM moderation_mutes WHERE user_id = ?;

-- name: ListMutesForUser :many
SELECT * FROM moderation_mutes WHERE user_id = ? ORDER BY id;

-- name: ListAllMutes :many
SELECT * FROM moderation_mutes ORDER BY id;
