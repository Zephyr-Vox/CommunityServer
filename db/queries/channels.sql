-- name: CreateChannelGroup :one
INSERT INTO channel_groups
    (id, name, position, visibility, created_at, updated_at, version)
VALUES (?, ?, ?, ?, ?, ?, 1)
RETURNING *;

-- name: GetChannelGroup :one
SELECT * FROM channel_groups WHERE id = ?;

-- name: CreateChannel :one
INSERT INTO channels
    (id, group_id, name, mode, temporary, visibility, capacity, position,
     pinned, created_by, created_at, updated_at, version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
RETURNING *;

-- name: GetChannel :one
SELECT * FROM channels WHERE id = ?;

-- name: ListChannels :many
SELECT * FROM channels
ORDER BY position, created_at, id;

-- name: DeleteChannel :one
DELETE FROM channels WHERE id = ? RETURNING id;
