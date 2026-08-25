-- name: CreateChannelGroup :one
INSERT INTO channel_groups
    (id, name, position, visibility, created_at, updated_at, version)
VALUES (?, ?, ?, ?, ?, ?, 1)
RETURNING *;

-- name: GetChannelGroup :one
SELECT * FROM channel_groups WHERE id = ?;

-- name: ListChannelGroups :many
SELECT * FROM channel_groups
ORDER BY position, id;

-- name: CountChannelGroups :one
SELECT COUNT(*) FROM channel_groups;

-- name: UpdateChannelGroup :one
UPDATE channel_groups
SET name = ?,
    position = ?,
    visibility = ?,
    updated_at = ?,
    version = version + 1
WHERE id = ?
RETURNING *;

-- name: TouchChannelGroup :one
UPDATE channel_groups
SET updated_at = ?,
    version = version + 1
WHERE id = ?
RETURNING *;

-- name: DeleteChannelGroup :one
DELETE FROM channel_groups WHERE id = ? RETURNING id;

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
ORDER BY position, id;

-- name: CountChannels :one
SELECT COUNT(*) FROM channels;

-- name: CountTemporaryChannels :one
SELECT COUNT(*) FROM channels WHERE temporary = 1;

-- name: CountTemporaryChannelsForCreator :one
SELECT COUNT(*) FROM channels WHERE temporary = 1 AND created_by = ?;

-- name: UpdateChannel :one
UPDATE channels
SET group_id = ?,
    name = ?,
    visibility = ?,
    capacity = ?,
    position = ?,
    pinned = ?,
    updated_at = ?,
    version = version + 1
WHERE id = ?
RETURNING *;

-- name: TouchChannel :one
UPDATE channels
SET updated_at = ?,
    version = version + 1
WHERE id = ?
RETURNING *;

-- name: DeleteChannel :one
DELETE FROM channels WHERE id = ? RETURNING id;
