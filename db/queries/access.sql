-- name: InsertGroupAccess :one
INSERT INTO group_access
    (id, group_id, principal_type, user_id, role_key, created_at)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: ListGroupAccess :many
SELECT * FROM group_access WHERE group_id = ? ORDER BY id;

-- name: InsertChannelAccess :one
INSERT INTO channel_access
    (id, channel_id, principal_type, user_id, role_key, created_at)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: ListChannelAccess :many
SELECT * FROM channel_access WHERE channel_id = ? ORDER BY id;
