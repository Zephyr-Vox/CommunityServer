-- name: GetServerPermissionConfigRow :one
SELECT * FROM scope_permission_configs
WHERE scope_type = 'server';

-- name: UpdateServerPermissionConfig :one
UPDATE scope_permission_configs
SET config = ?,
    updated_at = ?,
    version = version + 1
WHERE scope_type = 'server'
RETURNING *;

-- name: GetGroupPermissionConfig :one
SELECT * FROM scope_permission_configs
WHERE scope_type = 'group' AND group_id = ?;

-- name: GetChannelPermissionConfig :one
SELECT * FROM scope_permission_configs
WHERE scope_type = 'channel' AND channel_id = ?;

-- name: UpsertGroupPermissionConfig :one
INSERT INTO scope_permission_configs
    (scope_type, group_id, config, updated_at, version)
VALUES ('group', ?, ?, ?, ?)
ON CONFLICT (group_id) WHERE scope_type = 'group' DO UPDATE SET
    config = excluded.config,
    updated_at = excluded.updated_at,
    version = excluded.version
RETURNING *;

-- name: UpsertChannelPermissionConfig :one
INSERT INTO scope_permission_configs
    (scope_type, channel_id, config, updated_at, version)
VALUES ('channel', ?, ?, ?, ?)
ON CONFLICT (channel_id) WHERE scope_type = 'channel' DO UPDATE SET
    config = excluded.config,
    updated_at = excluded.updated_at,
    version = excluded.version
RETURNING *;

-- name: DeleteGroupPermissionConfig :one
DELETE FROM scope_permission_configs
WHERE scope_type = 'group' AND group_id = ?
RETURNING group_id;

-- name: DeleteChannelPermissionConfig :one
DELETE FROM scope_permission_configs
WHERE scope_type = 'channel' AND channel_id = ?
RETURNING channel_id;
