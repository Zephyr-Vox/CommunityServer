-- name: GetRoleByKey :one
SELECT * FROM roles WHERE key = ?;

-- name: ListRoles :many
SELECT * FROM roles ORDER BY rank DESC, display_name, key;

-- name: CreateRole :one
INSERT INTO roles
    (key, display_name, rank, builtin, immutable, created_at, updated_at, version)
VALUES (?, ?, ?, 0, 0, ?, ?, 1)
RETURNING *;

-- name: UpdateRole :one
UPDATE roles
SET display_name = ?,
    rank = ?,
    updated_at = ?,
    version = version + 1
WHERE key = ?
RETURNING *;

-- name: DeleteRole :one
DELETE FROM roles WHERE key = ? RETURNING key;

-- name: CountRoleReferences :one
WITH target(key) AS (SELECT CAST(sqlc.arg(role_key) AS TEXT))
SELECT
    (SELECT COUNT(*) FROM user_role_bindings WHERE role_key = (SELECT key FROM target)) +
    (SELECT COUNT(*) FROM group_access WHERE role_key = (SELECT key FROM target)) +
    (SELECT COUNT(*) FROM channel_access WHERE role_key = (SELECT key FROM target)) +
    (SELECT COUNT(*) FROM invites WHERE role_key = (SELECT key FROM target)) +
    (SELECT COUNT(*) FROM scope_permission_configs, json_each(config)
     WHERE json_each.key = (SELECT key FROM target)) AS count;

-- name: SeedRole :exec
INSERT OR IGNORE INTO roles
    (key, display_name, rank, builtin, immutable, created_at, updated_at, version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetServerPermissionConfig :one
SELECT config FROM scope_permission_configs
WHERE scope_type = 'server';

-- name: SeedServerPermissionConfig :exec
INSERT OR IGNORE INTO scope_permission_configs
    (scope_type, config, updated_at, version)
VALUES ('server', ?, ?, 1);

-- name: ListRoleBindingsForUser :many
SELECT * FROM user_role_bindings
WHERE user_id = ?
ORDER BY scope_type, group_id, channel_id, role_key;

-- name: ListRoleBindings :many
SELECT * FROM user_role_bindings ORDER BY id LIMIT ? OFFSET ?;

-- name: ListAllRoleBindings :many
SELECT * FROM user_role_bindings ORDER BY id;

-- name: ListUsersWithRoleBindings :many
SELECT DISTINCT user_id FROM user_role_bindings ORDER BY user_id;

-- name: GetRoleBindingByID :one
SELECT * FROM user_role_bindings WHERE id = ?;

-- name: GetOwnerBinding :one
SELECT * FROM user_role_bindings WHERE role_key = 'owner';

-- name: InsertRoleBinding :one
INSERT INTO user_role_bindings
    (id, user_id, role_key, scope_type, group_id, channel_id, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: DeleteRoleBinding :one
DELETE FROM user_role_bindings WHERE id = ? RETURNING id;

-- name: DeleteServerRoleBindingsForUser :exec
DELETE FROM user_role_bindings WHERE user_id = ? AND scope_type = 'server';

-- name: CountOwners :one
SELECT COUNT(*) AS count FROM user_role_bindings WHERE role_key = 'owner';

-- name: GetInstallationState :one
SELECT * FROM installation_state WHERE id = 1;

-- name: SeedInstallationState :execrows
INSERT OR IGNORE INTO installation_state (id, installation_id, initialized) VALUES (1, ?, 0);

-- name: SetInstallationInitialized :execrows
UPDATE installation_state
SET initialized = ?
WHERE id = 1 AND initialized = ?;
