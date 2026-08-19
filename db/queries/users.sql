-- name: GetUserByID :one
SELECT * FROM users WHERE id = ?;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = ?;

-- name: CreateUser :one
INSERT INTO users (id, username, password_hash, nickname, avatar, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateUserNickname :one
UPDATE users
SET nickname = ?, updated_at = ?
WHERE id = ?
RETURNING *;

-- name: SetUserAvatar :one
UPDATE users
SET avatar = ?, updated_at = ?
WHERE id = ?
RETURNING *;

-- name: SetUserPasswordHash :execrows
UPDATE users
SET password_hash = ?, auth_version = auth_version + 1, updated_at = ?
WHERE id = ?;

-- name: TouchUserLastLogin :exec
UPDATE users
SET last_login_at = ?, updated_at = ?
WHERE id = ?;

-- name: SetUserBanned :exec
UPDATE users
SET banned_at = ?, updated_at = ?
WHERE id = ?;

-- name: BumpUserAuthVersion :exec
UPDATE users
SET auth_version = auth_version + 1, updated_at = ?
WHERE id = ?;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: DeleteUser :one
DELETE FROM users WHERE id = ? RETURNING id;
