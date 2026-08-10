-- name: CreateInvite :one
INSERT INTO invites (id, code_hash, role, uses_left, expires_at, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetInviteByCodeHash :one
SELECT * FROM invites WHERE code_hash = ?;

-- name: ConsumeInvite :one
UPDATE invites
SET uses_left = uses_left - 1
WHERE id = ? AND uses_left > 0
RETURNING *;

-- name: DeleteInvite :exec
DELETE FROM invites WHERE id = ?;
