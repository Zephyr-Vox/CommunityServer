-- name: UpsertObject :one
INSERT INTO objects (bucket, name, content_type, size, original_name, created_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (bucket, name) DO UPDATE SET
    content_type  = excluded.content_type,
    size          = excluded.size,
    original_name = excluded.original_name,
    created_at    = excluded.created_at
RETURNING *;

-- name: GetObject :one
SELECT * FROM objects WHERE bucket = ? AND name = ?;

-- name: DeleteObject :exec
DELETE FROM objects WHERE bucket = ? AND name = ?;
