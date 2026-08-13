package db

import _ "embed"

// SchemaSQL is the full SQLite schema, embedded so the binary does not depend
// on a schema file at runtime. It is the source of truth for the database
// layout; edit internal/db/schema.sql and run sqlc generate afterwards.
//
//go:embed schema.sql
var SchemaSQL string
