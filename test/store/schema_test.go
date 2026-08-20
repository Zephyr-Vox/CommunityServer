package store_test

import (
	"path/filepath"
	"testing"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/store"
)

func TestSessionsPreviousTokenHashIndex(t *testing.T) {
	conn, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Exec(db.SchemaSQL); err != nil {
		t.Fatal(err)
	}

	rows, err := conn.Query("PRAGMA index_list('sessions')")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var sequence int
		var name string
		var unique int
		var origin string
		var partial int
		if err := rows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
			t.Fatal(err)
		}
		if name == "idx_sessions_prev_token_hash" {
			if partial != 1 {
				t.Fatalf("prev_token_hash index partial flag = %d, want 1", partial)
			}
			return
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("idx_sessions_prev_token_hash is missing")
}
