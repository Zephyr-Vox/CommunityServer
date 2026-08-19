package realtime_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

func TestDurableIdempotencyCanonicalReplayAndEpochChange(t *testing.T) {
	stores := newStores(t)
	ctx := context.Background()
	user, err := stores.Users.CreateUser(ctx, "alice", "hash", "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := realtime.NewRequestIdentitySigner([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	durable, err := realtime.NewDurableIdempotency(stores, signer)
	if err != nil {
		t.Fatal(err)
	}
	identity := realtime.HTTPCommandIdentity{
		PrincipalID:   user.ID,
		Method:        "POST",
		RouteTemplate: "/api/v0/groups",
		CanonicalDTO:  []byte(`{"position":1,"name":"General"}`),
		PreconditionHeaders: []realtime.CanonicalField{
			{Name: "If-Match", Value: `"server:1"`},
		},
	}
	key := "durable-command-1"
	result := realtime.CanonicalCommandResult{
		CommandID:   42,
		Status:      201,
		Body:        []byte(`{"group":{"name":"General","id":"10"}}`),
		Headers:     store.IdempotencyHeaders{ETag: `"group:10:1"`, Location: "/api/v0/groups/10", CacheControl: "no-store", Pragma: "no-cache"},
		Checkpoint:  realtime.Checkpoint{StreamEpoch: testEpoch, GEID: 9},
		StateCursor: "opaque-cursor",
	}
	tx, err := stores.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := durable.Save(ctx, stores.WithTx(tx), identity, key, result); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Field and JSON object order cannot change the identity HMAC.
	reordered := identity
	reordered.CanonicalDTO = []byte(`{"name":"General","position":1}`)
	reordered.PreconditionHeaders = []realtime.CanonicalField{{Name: "if-match", Value: `"server:1"`}}
	replay, found, err := durable.Lookup(ctx, reordered, key, testEpoch)
	if err != nil || !found {
		t.Fatalf("lookup found=%t err=%v", found, err)
	}
	if replay.CommandID != 42 || replay.Status != 201 || string(replay.Body) != `{"group":{"id":"10","name":"General"}}` || replay.Headers.Location != result.Headers.Location || replay.Checkpoint != result.Checkpoint || replay.StateCursor != result.StateCursor || replay.SyncRequired {
		t.Fatalf("same epoch replay = %+v", replay)
	}

	changed := reordered
	changed.CanonicalDTO = []byte(`{"name":"Other","position":1}`)
	if _, found, err := durable.Lookup(ctx, changed, key, testEpoch); !found || !errors.Is(err, realtime.ErrIdempotencyMismatch) {
		t.Fatalf("identity mismatch found=%t err=%v", found, err)
	}
	otherEpoch := "ffeeddccbbaa99887766554433221100"
	crossEpoch, found, err := durable.Lookup(ctx, reordered, key, otherEpoch)
	if err != nil || !found || !crossEpoch.SyncRequired || crossEpoch.StateCursor != "" || crossEpoch.Checkpoint != (realtime.Checkpoint{}) || crossEpoch.Status != 201 || crossEpoch.Headers.ETag != result.Headers.ETag {
		t.Fatalf("cross-epoch replay = %+v found=%t err=%v", crossEpoch, found, err)
	}

	rollbackKey := "durable-command-2"
	tx, err = stores.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack := result
	rolledBack.CommandID = 43
	if err := durable.Save(ctx, stores.WithTx(tx), identity, rollbackKey, rolledBack); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, found, err := durable.Lookup(ctx, identity, rollbackKey, testEpoch); err != nil || found {
		t.Fatalf("rolled back result found=%t err=%v", found, err)
	}

	noContent := result
	noContent.CommandID = 44
	noContent.Status = 204
	noContent.Body = nil
	tx, err = stores.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := durable.Save(ctx, stores.WithTx(tx), identity, "durable-command-3", noContent); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	noContentReplay, found, err := durable.Lookup(ctx, identity, "durable-command-3", testEpoch)
	if err != nil || !found || noContentReplay.Status != 204 || string(noContentReplay.Body) != "null" {
		t.Fatalf("no-content replay=%+v found=%t err=%v", noContentReplay, found, err)
	}
}

func TestRuntimeIdempotencyCacheCoalescesExpiresAndCapsPerUser(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	cache := realtime.NewRuntimeIdempotencyCacheWithClock(func() time.Time { return now })
	requestHMAC := strings.Repeat("a", 64)
	key := "runtime-key-0001"
	owner, err := cache.Claim(1, key, requestHMAC)
	if err != nil || !owner.Owner() {
		t.Fatalf("owner claim=%+v err=%v", owner, err)
	}
	waiter, err := cache.Claim(1, key, requestHMAC)
	if err != nil || waiter.Owner() {
		t.Fatalf("waiter claim=%+v err=%v", waiter, err)
	}
	completed := make(chan struct {
		result realtime.RuntimeCommandResult
		err    error
	}, 1)
	go func() {
		result, waitErr := waiter.Wait(context.Background())
		completed <- struct {
			result realtime.RuntimeCommandResult
			err    error
		}{result, waitErr}
	}()
	result := runtimeResult(1)
	if err := owner.Complete(result); err != nil {
		t.Fatal(err)
	}
	got := <-completed
	if got.err != nil || got.result.CommandID != 1 || string(got.result.Body) != `{"a":1,"b":2}` {
		t.Fatalf("waiter result=%+v err=%v", got.result, got.err)
	}
	if _, err := cache.Claim(1, key, strings.Repeat("b", 64)); !errors.Is(err, realtime.ErrIdempotencyMismatch) {
		t.Fatalf("mismatched runtime retry = %v", err)
	}
	now = now.Add(realtime.RuntimeIdempotencyTTL)
	if cache.Len() != 0 {
		t.Fatalf("expired runtime entries = %d", cache.Len())
	}

	for i := 0; i < realtime.MaxRuntimeIdempotencyRecordsPerUser; i++ {
		entryKey := fmt.Sprintf("runtime-key-%04d", i)
		claim, err := cache.Claim(1, entryKey, requestHMAC)
		if err != nil || !claim.Owner() {
			t.Fatalf("claim %d owner=%t err=%v", i, claim != nil && claim.Owner(), err)
		}
		if err := claim.Complete(runtimeResult(int64(i + 2))); err != nil {
			t.Fatal(err)
		}
	}
	if cache.Len() != realtime.MaxRuntimeIdempotencyRecordsPerUser {
		t.Fatalf("per-user record count = %d", cache.Len())
	}
	extra, err := cache.Claim(1, "runtime-key-9999", requestHMAC)
	if err != nil || !extra.Owner() || cache.Len() != realtime.MaxRuntimeIdempotencyRecordsPerUser {
		t.Fatalf("cap eviction owner=%t len=%d err=%v", extra != nil && extra.Owner(), cache.Len(), err)
	}
	oldest, err := cache.Claim(1, "runtime-key-0000", requestHMAC)
	if err != nil || !oldest.Owner() {
		t.Fatalf("oldest completed entry was not evicted: owner=%t err=%v", oldest != nil && oldest.Owner(), err)
	}
}

func runtimeResult(commandID int64) realtime.RuntimeCommandResult {
	return realtime.RuntimeCommandResult{
		CommandID:   commandID,
		Status:      200,
		Body:        []byte(`{"b":2,"a":1}`),
		Checkpoint:  realtime.Checkpoint{StreamEpoch: testEpoch, GEID: uint64(commandID)},
		StateCursor: "runtime-cursor",
	}
}
