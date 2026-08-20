package realtime_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/snowflake"
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
	txStores := stores.WithTx(tx)
	if err := durable.Admit(ctx, txStores); err != nil {
		t.Fatal(err)
	}
	if err := durable.Save(ctx, txStores, identity, key, result); err != nil {
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
	txStores = stores.WithTx(tx)
	if err := durable.Admit(ctx, txStores); err != nil {
		t.Fatal(err)
	}
	if err := durable.Save(ctx, txStores, identity, rollbackKey, rolledBack); err != nil {
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
	txStores = stores.WithTx(tx)
	if err := durable.Admit(ctx, txStores); err != nil {
		t.Fatal(err)
	}
	if err := durable.Save(ctx, txStores, identity, "durable-command-3", noContent); err != nil {
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

func TestActivationIdempotencyUsesInstallationIdentityWithoutPlaintext(t *testing.T) {
	stores := newStores(t)
	ctx := context.Background()
	installation, err := stores.Installation.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := realtime.NewRequestIdentitySigner([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	durable, err := realtime.NewDurableActivationIdempotency(stores, signer)
	if err != nil {
		t.Fatal(err)
	}
	identity := realtime.InstallationCommandIdentity{
		InstallationID:     installation.InstallationID,
		ActivationCodeHash: strings.Repeat("a", 64),
		Method:             "POST",
		RouteTemplate:      "/api/v0/admin/activate",
		CanonicalDTO:       []byte(`{"username":"boss","password":"secret123","nickname":"Boss"}`),
	}
	key := "activation-key-0001"
	result := realtime.ActivationCommandResult{
		CommandID: 77,
		Status:    200,
		Body:      []byte(`{"user":{"id":"42","username":"boss","nickname":"Boss","avatar":""}}`),
	}
	tx, err := stores.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	txStores := stores.WithTx(tx)
	if err := durable.Admit(ctx, txStores); err != nil {
		t.Fatal(err)
	}
	if err := durable.Save(ctx, txStores, identity, key, result); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	replay, found, err := durable.Lookup(ctx, identity, key)
	if err != nil || !found || replay.CommandID != result.CommandID || replay.Status != result.Status {
		t.Fatalf("activation replay=%+v found=%t err=%v", replay, found, err)
	}
	changedCode := identity
	changedCode.ActivationCodeHash = strings.Repeat("b", 64)
	if _, found, err := durable.Lookup(ctx, changedCode, key); !found || !errors.Is(err, realtime.ErrIdempotencyMismatch) {
		t.Fatalf("activation code mismatch found=%t err=%v", found, err)
	}
	changedPassword := identity
	changedPassword.CanonicalDTO = []byte(`{"username":"boss","password":"other123","nickname":"Boss"}`)
	if _, found, err := durable.Lookup(ctx, changedPassword, key); !found || !errors.Is(err, realtime.ErrIdempotencyMismatch) {
		t.Fatalf("activation request mismatch found=%t err=%v", found, err)
	}

	record, err := stores.ActivationIdempotency.Lookup(ctx, installation.InstallationID, key)
	if err != nil {
		t.Fatal(err)
	}
	stored := strings.Join([]string{record.ActivationCodeHash, record.RequestHMAC, string(record.ResultBody)}, "\n")
	if strings.Contains(stored, "secret123") || strings.Contains(stored, "BossPassword") || record.RequestHMAC == "" {
		t.Fatalf("activation record retained plaintext request data: %+v", record)
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
	if _, err := cache.Claim(1, "runtime-key-9999", requestHMAC); !errors.Is(err, realtime.ErrRuntimeIdempotencyFull) {
		t.Fatalf("live per-user cap claim = %v, want ErrRuntimeIdempotencyFull", err)
	}
	oldest, err := cache.Claim(1, "runtime-key-0000", requestHMAC)
	if err != nil || oldest.Owner() {
		t.Fatalf("live oldest result was evicted: owner=%t err=%v", oldest != nil && oldest.Owner(), err)
	}
	replayed, err := oldest.Wait(context.Background())
	if err != nil || replayed.CommandID != 2 {
		t.Fatalf("oldest replay = %+v, err=%v", replayed, err)
	}
}

func TestRuntimeIdempotencyGlobalCapPreservesLiveResults(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	cache := realtime.NewRuntimeIdempotencyCacheWithClock(func() time.Time { return now })
	requestHMAC := strings.Repeat("a", 64)
	for index := 0; index < realtime.MaxRuntimeIdempotencyRecords; index++ {
		principalID := int64(index/realtime.MaxRuntimeIdempotencyRecordsPerUser + 1)
		key := fmt.Sprintf("global-key-%08d", index%realtime.MaxRuntimeIdempotencyRecordsPerUser)
		claim, err := cache.Claim(principalID, key, requestHMAC)
		if err != nil || !claim.Owner() {
			t.Fatalf("global claim %d owner=%t err=%v", index, claim != nil && claim.Owner(), err)
		}
		if err := claim.Complete(runtimeResult(int64(index + 1))); err != nil {
			t.Fatalf("complete global claim %d: %v", index, err)
		}
	}
	if _, err := cache.Claim(10_000, "global-key-extra", requestHMAC); !errors.Is(err, realtime.ErrRuntimeIdempotencyFull) {
		t.Fatalf("global cap claim = %v, want ErrRuntimeIdempotencyFull", err)
	}
	oldest, err := cache.Claim(1, "global-key-00000000", requestHMAC)
	if err != nil || oldest.Owner() {
		t.Fatalf("oldest global result was evicted: owner=%t err=%v", oldest != nil && oldest.Owner(), err)
	}
	result, err := oldest.Wait(context.Background())
	if err != nil || result.CommandID != 1 {
		t.Fatalf("oldest global replay=%+v err=%v", result, err)
	}

	now = now.Add(realtime.RuntimeIdempotencyTTL)
	claim, err := cache.Claim(10_000, "global-key-extra", requestHMAC)
	if err != nil || !claim.Owner() {
		t.Fatalf("post-expiry global claim owner=%t err=%v", claim != nil && claim.Owner(), err)
	}
}

func TestSequencerPersistsReservedResultWithDomainTransaction(t *testing.T) {
	ctx := context.Background()
	stores := newStores(t)
	user, err := stores.Users.CreateUser(ctx, "alice", "hash", "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := realtime.NewStateStoreWithEpoch(ctx, stores, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), func() int64 { return 123 })
	if err != nil {
		t.Fatal(err)
	}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	fatal := make(chan error, 1)
	sequencer, err := realtime.NewPostCommitSequencer(publication, idGen, func(err error) { fatal <- err })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sequencer.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	cursorSigner, err := realtime.NewCursorSignerWithKey(testEpoch, []byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	requestSigner, err := realtime.NewRequestIdentitySigner([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	durable, err := realtime.NewDurableIdempotency(stores, requestSigner)
	if err != nil {
		t.Fatal(err)
	}
	identity := realtime.HTTPCommandIdentity{
		PrincipalID:   user.ID,
		Method:        "POST",
		RouteTemplate: "/api/v0/groups",
		CanonicalDTO:  []byte(`{"name":"Reserved"}`),
	}
	key := "reserved-result-01"

	completion, err := sequencer.Submit(ctx, realtime.PostCommitCommand{
		QueueBytes: 1,
		Execute: func(ctx context.Context, commandID int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			tx, err := stores.BeginTx(ctx)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			committed := false
			defer func() {
				if !committed {
					_ = tx.Rollback()
				}
			}()
			txStores := stores.WithTx(tx)
			if err := durable.Admit(ctx, txStores); err != nil {
				return realtime.CommandOutput{}, err
			}
			group, err := txStores.Channels.CreateGroup(ctx, "Reserved", 1, "public")
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			candidate, err := state.BuildPersistentCandidateFrom(ctx, txStores)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			reserved, err := execution.Reserve(realtime.PublicationRequest{
				Candidate: candidate,
				Events: []realtime.StateEventTemplate{{
					EventType: "group.created",
					Scope:     realtime.Scope{Type: "server"},
					Data:      []byte(fmt.Sprintf(`{"group_id":"%d"}`, group.ID)),
				}},
			})
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			cursor, err := cursorSigner.Issue(user.ID, reserved.Checkpoint, reserved.Version.VisibilityEpoch(user.ID))
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if err := durable.Save(ctx, txStores, identity, key, realtime.CanonicalCommandResult{
				CommandID:   commandID,
				Status:      201,
				Body:        []byte(fmt.Sprintf(`{"group":{"id":"%d","name":"Reserved"}}`, group.ID)),
				Checkpoint:  reserved.Checkpoint,
				StateCursor: cursor,
			}); err != nil {
				return realtime.CommandOutput{}, err
			}
			if _, err := execution.Commit(tx); err != nil {
				return realtime.CommandOutput{}, err
			}
			committed = true
			return realtime.CommandOutput{Value: group.ID}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-fatal:
		t.Fatalf("unexpected sequencer failure: %v", err)
	default:
	}
	if completion.CommandID == 0 || completion.Publication.Checkpoint.GEID != 1 {
		t.Fatalf("completion = %+v", completion)
	}
	replay, found, err := durable.Lookup(ctx, identity, key, testEpoch)
	if err != nil || !found {
		t.Fatalf("durable lookup found=%t err=%v", found, err)
	}
	if replay.CommandID != completion.CommandID || replay.Checkpoint != completion.Publication.Checkpoint || replay.StateCursor == "" {
		t.Fatalf("durable replay = %+v completion=%+v", replay, completion)
	}
	if _, exists := publication.Capture().Version.Group(completion.Value.(int64)); !exists {
		t.Fatal("published candidate omitted transaction-created group")
	}
}

func TestDurableIdempotencyRejectsFullLiveWindowWithoutEviction(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC).UnixMilli()
	conn, err := store.Open(filepath.Join(t.TempDir(), "idempotency-cap.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Exec(db.SchemaSQL); err != nil {
		t.Fatal(err)
	}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	stores := store.New(conn, idGen, func() int64 { return now })
	if err := stores.SeedAndVerify(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := stores.Users.CreateUser(ctx, "alice", "hash", "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `
WITH RECURSIVE sequence(number) AS (
    VALUES(1)
    UNION ALL
    SELECT number + 1 FROM sequence WHERE number < ?
)
INSERT INTO command_idempotency (
    principal_id, idempotency_key, endpoint, request_hmac, command_id, status,
    result_body, stream_epoch, geid, state_cursor, created_at, expires_at
)
SELECT ?, printf('cap-fill-%08d', number), 'POST /cap', ?, number, 200,
       '{}', ?, number, 'cursor', ?, ?
FROM sequence;
`, store.MaxCommandIdempotencyRecords, user.ID, strings.Repeat("a", 64), testEpoch, now, now+store.CommandIdempotencyTTL.Milliseconds()); err != nil {
		t.Fatal(err)
	}

	tx, err := stores.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = stores.WithTx(tx).Idempotency.Admit(ctx)
	if !errors.Is(err, store.ErrCommandIdempotencyFull) {
		t.Fatalf("full live window admission = %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	record, err := stores.Idempotency.Lookup(ctx, user.ID, "cap-fill-00000001")
	if err != nil || record.CommandID != 1 {
		t.Fatalf("oldest live record was evicted: record=%+v err=%v", record, err)
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
