package auth_test

import (
	"context"
	"testing"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

// TestStateMutationRuntimePublishesAccountChanges verifies that the account
// runtime exposes a committed database mutation and its replay event as one
// ordered result instead of requiring a second post-commit bridge.
func TestStateMutationRuntimePublishesAccountChanges(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	state, err := realtime.NewStateStore(ctx, e.stores)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sequencer, err := realtime.NewPostCommitSequencer(publication, e.stores.IDGenerator(), func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sequencer.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	runtime, err := auth.NewStateMutationRuntime(e.stores, e.principals, state, sequencer, realtime.NewMutationGate())
	if err != nil {
		t.Fatal(err)
	}

	value, err := runtime.Run(ctx, nil, func(commandCtx context.Context, txStores *store.Stores) (auth.AccountMutationResult, error) {
		user, err := txStores.Users.CreateUser(commandCtx, "alice", "hash", "Alice", nil)
		if err != nil {
			return auth.AccountMutationResult{}, err
		}
		return auth.AccountMutationResult{
			Value:  user,
			Change: auth.StateChange{EventType: "user.created", UserID: user.ID},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	user, ok := value.(*db.User)
	if !ok {
		t.Fatalf("runtime value = %T, want *db.User", value)
	}
	if got, ok := state.Current().User(user.ID); !ok || got.Nickname != "Alice" {
		t.Fatalf("published user = %+v, exists = %t", got, ok)
	}
	capture := publication.Capture()
	created := false
	for _, event := range capture.Events {
		if event.EventType == "user.created" {
			created = true
			break
		}
	}
	if !created {
		t.Fatalf("created event missing from %+v", capture.Events)
	}

	if _, err := runtime.Run(ctx, []int64{user.ID}, func(commandCtx context.Context, txStores *store.Stores) (auth.AccountMutationResult, error) {
		if _, err := txStores.Users.UpdateNickname(commandCtx, user.ID, "Alice 2"); err != nil {
			return auth.AccountMutationResult{}, err
		}
		return auth.AccountMutationResult{Change: auth.StateChange{EventType: "user.updated", UserID: user.ID}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, ok := state.Current().User(user.ID); !ok || got.Nickname != "Alice 2" {
		t.Fatalf("updated user = %+v, exists = %t", got, ok)
	}
	capture = publication.Capture()
	if len(capture.Events) < 2 || capture.Events[len(capture.Events)-2].EventType != "user.updated" || capture.Events[len(capture.Events)-1].EventType != "self.updated" {
		t.Fatalf("updated events = %+v", capture.Events)
	}
}
