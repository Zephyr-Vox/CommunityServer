package auth_test

import (
	"context"
	"sync"
	"testing"
)

type connectionRevoker struct {
	mu    sync.Mutex
	users []int64
}

func (r *connectionRevoker) DisconnectLoginSession(int64, int64, string) {}

func (r *connectionRevoker) DisconnectUser(userID int64, _ string) {
	r.mu.Lock()
	r.users = append(r.users, userID)
	r.mu.Unlock()
}

func (r *connectionRevoker) Users() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int64(nil), r.users...)
}

func TestUserServiceOnlyRevokesConnectionsForDelete(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	actor := e.createUser(t, "admin", "secret123", "admin")
	unbanTarget := e.createUser(t, "unban-target", "secret123", "member")
	deleteTarget := e.createUser(t, "delete-target", "secret123", "member")
	if err := e.stores.Users.Ban(ctx, unbanTarget.ID); err != nil {
		t.Fatal(err)
	}
	revoker := &connectionRevoker{}
	users, _ := newUserService(t, e)
	users.SetConnectionRevoker(revoker)
	if err := users.Unban(ctx, actor.ID, unbanTarget.ID); err != nil {
		t.Fatal(err)
	}
	if got := revoker.Users(); len(got) != 0 {
		t.Fatalf("Unban connection revocations = %v, want none", got)
	}
	if err := users.Delete(ctx, actor.ID, deleteTarget.ID); err != nil {
		t.Fatal(err)
	}
	if got := revoker.Users(); len(got) != 1 || got[0] != deleteTarget.ID {
		t.Fatalf("Delete connection revocations = %v, want [%d]", got, deleteTarget.ID)
	}
}
