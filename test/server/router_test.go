package server_test

import (
	"slices"
	"testing"
)

// TestRouteTable pins the complete mounted route table. This guards the
// path-grouping refactor against accidentally dropping or renaming a route,
// including the public metadata endpoint and authenticated synchronization
// endpoints alongside empty-path routes such as PATCH /api/v0/me.
func TestRouteTable(t *testing.T) {
	app := newTestApp(t)
	got := make([]string, 0, 60)
	for _, r := range app.Echo().Router().Routes() {
		got = append(got, r.Method+" "+r.Path)
	}
	slices.Sort(got)

	want := []string{
		"DELETE /api/v0/admin/invites/:id",
		"DELETE /api/v0/channels/:id",
		"DELETE /api/v0/channels/:id/access/:access_id",
		"DELETE /api/v0/groups/:id",
		"DELETE /api/v0/groups/:id/access/:access_id",
		"DELETE /api/v0/me/avatar",
		"DELETE /api/v0/mutes/:id",
		"DELETE /api/v0/rbac/bindings/:id",
		"DELETE /api/v0/rbac/roles/:key",
		"DELETE /api/v0/users/:id",
		"GET /api/v0/admin/invites",
		"GET /api/v0/admin/metrics",
		"GET /api/v0/auth/me",
		"GET /api/v0/auth/status",
		"GET /api/v0/channels",
		"GET /api/v0/channels/:id",
		"GET /api/v0/channels/:id/access",
		"GET /api/v0/groups",
		"GET /api/v0/groups/:id",
		"GET /api/v0/groups/:id/access",
		"GET /api/v0/metadata",
		"GET /api/v0/mutes",
		"GET /api/v0/rbac/bindings",
		"GET /api/v0/rbac/config",
		"GET /api/v0/rbac/roles",
		"GET /api/v0/state/snapshot",
		"GET /api/v0/users",
		"GET /api/v0/users/:id",
		"GET /api/v0/ws",
		"GET /avatar/:file",
		"PATCH /api/v0/channels/:id",
		"PATCH /api/v0/groups/:id",
		"PATCH /api/v0/me",
		"PATCH /api/v0/mutes/:id",
		"PATCH /api/v0/rbac/roles/:key",
		"PATCH /api/v0/users/:id",
		"POST /api/v0/admin/activate",
		"POST /api/v0/admin/invites",
		"POST /api/v0/auth/login",
		"POST /api/v0/auth/logout",
		"POST /api/v0/auth/refresh",
		"POST /api/v0/auth/register",
		"POST /api/v0/channels",
		"POST /api/v0/channels/:id/access",
		"POST /api/v0/channels/:id/join",
		"POST /api/v0/channels/current/leave",
		"POST /api/v0/groups",
		"POST /api/v0/groups/:id/access",
		"POST /api/v0/me/avatar",
		"POST /api/v0/me/password",
		"POST /api/v0/mutes",
		"POST /api/v0/owner/transfer",
		"POST /api/v0/rbac/bindings",
		"POST /api/v0/rbac/config/reset",
		"POST /api/v0/rbac/roles",
		"PUT /api/v0/rbac/config",
		"POST /api/v0/users/:id/ban",
		"POST /api/v0/users/:id/kick",
		"POST /api/v0/users/:id/password",
		"POST /api/v0/users/:id/unban",
	}
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Fatalf("route table mismatch\n got: %v\nwant: %v", got, want)
	}
}
