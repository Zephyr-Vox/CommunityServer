package rbac

const (
	PermVoiceJoin    Permission = "voice:join"
	PermUserRead     Permission = "user:read"
	PermUserCreate   Permission = "user:create"
	PermUserUpdate   Permission = "user:update"
	PermUserDelete   Permission = "user:delete"
	PermUserKick     Permission = "user:kick"
	PermInviteManage Permission = "invite:manage"
)

// AllPermissions is the registry every role configuration is validated against.
var AllPermissions = []Permission{
	PermVoiceJoin,
	PermUserRead,
	PermUserCreate,
	PermUserUpdate,
	PermUserDelete,
	PermUserKick,
	PermInviteManage,
}

var allPermissionSet = func() map[Permission]struct{} {
	m := make(map[Permission]struct{}, len(AllPermissions))
	for _, p := range AllPermissions {
		m[p] = struct{}{}
	}
	return m
}()

// IsKnown reports whether p is a registered permission.
func IsKnown(p Permission) bool {
	_, ok := allPermissionSet[p]
	return ok
}
