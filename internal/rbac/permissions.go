package rbac

import (
	"encoding/json"
)

const (
	PermServerManage      Permission = "server.manage"
	PermServerMetrics     Permission = "server.metrics"
	PermRoleManage        Permission = "role.manage"
	PermUserRead          Permission = "user:read"
	PermUserUpdate        Permission = "user:update"
	PermUserDelete        Permission = "user:delete"
	PermUserKick          Permission = "user:kick"
	PermInviteManage      Permission = "invite.manage"
	PermGroupCreate       Permission = "group.create"
	PermGroupManage       Permission = "group.manage"
	PermChannelCreate     Permission = "channel.create"
	PermChannelCreateTemp Permission = "channel.create_temporary"
	PermChannelManage     Permission = "channel.manage"
	PermChannelInvite     Permission = "channel.invite"
	PermChannelAnnounce   Permission = "channel.announce"
	PermMemberMute        Permission = "member.mute"
)

// AllPermissions is the registry every role configuration is validated against.
var AllPermissions = []Permission{
	PermServerManage,
	PermServerMetrics,
	PermRoleManage,
	PermUserRead,
	PermUserUpdate,
	PermUserDelete,
	PermUserKick,
	PermInviteManage,
	PermGroupCreate,
	PermGroupManage,
	PermChannelCreate,
	PermChannelCreateTemp,
	PermChannelManage,
	PermChannelInvite,
	PermChannelAnnounce,
	PermMemberMute,
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

// DefaultServerPermissionConfig returns the canonical JSON config for the
// built-in roles. Owner is represented explicitly as wildcard; all other
// built-in grants are constrained to the permission registry.
func DefaultServerPermissionConfig() (string, error) {
	permissions := map[string][]Permission{
		"owner": {Wildcard},
		"admin": {
			PermServerManage,
			PermServerMetrics,
			PermRoleManage,
			PermUserRead,
			PermUserUpdate,
			PermUserDelete,
			PermUserKick,
			PermInviteManage,
			PermGroupCreate,
			PermGroupManage,
			PermChannelCreate,
			PermChannelCreateTemp,
			PermChannelManage,
			PermChannelInvite,
			PermChannelAnnounce,
			PermMemberMute,
		},
		"member": {PermChannelCreateTemp},
	}
	encoded, err := json.Marshal(permissions)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
