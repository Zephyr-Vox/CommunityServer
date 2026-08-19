// Package rbac implements the core authorization model: permissions, roles,
// principals and deny-by-default decisions. It has no dependency on Echo or
// any configuration library.
package rbac

import (
	"context"
	"slices"
)

// Permission is a named capability, e.g. "user:read".
type Permission string

// Wildcard grants every registered permission.
const Wildcard Permission = "*"

// Principal is the authenticated identity whose permissions are being checked.
type Principal struct {
	UserID   int64
	Bindings []RoleBinding
}

// RoleBinding identifies a role granted to a user at one resource scope.
// GroupID and ChannelID are populated only for their matching scope types.
type RoleBinding struct {
	RoleKey   string
	ScopeType string
	GroupID   *int64
	ChannelID *int64
}

// Decision is the outcome of an authorization check, with a reason suitable
// for audit logs.
type Decision struct {
	Allow  bool
	Reason string
}

// PermissionStore resolves the permissions granted by a role.
type PermissionStore interface {
	// PermissionsForRole returns the role's permissions and whether the role
	// exists. Unknown roles grant nothing.
	PermissionsForRole(ctx context.Context, role string) ([]Permission, bool, error)
}

// Authorizer decides whether a principal may perform an action. It is safe for
// concurrent use as long as the underlying PermissionStore is.
type Authorizer struct {
	store PermissionStore
}

// NewAuthorizer returns an Authorizer backed by the given store.
func NewAuthorizer(store PermissionStore) *Authorizer {
	return &Authorizer{store: store}
}

// Check returns an allow decision only when the principal's effective
// permissions contain perm or Wildcard. Anything else — unknown roles, store
// errors, an empty role list — is denied.
func (a *Authorizer) Check(ctx context.Context, p Principal, perm Permission) Decision {
	permissions, err := a.effectivePermissions(ctx, p)
	if err != nil {
		return Decision{Allow: false, Reason: "denied: permission lookup failed"}
	}
	for _, granted := range permissions {
		if granted == Wildcard || granted == perm {
			return Decision{Allow: true, Reason: "allowed"}
		}
	}
	return Decision{Allow: false, Reason: "denied: missing permission " + string(perm)}
}

// Permissions returns the deduplicated, sorted union of all permissions granted
// by the principal's roles. Used by endpoints such as GET /me.
func (a *Authorizer) Permissions(ctx context.Context, p Principal) ([]Permission, error) {
	return a.effectivePermissions(ctx, p)
}

// effectivePermissions returns grants from the principal's server bindings.
// Target-scoped authorization will add the applicable group/channel bindings;
// current HTTP routes are server-scoped and must not accidentally merge them.
func (a *Authorizer) effectivePermissions(ctx context.Context, p Principal) ([]Permission, error) {
	seen := make(map[Permission]struct{})
	var permissions []Permission
	for _, binding := range p.Bindings {
		if binding.ScopeType != "server" {
			continue
		}
		granted, ok, err := a.store.PermissionsForRole(ctx, binding.RoleKey)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		for _, perm := range granted {
			if _, dup := seen[perm]; dup {
				continue
			}
			seen[perm] = struct{}{}
			permissions = append(permissions, perm)
		}
	}
	slices.Sort(permissions)
	return permissions, nil
}
