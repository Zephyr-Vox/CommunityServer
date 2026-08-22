// Package scope evaluates RBAC permissions at server, group, and channel
// resource scopes against immutable realtime state.
package scope

import (
	"encoding/json"
	"errors"
	"slices"

	"zephyr.vox/server/ce/internal/rbac"
	"zephyr.vox/server/ce/internal/realtime"
)

var (
	// ErrInvalidState is returned when a published projection lacks the root
	// permission config or contains an unreadable effective config.
	ErrInvalidState = errors.New("rbac scope: invalid state projection")
)

// Authority is the resource-scoped RBAC result for one user. Permissions are
// sorted and deduplicated. Rank is -1 when the user has no applicable role.
type Authority struct {
	Owner       bool
	Rank        int64
	Permissions []rbac.Permission
}

// Decision is one resource authorization result. Invisible distinguishes the
// required not-found response for inaccessible private resources from an
// ordinary visible-but-forbidden permission denial.
type Decision struct {
	Allow     bool
	Visible   bool
	Authority Authority
	Reason    string
}

// Authorizer evaluates scoped permissions without retaining mutable caches.
// Every decision is derived from the exact immutable StateVersion supplied by
// its caller, so HTTP checks and sequencer revalidation can share one model.
type Authorizer struct {
	visibility *realtime.VisibilityResolver
}

// NewAuthorizer returns a stateless resource-scope authorizer.
func NewAuthorizer() *Authorizer {
	return &Authorizer{visibility: realtime.NewVisibilityResolver()}
}

// Decide evaluates permission for userID at target. It verifies resource
// visibility before permission for non-owners so callers can render private
// resources as not found. A malformed target or missing resource produces a
// denied, invisible decision; malformed persisted permission state is an error.
func (a *Authorizer) Decide(userID int64, target realtime.Scope, permission rbac.Permission, version *realtime.StateVersion) (Decision, error) {
	if a == nil || a.visibility == nil || version == nil || userID <= 0 || !target.Valid() || !rbac.AllowedAtScope(target.Type, permission) {
		return Decision{Reason: "invalid authorization target"}, nil
	}
	if _, exists := version.User(userID); !exists {
		return Decision{Reason: "unknown user"}, nil
	}
	if !targetExists(target, version) {
		return Decision{Reason: "target not found"}, nil
	}

	authority, err := a.Authority(userID, target, version)
	if err != nil {
		return Decision{}, err
	}
	visible := authority.Owner || visibleAt(a.visibility, userID, target, version)
	if !visible {
		return Decision{Visible: false, Authority: authority, Reason: "target not visible"}, nil
	}
	if authority.Owner || slices.Contains(authority.Permissions, permission) {
		return Decision{Allow: true, Visible: true, Authority: authority, Reason: "allowed"}, nil
	}
	return Decision{Visible: true, Authority: authority, Reason: "missing permission " + string(permission)}, nil
}

// Authority resolves the role rank and permission union that apply to userID
// at target. It does not perform ACL visibility checks, allowing callers to
// compare target ranks only after their separate visibility policy succeeds.
func (a *Authorizer) Authority(userID int64, target realtime.Scope, version *realtime.StateVersion) (Authority, error) {
	if version == nil || userID <= 0 || !target.Valid() {
		return Authority{}, ErrInvalidState
	}
	if _, exists := version.User(userID); !exists || !targetExists(target, version) {
		return Authority{Rank: -1}, nil
	}

	config, err := effectiveConfig(target, version)
	if err != nil {
		return Authority{}, err
	}
	var grants map[string][]string
	if err := json.Unmarshal([]byte(config.Config), &grants); err != nil || grants == nil {
		return Authority{}, ErrInvalidState
	}

	authority := Authority{Rank: -1}
	seen := make(map[rbac.Permission]struct{})
	for _, binding := range version.Bindings(userID) {
		if !bindingApplies(binding, target, version) {
			continue
		}
		role, exists := version.Role(binding.RoleKey)
		if !exists {
			return Authority{}, ErrInvalidState
		}
		if role.Rank > authority.Rank {
			authority.Rank = role.Rank
		}
		if binding.RoleKey == "owner" && binding.Scope == (realtime.Scope{Type: "server"}) {
			authority.Owner = true
			continue
		}
		for _, rawPermission := range grants[binding.RoleKey] {
			permission := rbac.Permission(rawPermission)
			if !rbac.IsKnown(permission) || !rbac.AllowedAtScope(target.Type, permission) {
				continue
			}
			if _, duplicate := seen[permission]; duplicate {
				continue
			}
			seen[permission] = struct{}{}
			authority.Permissions = append(authority.Permissions, permission)
		}
	}
	slices.Sort(authority.Permissions)
	return authority, nil
}

// targetExists reports whether target names a projection resource.
func targetExists(target realtime.Scope, version *realtime.StateVersion) bool {
	if target.Type == "server" {
		return true
	}
	if target.Type == "group" {
		_, exists := version.Group(target.ID)
		return exists
	}
	_, exists := version.Channel(target.ID)
	return exists
}

// visibleAt applies the shared ACL resolver to one non-server target.
func visibleAt(visibility *realtime.VisibilityResolver, userID int64, target realtime.Scope, version *realtime.StateVersion) bool {
	if target.Type == "server" {
		return true
	}
	if target.Type == "group" {
		return visibility.CanSeeGroup(userID, target.ID, version)
	}
	return visibility.CanAccessChannel(userID, target.ID, version)
}

// bindingApplies reports whether a binding participates in target's effective
// permission union. Sibling and unrelated scoped bindings never participate.
func bindingApplies(binding realtime.RoleBinding, target realtime.Scope, version *realtime.StateVersion) bool {
	if binding.Scope.Type == "server" {
		return true
	}
	if target.Type == "server" {
		return false
	}
	if target.Type == "group" {
		return binding.Scope.Type == "group" && binding.Scope.ID == target.ID
	}
	channel, exists := version.Channel(target.ID)
	if !exists {
		return false
	}
	if binding.Scope.Type == "channel" {
		return binding.Scope.ID == target.ID
	}
	return binding.Scope.Type == "group" && channel.GroupID != nil && binding.Scope.ID == *channel.GroupID
}

// effectiveConfig returns target's nearest local config, falling back through
// channel parent and then server. The root row must always exist after seed.
func effectiveConfig(target realtime.Scope, version *realtime.StateVersion) (realtime.PermissionConfig, error) {
	if config, exists := version.Config(target); exists {
		return config, nil
	}
	if target.Type == "channel" {
		channel, exists := version.Channel(target.ID)
		if !exists {
			return realtime.PermissionConfig{}, ErrInvalidState
		}
		if channel.GroupID != nil {
			if config, exists := version.Config(realtime.Scope{Type: "group", ID: *channel.GroupID}); exists {
				return config, nil
			}
		}
	}
	root, exists := version.Config(realtime.Scope{Type: "server"})
	if !exists {
		return realtime.PermissionConfig{}, ErrInvalidState
	}
	return root, nil
}
