package realtime

import "sort"

// VisibilityResolver evaluates group and channel visibility against one
// immutable StateVersion. It is deliberately stateless: snapshots, event
// recipient selection and future write-pump checks must all use this one rule
// set instead of maintaining independent ACL caches.
type VisibilityResolver struct{}

// NewVisibilityResolver returns a resolver for immutable StateVersion values.
func NewVisibilityResolver() *VisibilityResolver {
	return &VisibilityResolver{}
}

// CanSeeGroup reports whether userID can see groupID in version. Owner bypasses
// ACL checks; all other users need a public group or a matching user/role ACL.
func (r *VisibilityResolver) CanSeeGroup(userID, groupID int64, version *StateVersion) bool {
	if version == nil {
		return false
	}
	group, exists := version.persistent.groups[groupID]
	if !exists || !r.knownUser(userID, version) {
		return false
	}
	if r.isOwner(userID, version) || group.Visibility == "public" {
		return true
	}
	return r.matchesGroupAccess(userID, groupID, version)
}

// CanAccessChannel reports whether userID can see and access channelID in
// version. A grouped channel first requires visibility of its parent group,
// even when the channel itself has a matching private ACL.
func (r *VisibilityResolver) CanAccessChannel(userID, channelID int64, version *StateVersion) bool {
	if version == nil {
		return false
	}
	channel, exists := version.persistent.channels[channelID]
	if !exists || !r.knownUser(userID, version) {
		return false
	}
	if channel.GroupID != nil && !r.CanSeeGroup(userID, *channel.GroupID, version) {
		return false
	}
	if r.isOwner(userID, version) || channel.Visibility == "public" {
		return true
	}
	return r.matchesChannelAccess(userID, channel, version)
}

// VisibleScopeIDs returns every group and channel visible to userID in stable
// scope-key order. Group-less channels appear without an enclosing group scope.
func (r *VisibilityResolver) VisibleScopeIDs(userID int64, version *StateVersion) []Scope {
	if version == nil || !r.knownUser(userID, version) {
		return nil
	}
	scopes := make([]Scope, 0, len(version.persistent.groups)+len(version.persistent.channels))
	for groupID := range version.persistent.groups {
		if r.CanSeeGroup(userID, groupID, version) {
			scopes = append(scopes, Scope{Type: "group", ID: groupID})
		}
	}
	for channelID := range version.persistent.channels {
		if r.CanAccessChannel(userID, channelID, version) {
			scopes = append(scopes, Scope{Type: "channel", ID: channelID})
		}
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Key() < scopes[j].Key() })
	return scopes
}

// VisibilityChange contains the scopes gained and lost between two immutable
// versions for one user. Empty slices mean that the visible-scope set is equal.
type VisibilityChange struct {
	Granted []Scope
	Revoked []Scope
}

// Changed reports whether the visible-scope set changed.
func (c VisibilityChange) Changed() bool {
	return len(c.Granted) != 0 || len(c.Revoked) != 0
}

// Diff returns userID's gained and revoked scopes from before to after. Future
// StatePublication code increments the user's visibility epoch exactly when the
// returned change is non-empty.
func (r *VisibilityResolver) Diff(userID int64, before, after *StateVersion) VisibilityChange {
	beforeSet := scopesToSet(r.VisibleScopeIDs(userID, before))
	afterSet := scopesToSet(r.VisibleScopeIDs(userID, after))
	change := VisibilityChange{}
	for scope := range afterSet {
		if _, existed := beforeSet[scope]; !existed {
			change.Granted = append(change.Granted, scope)
		}
	}
	for scope := range beforeSet {
		if _, remains := afterSet[scope]; !remains {
			change.Revoked = append(change.Revoked, scope)
		}
	}
	sort.Slice(change.Granted, func(i, j int) bool { return change.Granted[i].Key() < change.Granted[j].Key() })
	sort.Slice(change.Revoked, func(i, j int) bool { return change.Revoked[i].Key() < change.Revoked[j].Key() })
	return change
}

// knownUser reports whether userID exists in the projection.
func (r *VisibilityResolver) knownUser(userID int64, version *StateVersion) bool {
	_, exists := version.persistent.users[userID]
	return exists
}

// isOwner reports whether userID has the unique server-scope owner binding.
func (r *VisibilityResolver) isOwner(userID int64, version *StateVersion) bool {
	for _, binding := range version.persistent.bindings[userID] {
		if binding.RoleKey == "owner" && binding.Scope.Type == "server" {
			return true
		}
	}
	return false
}

// matchesGroupAccess evaluates group user and role ACL entries.
func (r *VisibilityResolver) matchesGroupAccess(userID, groupID int64, version *StateVersion) bool {
	for _, entry := range version.persistent.groupAccess[groupID] {
		if entry.UserID != nil && *entry.UserID == userID {
			return true
		}
		if entry.RoleKey != nil && r.hasRoleAtGroup(userID, *entry.RoleKey, groupID, version) {
			return true
		}
	}
	return false
}

// matchesChannelAccess evaluates channel user and role ACL entries.
func (r *VisibilityResolver) matchesChannelAccess(userID int64, channel Channel, version *StateVersion) bool {
	for _, entry := range version.persistent.channelAccess[channel.ID] {
		if entry.UserID != nil && *entry.UserID == userID {
			return true
		}
		if entry.RoleKey != nil && r.hasRoleAtChannel(userID, *entry.RoleKey, channel, version) {
			return true
		}
	}
	return false
}

// hasRoleAtGroup reports whether a binding can satisfy a group ACL role entry.
func (r *VisibilityResolver) hasRoleAtGroup(userID int64, roleKey string, groupID int64, version *StateVersion) bool {
	for _, binding := range version.persistent.bindings[userID] {
		if binding.RoleKey != roleKey {
			continue
		}
		if binding.Scope.Type == "server" || (binding.Scope.Type == "group" && binding.Scope.ID == groupID) {
			return true
		}
	}
	return false
}

// hasRoleAtChannel reports whether a binding can satisfy a channel ACL role
// entry. Server, parent-group and exact-channel bindings are applicable.
func (r *VisibilityResolver) hasRoleAtChannel(userID int64, roleKey string, channel Channel, version *StateVersion) bool {
	for _, binding := range version.persistent.bindings[userID] {
		if binding.RoleKey != roleKey {
			continue
		}
		if binding.Scope.Type == "server" || (binding.Scope.Type == "channel" && binding.Scope.ID == channel.ID) {
			return true
		}
		if channel.GroupID != nil && binding.Scope.Type == "group" && binding.Scope.ID == *channel.GroupID {
			return true
		}
	}
	return false
}

// scopesToSet converts a stable scope slice into a set for a visibility diff.
func scopesToSet(scopes []Scope) map[Scope]struct{} {
	set := make(map[Scope]struct{}, len(scopes))
	for _, scope := range scopes {
		set[scope] = struct{}{}
	}
	return set
}
