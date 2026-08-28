package control

import (
	"encoding/json"
	"errors"
	"strconv"

	"zephyr.vox/server/ce/internal/realtime"
)

// StateEventTemplates creates canonical replayable RBAC events from the exact
// candidate StateVersion that will become visible with the mutation. Affected
// users also receive complete self.updated data to converge their local
// permission UI without refetching a server-wide role list.
func StateEventTemplates(change StateChange, version *realtime.StateVersion) ([]realtime.StateEventTemplate, error) {
	if version == nil {
		return nil, errors.New("rbac control: nil state version")
	}
	scope := change.Scope
	if !scope.Valid() {
		scope = realtime.Scope{Type: "server"}
	}
	events := make([]realtime.StateEventTemplate, 0, 1+len(change.UserIDs))
	switch change.EventType {
	case "rbac.role.created", "rbac.role.updated":
		role, ok := version.Role(change.RoleKey)
		if !ok {
			return nil, errors.New("rbac control: role missing from state projection")
		}
		data, err := json.Marshal(realtime.SnapshotRole{
			Key:         role.Key,
			DisplayName: role.DisplayName,
			Rank:        role.Rank,
			Builtin:     role.Builtin,
		})
		if err != nil {
			return nil, err
		}
		events = append(events, realtime.StateEventTemplate{EventType: change.EventType, Scope: realtime.Scope{Type: "server"}, Data: data})
	case "rbac.role.deleted":
		data, err := json.Marshal(struct {
			RoleKey string `json:"role_key"`
		}{RoleKey: change.RoleKey})
		if err != nil {
			return nil, err
		}
		events = append(events, realtime.StateEventTemplate{EventType: change.EventType, Scope: realtime.Scope{Type: "server"}, Data: data})
	case "rbac.binding.updated", "rbac.config.updated":
		data, err := json.Marshal(struct {
			Scope         stateScope `json:"scope"`
			EntityVersion string     `json:"entity_version"`
		}{Scope: stateScopeFrom(scope), EntityVersion: strconv.FormatUint(version.Number(), 10)})
		if err != nil {
			return nil, err
		}
		events = append(events, realtime.StateEventTemplate{EventType: change.EventType, Scope: scope, Data: data})
	case "owner.transferred":
		if change.PreviousOwnerID <= 0 || change.NewOwnerID <= 0 {
			return nil, errors.New("rbac control: invalid owner transfer event")
		}
		transferData, err := json.Marshal(struct {
			PreviousOwnerID string `json:"previous_owner_id"`
			NewOwnerID      string `json:"new_owner_id"`
		}{
			PreviousOwnerID: strconv.FormatInt(change.PreviousOwnerID, 10),
			NewOwnerID:      strconv.FormatInt(change.NewOwnerID, 10),
		})
		if err != nil {
			return nil, err
		}
		events = append(events, realtime.StateEventTemplate{
			EventType: "owner.transferred",
			Scope:     realtime.Scope{Type: "server"},
			Data:      transferData,
		})
		bindingData, err := json.Marshal(struct {
			Scope         stateScope `json:"scope"`
			EntityVersion string     `json:"entity_version"`
		}{Scope: stateScopeFrom(realtime.Scope{Type: "server"}), EntityVersion: strconv.FormatUint(version.Number(), 10)})
		if err != nil {
			return nil, err
		}
		events = append(events, realtime.StateEventTemplate{
			EventType: "rbac.binding.updated",
			Scope:     realtime.Scope{Type: "server"},
			Data:      bindingData,
		})
		for _, moderationScope := range uniqueScopes(change.ModerationScopes) {
			data, err := moderationMuteRemovedData(moderationScope, version.ModerationEpoch())
			if err != nil {
				return nil, err
			}
			events = append(events, realtime.StateEventTemplate{
				EventType: "moderation.mute.removed",
				Scope:     moderationScope,
				Data:      data,
			})
		}
	default:
		return nil, errors.New("rbac control: invalid state change")
	}
	for _, userID := range uniqueUserIDs(change.UserIDs) {
		if _, exists := version.User(userID); !exists {
			continue
		}
		data, err := json.Marshal(struct {
			Self realtime.SnapshotSelf `json:"self"`
		}{Self: realtime.SnapshotSelfFor(userID, version)})
		if err != nil {
			return nil, err
		}
		events = append(events, realtime.StateEventTemplate{
			EventType:       "self.updated",
			Scope:           realtime.Scope{Type: "server"},
			Data:            data,
			DeliveryPolicy:  realtime.StateDeliveryUserTargeted,
			RecipientUserID: userID,
		})
	}
	return events, nil
}

// uniqueScopes removes duplicate moderation invalidation scopes while
// preserving the deterministic order supplied by the mutation command.
func uniqueScopes(scopes []realtime.Scope) []realtime.Scope {
	seen := make(map[realtime.Scope]struct{}, len(scopes))
	unique := make([]realtime.Scope, 0, len(scopes))
	for _, scope := range scopes {
		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}
		unique = append(unique, scope)
	}
	return unique
}

// moderationMuteRemovedData builds the compact cache invalidation payload used
// when an owner transfer removes all mutes for one scope.
func moderationMuteRemovedData(scope realtime.Scope, epoch uint64) ([]byte, error) {
	return json.Marshal(struct {
		Scope           stateScope `json:"scope"`
		ModerationEpoch string     `json:"moderation_epoch"`
	}{
		Scope:           stateScopeFrom(scope),
		ModerationEpoch: strconv.FormatUint(epoch, 10),
	})
}

// stateScope is the JSON-safe scope representation used inside RBAC cache
// invalidation events. IDs use decimal text to preserve snowflake precision.
type stateScope struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// stateScopeFrom converts an internal scope to its wire-safe representation.
func stateScopeFrom(scope realtime.Scope) stateScope {
	if scope.Type == "server" {
		return stateScope{Type: "server"}
	}
	return stateScope{Type: scope.Type, ID: strconv.FormatInt(scope.ID, 10)}
}
