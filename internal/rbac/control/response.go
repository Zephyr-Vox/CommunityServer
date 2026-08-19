package control

import (
	"encoding/json"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/store"
)

// Response DTOs for the RBAC control-plane endpoints.

type roleResponse struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
	Rank        int64  `json:"rank"`
	Builtin     bool   `json:"builtin"`
	Immutable   bool   `json:"immutable"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
	Version     int64  `json:"version"`
}

type bindingScopeResponse struct {
	Type string `json:"type"`
	ID   *int64 `json:"id,omitempty"`
}

type bindingResponse struct {
	ID        int64                `json:"id"`
	UserID    int64                `json:"user_id"`
	RoleKey   string               `json:"role_key"`
	Scope     bindingScopeResponse `json:"scope"`
	CreatedAt int64                `json:"created_at"`
}

type ownerTransferResponse struct {
	PreviousOwnerID int64 `json:"previous_owner_id"`
	NewOwnerID      int64 `json:"new_owner_id"`
}

type configScopeResponse struct {
	Type string `json:"type"`
	ID   *int64 `json:"id,omitempty"`
}

type permissionConfigResponse struct {
	Scope         configScopeResponse `json:"scope"`
	Local         map[string][]string `json:"local"`
	LocalVersion  *int64              `json:"local_version"`
	Source        configScopeResponse `json:"source"`
	SourceVersion int64               `json:"source_version"`
	Effective     map[string][]string `json:"effective"`
}

// newRoleResponse converts a persisted role to its public control-plane DTO.
func newRoleResponse(role *db.Role) roleResponse {
	return roleResponse{
		Key:         role.Key,
		DisplayName: role.DisplayName,
		Rank:        role.Rank,
		Builtin:     role.Builtin == 1,
		Immutable:   role.Immutable == 1,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
		Version:     role.Version,
	}
}

// newBindingResponse converts a persisted binding to its public DTO.
func newBindingResponse(binding *db.UserRoleBinding) bindingResponse {
	var scopeID *int64
	if binding.GroupID.Valid {
		id := binding.GroupID.Int64
		scopeID = &id
	}
	if binding.ChannelID.Valid {
		id := binding.ChannelID.Int64
		scopeID = &id
	}
	return bindingResponse{
		ID:      binding.ID,
		UserID:  binding.UserID,
		RoleKey: binding.RoleKey,
		Scope: bindingScopeResponse{
			Type: binding.ScopeType,
			ID:   scopeID,
		},
		CreatedAt: binding.CreatedAt,
	}
}

// newPermissionConfigResponse converts local/effective config rows to the
// public control-plane shape. A nil Local and LocalVersion means inheritance.
func newPermissionConfigResponse(config *store.EffectiveConfig) (permissionConfigResponse, error) {
	effective, err := decodePermissionConfig(config.Source.Config)
	if err != nil {
		return permissionConfigResponse{}, err
	}
	response := permissionConfigResponse{
		Scope:         newConfigScopeResponse(config.Scope.Type, config.Scope.ID),
		Source:        newConfigScopeResponseFromRow(config.Source),
		SourceVersion: config.Source.Version,
		Effective:     effective,
	}
	if config.Local != nil {
		local, err := decodePermissionConfig(config.Local.Config)
		if err != nil {
			return permissionConfigResponse{}, err
		}
		version := config.Local.Version
		response.Local = local
		response.LocalVersion = &version
	}
	return response, nil
}

// newConfigScopeResponseFromRow converts a persisted config row's scope.
func newConfigScopeResponseFromRow(config db.ScopePermissionConfig) configScopeResponse {
	if config.GroupID.Valid {
		id := config.GroupID.Int64
		return newConfigScopeResponse(config.ScopeType, &id)
	}
	if config.ChannelID.Valid {
		id := config.ChannelID.Int64
		return newConfigScopeResponse(config.ScopeType, &id)
	}
	return newConfigScopeResponse(config.ScopeType, nil)
}

// newConfigScopeResponse converts a scope type and optional ID to its DTO.
func newConfigScopeResponse(scopeType string, id *int64) configScopeResponse {
	return configScopeResponse{Type: scopeType, ID: id}
}

// decodePermissionConfig decodes canonical persisted JSON for API output.
func decodePermissionConfig(raw string) (map[string][]string, error) {
	var config map[string][]string
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return nil, err
	}
	return config, nil
}
