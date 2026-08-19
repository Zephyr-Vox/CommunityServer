package control

// Request DTOs for the RBAC control-plane endpoints.

type createRoleRequest struct {
	Key         string `json:"key" validate:"required,max=64"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=64"`
	Rank        int64  `json:"rank" validate:"min=0,max=999999"`
}

type updateRoleRequest struct {
	DisplayName *string `json:"display_name" validate:"omitempty,min=1,max=64"`
	Rank        *int64  `json:"rank" validate:"omitempty,min=0,max=999999"`
}

type bindingScopeRequest struct {
	Type string `json:"type" validate:"required,oneof=server group channel"`
	ID   *int64 `json:"id" validate:"omitempty,gt=0"`
}

type createBindingRequest struct {
	UserID  int64               `json:"user_id" validate:"required,gt=0"`
	RoleKey string              `json:"role_key" validate:"required,max=64"`
	Scope   bindingScopeRequest `json:"scope" validate:"required"`
}

type ownerTransferRequest struct {
	TargetUserID int64 `json:"target_user_id" validate:"required,gt=0"`
}

type configScopeRequest struct {
	Type string `json:"type" validate:"required,oneof=server group channel"`
	ID   *int64 `json:"id" validate:"omitempty,gt=0"`
}

type updateConfigRequest struct {
	Scope  configScopeRequest  `json:"scope" validate:"required"`
	Config map[string][]string `json:"config" validate:"required"`
}

type resetConfigRequest struct {
	Scope configScopeRequest `json:"scope" validate:"required"`
}
