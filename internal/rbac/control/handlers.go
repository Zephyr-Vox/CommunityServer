package control

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/store"
)

// ListRolesHandler handles GET /api/v0/rbac/roles. The route must be mounted
// behind AuthN.
//
// Errors:
//   - 1002 unauthorized: missing or invalid access token
//   - 1009 internal: unexpected server error
func ListRolesHandler(svc *Service) echo.HandlerFunc {
	return func(c *echo.Context) error {
		roles, err := svc.ListRoles(c.Request().Context())
		if err != nil {
			return err
		}
		response := make([]roleResponse, 0, len(roles))
		for i := range roles {
			response = append(response, newRoleResponse(&roles[i]))
		}
		return api.OK(c, http.StatusOK, response)
	}
}

// CreateRoleHandler handles POST /api/v0/rbac/roles. The route must be mounted
// behind AuthN and Require(role.manage).
//
// Errors:
//   - 1 invalid role key: key is reserved or violates the role-key grammar
//   - 2 rank protected: actor cannot create a peer or higher role
//   - 3 role exists: another role already has the requested key
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func CreateRoleHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidKey = 1
		codeRank       = 2
		codeExists     = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		var req createRoleRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		role, err := svc.CreateRole(c.Request().Context(), principal.UserID, req.Key, req.DisplayName, req.Rank)
		switch {
		case errors.Is(err, ErrInvalidRoleKey):
			return api.NewError(codeInvalidKey, http.StatusBadRequest, "invalid role key")
		case errors.Is(err, ErrRankProtected):
			return api.NewError(codeRank, http.StatusForbidden, "role rank is protected")
		case errors.Is(err, store.ErrConflict):
			return api.NewError(codeExists, http.StatusConflict, "role already exists")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		return api.OK(c, http.StatusCreated, newRoleResponse(role))
	})
}

// UpdateRoleHandler handles PATCH /api/v0/rbac/roles/:key. The route must be
// mounted behind AuthN and Require(role.manage).
//
// Errors:
//   - 1 empty patch: no mutable field was supplied
//   - 2 role not found
//   - 3 role protected: owner is immutable or rank policy rejects the change
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func UpdateRoleHandler(svc *Service) echo.HandlerFunc {
	const (
		codeEmptyPatch = 1
		codeNotFound   = 2
		codeProtected  = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		var req updateRoleRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		if req.DisplayName == nil && req.Rank == nil {
			return api.NewError(codeEmptyPatch, http.StatusBadRequest, "at least one field is required")
		}
		role, err := svc.UpdateRole(c.Request().Context(), principal.UserID, c.Param("key"), req.DisplayName, req.Rank)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "role not found")
		case errors.Is(err, ErrRankProtected), errors.Is(err, ErrImmutableRole):
			return api.NewError(codeProtected, http.StatusForbidden, "role is protected")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		return api.OK(c, http.StatusOK, newRoleResponse(role))
	})
}

// DeleteRoleHandler handles DELETE /api/v0/rbac/roles/:key. The route must be
// mounted behind AuthN and Require(role.manage).
//
// Errors:
//   - 1 role not found
//   - 2 role protected: built-in or peer/higher role cannot be deleted
//   - 3 role referenced: role still has a binding, ACL, config or invite reference
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func DeleteRoleHandler(svc *Service) echo.HandlerFunc {
	const (
		codeNotFound   = 1
		codeProtected  = 2
		codeReferenced = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		err := svc.DeleteRole(c.Request().Context(), principal.UserID, c.Param("key"))
		switch {
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "role not found")
		case errors.Is(err, ErrBuiltinRole), errors.Is(err, ErrRankProtected):
			return api.NewError(codeProtected, http.StatusForbidden, "role is protected")
		case errors.Is(err, store.ErrConflict):
			return api.NewError(codeReferenced, http.StatusConflict, "role is still referenced")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		return api.NoContent(c, http.StatusNoContent)
	})
}

// ListBindingsHandler handles GET /api/v0/rbac/bindings. The route must be
// mounted behind AuthN and Require(role.manage).
//
// Errors:
//   - 1 invalid pagination: limit must be 1-100 and offset non-negative
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func ListBindingsHandler(svc *Service) echo.HandlerFunc {
	const codeInvalidPagination = 1
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		limit, offset, err := bindingPagination(c)
		if err != nil {
			return api.NewError(codeInvalidPagination, http.StatusBadRequest, "invalid limit or offset")
		}
		bindings, err := svc.ListBindings(c.Request().Context(), principal.UserID, limit, offset)
		if err != nil {
			return err
		}
		response := make([]bindingResponse, 0, len(bindings))
		for i := range bindings {
			response = append(response, newBindingResponse(&bindings[i]))
		}
		return api.OK(c, http.StatusOK, response)
	})
}

// CreateBindingHandler handles POST /api/v0/rbac/bindings. The route must be
// mounted behind AuthN and Require(role.manage).
//
// Errors:
//   - 1 invalid scope: scope and scope ID do not match
//   - 2 owner protected: owner can only change through owner transfer
//   - 3 target not found: user, role or scope resource is absent
//   - 4 rank protected: actor cannot manage the target user or requested role
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func CreateBindingHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidScope = 1
		codeOwner        = 2
		codeNotFound     = 3
		codeRank         = 4
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		var req createBindingRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		binding, created, err := svc.CreateBinding(c.Request().Context(), principal.UserID, BindingInput{
			UserID:    req.UserID,
			RoleKey:   req.RoleKey,
			ScopeType: req.Scope.Type,
			ScopeID:   req.Scope.ID,
		})
		switch {
		case errors.Is(err, ErrInvalidScope):
			return api.NewError(codeInvalidScope, http.StatusBadRequest, "invalid binding scope")
		case errors.Is(err, store.ErrOwnerBindingProtected):
			return api.NewError(codeOwner, http.StatusBadRequest, "owner binding is protected")
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "binding target not found")
		case errors.Is(err, ErrRankProtected):
			return api.NewError(codeRank, http.StatusForbidden, "binding rank is protected")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		return api.OK(c, status, newBindingResponse(binding))
	})
}

// DeleteBindingHandler handles DELETE /api/v0/rbac/bindings/:id. The route
// must be mounted behind AuthN and Require(role.manage).
//
// Errors:
//   - 1 invalid binding ID
//   - 2 binding not found
//   - 3 owner protected: owner can only change through owner transfer
//   - 4 rank protected: actor cannot manage the binding target
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func DeleteBindingHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidID = 1
		codeNotFound  = 2
		codeOwner     = 3
		codeRank      = 4
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		bindingID, err := parsePositiveID(c.Param("id"))
		if err != nil {
			return api.NewError(codeInvalidID, http.StatusBadRequest, "invalid binding id")
		}
		err = svc.DeleteBinding(c.Request().Context(), principal.UserID, bindingID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "binding not found")
		case errors.Is(err, store.ErrOwnerBindingProtected):
			return api.NewError(codeOwner, http.StatusBadRequest, "owner binding is protected")
		case errors.Is(err, ErrRankProtected):
			return api.NewError(codeRank, http.StatusForbidden, "binding rank is protected")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		return api.NoContent(c, http.StatusNoContent)
	})
}

// TransferOwnerHandler handles POST /api/v0/owner/transfer. The route must be
// mounted behind AuthN and Require(role.manage); the service additionally
// verifies the caller is the current owner.
//
// Errors:
//   - 1 current owner required: actor is not the current owner
//   - 2 invalid transfer target: target is self or banned
//   - 3 target user not found
//   - 4 owner invariant: installation state is inconsistent
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func TransferOwnerHandler(svc *Service) echo.HandlerFunc {
	const (
		codeCurrentOwner = 1
		codeTarget       = 2
		codeNotFound     = 3
		codeInvariant    = 4
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		var req ownerTransferRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		err := svc.TransferOwner(c.Request().Context(), principal.UserID, req.TargetUserID)
		switch {
		case errors.Is(err, store.ErrOwnerTransferForbidden):
			return api.NewError(codeCurrentOwner, http.StatusForbidden, "current owner required")
		case errors.Is(err, store.ErrOwnerTransferTarget):
			return api.NewError(codeTarget, http.StatusBadRequest, "invalid owner transfer target")
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "target user not found")
		case errors.Is(err, store.ErrInstallationInvariant):
			return api.NewError(codeInvariant, http.StatusConflict, "owner invariant violated")
		case err != nil:
			return err
		}
		return api.OK(c, http.StatusOK, ownerTransferResponse{
			PreviousOwnerID: principal.UserID,
			NewOwnerID:      req.TargetUserID,
		})
	})
}

// GetConfigHandler handles GET /api/v0/rbac/config. The route must be mounted
// behind AuthN and Require(role.manage).
//
// Errors:
//   - 1 invalid scope: scope_type and scope_id do not match
//   - 2 scope not found
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func GetConfigHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidScope = 1
		codeNotFound     = 2
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		scope, err := configScopeFromQuery(c)
		if err != nil {
			return api.NewError(codeInvalidScope, http.StatusBadRequest, "invalid permission config scope")
		}
		config, etag, err := svc.GetConfig(c.Request().Context(), principal.UserID, scope)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "permission config scope not found")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		response, err := newPermissionConfigResponse(config)
		if err != nil {
			return err
		}
		c.Response().Header().Set("ETag", etag)
		return api.OK(c, http.StatusOK, response)
	})
}

// UpdateConfigHandler handles PUT /api/v0/rbac/config. The route must be
// mounted behind AuthN and Require(role.manage).
//
// Errors:
//   - 1 invalid scope: scope and scope ID do not match
//   - 2 precondition failed: If-Match is missing or does not match effective config
//   - 3 permission protected: request grants a permission the actor lacks
//   - 4 scope not found
//   - 5 invalid config: roles or permissions violate config constraints
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func UpdateConfigHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidScope = 1
		codePrecondition = 2
		codeProtected    = 3
		codeNotFound     = 4
		codeInvalid      = 5
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		var req updateConfigRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		scope, err := configScopeFromRequest(req.Scope)
		if err != nil {
			return api.NewError(codeInvalidScope, http.StatusBadRequest, "invalid permission config scope")
		}
		config, etag, err := svc.UpdateConfig(c.Request().Context(), principal.UserID, exactIfMatch(c), ConfigInput{Scope: scope, Config: req.Config})
		switch {
		case errors.Is(err, ErrPreconditionFailed):
			return api.NewError(codePrecondition, http.StatusPreconditionFailed, "precondition failed")
		case errors.Is(err, ErrRankProtected), errors.Is(err, ErrManagementLost):
			return api.NewError(codeProtected, http.StatusForbidden, "permission grant is protected")
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "permission config scope not found")
		case errors.Is(err, store.ErrInvalidPermissionConfig):
			return api.NewError(codeInvalid, http.StatusBadRequest, "invalid permission config")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		response, err := newPermissionConfigResponse(config)
		if err != nil {
			return err
		}
		c.Response().Header().Set("ETag", etag)
		return api.OK(c, http.StatusOK, response)
	})
}

// ResetConfigHandler handles POST /api/v0/rbac/config/reset. The route must
// be mounted behind AuthN and Require(role.manage).
//
// Errors:
//   - 1 invalid scope: scope and scope ID do not match
//   - 2 precondition failed: If-Match is missing or does not match effective config
//   - 3 permission protected: reset would grant a permission the actor lacks
//   - 4 scope not found
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func ResetConfigHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidScope = 1
		codePrecondition = 2
		codeProtected    = 3
		codeNotFound     = 4
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		var req resetConfigRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		scope, err := configScopeFromRequest(req.Scope)
		if err != nil {
			return api.NewError(codeInvalidScope, http.StatusBadRequest, "invalid permission config scope")
		}
		config, etag, err := svc.ResetConfig(c.Request().Context(), principal.UserID, exactIfMatch(c), scope)
		switch {
		case errors.Is(err, ErrPreconditionFailed):
			return api.NewError(codePrecondition, http.StatusPreconditionFailed, "precondition failed")
		case errors.Is(err, ErrRankProtected), errors.Is(err, ErrManagementLost):
			return api.NewError(codeProtected, http.StatusForbidden, "permission grant is protected")
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "permission config scope not found")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		response, err := newPermissionConfigResponse(config)
		if err != nil {
			return err
		}
		c.Response().Header().Set("ETag", etag)
		return api.OK(c, http.StatusOK, response)
	})
}

// bindingPagination reads bounded pagination query parameters.
func bindingPagination(c *echo.Context) (limit, offset int64, err error) {
	limit = 50
	if raw := c.QueryParam("limit"); raw != "" {
		limit, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || limit < 1 || limit > 100 {
			return 0, 0, errors.New("invalid limit")
		}
	}
	if raw := c.QueryParam("offset"); raw != "" {
		offset, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || offset < 0 {
			return 0, 0, errors.New("invalid offset")
		}
	}
	return limit, offset, nil
}

// parsePositiveID parses a positive snowflake ID from a path parameter.
func parsePositiveID(raw string) (int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid id")
	}
	return id, nil
}

// exactIfMatch returns one exact If-Match field value. Missing or repeated
// field values deliberately fail the strong precondition inside Service.
func exactIfMatch(c *echo.Context) string {
	values := c.Request().Header.Values("If-Match")
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

// configScopeFromQuery parses the exact permission-config scope query shape.
func configScopeFromQuery(c *echo.Context) (store.ConfigScope, error) {
	scope := configScopeRequest{Type: c.QueryParam("scope_type")}
	if raw := c.QueryParam("scope_id"); raw != "" {
		id, err := parsePositiveID(raw)
		if err != nil {
			return store.ConfigScope{}, err
		}
		scope.ID = &id
	}
	return configScopeFromRequest(scope)
}

// configScopeFromRequest converts and validates a config scope DTO.
func configScopeFromRequest(scope configScopeRequest) (store.ConfigScope, error) {
	if scope.Type == "server" && scope.ID == nil {
		return store.ConfigScope{Type: scope.Type}, nil
	}
	if (scope.Type == "group" || scope.Type == "channel") && scope.ID != nil && *scope.ID > 0 {
		return store.ConfigScope{Type: scope.Type, ID: scope.ID}, nil
	}
	return store.ConfigScope{}, errors.New("invalid config scope")
}
