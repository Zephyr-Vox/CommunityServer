package server

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/presence"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
)

// routes mounts every endpoint on e. Public endpoints sit outside the JWT
// middleware; everything else requires AuthN, and admin endpoints add the
// matching Require permission middleware.
func (a *App) routes(e *echo.Echo) {
	jwtMW := echojwt.WithConfig(echojwt.Config{
		SigningKey:    []byte(a.cfg.JWTSecret),
		NewClaimsFunc: func(c *echo.Context) jwt.Claims { return &auth.Claims{} },
	})
	authnMW := rbacecho.AuthN(auth.NewPrincipalResolver(a.principals))
	authz := rbac.NewAuthorizer(a.roles)

	api := e.Group("/api/v0")
	api.GET("/auth/status", auth.StatusHandler(a.stores, auth.RegistrationMode(a.cfg.RegistrationMode)))
	api.POST("/auth/register", auth.RegisterHandler(a.register))
	api.POST("/admin/activate", auth.ActivateHandler(a.activate), auth.LoginRateLimit(a.cfg.LoginRateLimit))
	api.POST("/auth/login", auth.LoginHandler(a.authSvc), auth.LoginRateLimit(a.cfg.LoginRateLimit))
	api.POST("/auth/refresh", auth.RefreshHandler(a.authSvc))
	api.POST("/auth/logout", auth.LogoutHandler(a.authSvc))

	protected := e.Group("/api/v0", jwtMW, authnMW)
	protected.GET("/auth/me", auth.MeHandler(a.stores.Users, authz))
	protected.PATCH("/me", auth.MeProfileHandler(a.users))
	protected.POST("/me/password", auth.MePasswordHandler(a.authSvc))
	protected.POST("/presence/heartbeat", presence.HeartbeatHandler(a.presence))
	protected.GET("/presence", presence.QueryHandler(a.presence))

	admin := e.Group("/api/v0", jwtMW, authnMW)
	admin.GET("/users", auth.ListUsersHandler(a.users), rbacecho.Require(authz, rbac.PermUserRead))
	admin.GET("/users/:id", auth.GetUserHandler(a.users), rbacecho.Require(authz, rbac.PermUserRead))
	admin.PATCH("/users/:id", auth.UpdateUserHandler(a.users), rbacecho.Require(authz, rbac.PermUserUpdate))
	admin.PUT("/users/:id/roles", auth.SetUserRolesHandler(a.users), rbacecho.Require(authz, rbac.PermUserUpdate))
	admin.POST("/users/:id/password", auth.ResetUserPasswordHandler(a.authSvc), rbacecho.Require(authz, rbac.PermUserUpdate))
	admin.POST("/users/:id/kick", auth.KickUserHandler(a.users), rbacecho.Require(authz, rbac.PermUserKick))
	admin.POST("/users/:id/ban", auth.BanUserHandler(a.users), rbacecho.Require(authz, rbac.PermUserUpdate))
	admin.POST("/users/:id/unban", auth.UnbanUserHandler(a.users), rbacecho.Require(authz, rbac.PermUserUpdate))
	admin.DELETE("/users/:id", auth.DeleteUserHandler(a.users), rbacecho.Require(authz, rbac.PermUserDelete))
	admin.GET("/admin/invites", auth.InviteListHandler(a.invites), rbacecho.Require(authz, rbac.PermInviteManage))
	admin.POST("/admin/invites", auth.InviteCreateHandler(a.invites), rbacecho.Require(authz, rbac.PermInviteManage))
	admin.DELETE("/admin/invites/:id", auth.InviteDeleteHandler(a.invites), rbacecho.Require(authz, rbac.PermInviteManage))
}
