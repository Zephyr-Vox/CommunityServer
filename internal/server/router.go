package server

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/image"
	"zephyr.vox/server/ce/internal/presence"
	"zephyr.vox/server/ce/internal/rbac"
	rbaccontrol "zephyr.vox/server/ce/internal/rbac/control"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
)

// routes mounts every endpoint on e. Groups mirror URL prefixes only; each
// route declares the middleware it needs, so public routes are explicit
// rather than the default. Authed routes attach jwtMW + authnMW via authed,
// and permission-protected routes add the matching Require middleware.
func (a *App) routes(e *echo.Echo) error {
	// Global access log: runs for matched routes and for unknown paths, so
	// 404s are visible too.
	e.Use(a.requestLogging())

	// Public avatar reads: no AuthN, streamed from the avatars bucket.
	publicAvatar, err := a.objects.GetHandler(image.AvatarBucket)
	if err != nil {
		return err
	}
	e.GET("/avatar/:file", publicAvatar)

	jwtMW := echojwt.WithConfig(echojwt.Config{
		SigningKey:    []byte(a.cfg.JWTSecret),
		NewClaimsFunc: func(c *echo.Context) jwt.Claims { return &auth.Claims{} },
	})
	authnMW := rbacecho.AuthN(auth.NewPrincipalResolver(a.principals))
	authz := rbac.NewAuthorizer(a.stores.Roles)
	rbacSvc := rbaccontrol.NewService(a.stores, a.principals)

	// authed wraps the standard authentication chain; extra middleware (e.g.
	// permission checks) runs after it.
	authed := func(extra ...echo.MiddlewareFunc) []echo.MiddlewareFunc {
		return append([]echo.MiddlewareFunc{jwtMW, authnMW}, extra...)
	}

	api := e.Group("/api/v0")
	authGroup := api.Group("/auth")
	authGroup.GET("/status", auth.StatusHandler(a.stores, auth.RegistrationMode(a.cfg.RegistrationMode)))
	authGroup.POST("/register", auth.RegisterHandler(a.register), auth.IPRateLimit(a.cfg.LoginRateLimit))
	authGroup.POST("/login", auth.LoginHandler(a.authSvc), auth.IPRateLimit(a.cfg.LoginRateLimit))
	authGroup.POST("/refresh", auth.RefreshHandler(a.authSvc))
	authGroup.POST("/logout", auth.LogoutHandler(a.authSvc))
	authGroup.GET("/me", auth.MeHandler(a.stores.Users, authz), authed()...)

	me := api.Group("/me")
	me.PATCH("", auth.MeProfileHandler(a.users), authed()...)
	me.POST("/avatar", image.UploadAvatarHandler(a.avatar), authed()...)
	me.DELETE("/avatar", image.DeleteAvatarHandler(a.avatar), authed()...)
	me.POST("/password", auth.MePasswordHandler(a.authSvc), authed()...)

	presenceGroup := api.Group("/presence")
	presenceGroup.POST("/heartbeat", presence.HeartbeatHandler(a.presence), authed()...)
	presenceGroup.GET("", presence.QueryHandler(a.presence), authed()...)

	users := api.Group("/users")
	users.GET("", auth.ListUsersHandler(a.users), authed(rbacecho.Require(authz, rbac.PermUserRead))...)
	users.GET("/:id", auth.GetUserHandler(a.users), authed(rbacecho.Require(authz, rbac.PermUserRead))...)
	users.PATCH("/:id", auth.UpdateUserHandler(a.users), authed(rbacecho.Require(authz, rbac.PermUserUpdate))...)
	users.POST("/:id/password", auth.ResetUserPasswordHandler(a.authSvc), authed(rbacecho.Require(authz, rbac.PermUserUpdate))...)
	users.POST("/:id/kick", auth.KickUserHandler(a.users), authed(rbacecho.Require(authz, rbac.PermUserKick))...)
	users.POST("/:id/ban", auth.BanUserHandler(a.users), authed(rbacecho.Require(authz, rbac.PermUserUpdate))...)
	users.POST("/:id/unban", auth.UnbanUserHandler(a.users), authed(rbacecho.Require(authz, rbac.PermUserUpdate))...)
	users.DELETE("/:id", auth.DeleteUserHandler(a.users), authed(rbacecho.Require(authz, rbac.PermUserDelete))...)

	rbacGroup := api.Group("/rbac")
	rbacGroup.GET("/roles", rbaccontrol.ListRolesHandler(rbacSvc), authed()...)
	rbacGroup.POST("/roles", rbaccontrol.CreateRoleHandler(rbacSvc), authed(rbacecho.Require(authz, rbac.PermRoleManage))...)
	rbacGroup.PATCH("/roles/:key", rbaccontrol.UpdateRoleHandler(rbacSvc), authed(rbacecho.Require(authz, rbac.PermRoleManage))...)
	rbacGroup.DELETE("/roles/:key", rbaccontrol.DeleteRoleHandler(rbacSvc), authed(rbacecho.Require(authz, rbac.PermRoleManage))...)
	rbacGroup.GET("/bindings", rbaccontrol.ListBindingsHandler(rbacSvc), authed(rbacecho.Require(authz, rbac.PermRoleManage))...)
	rbacGroup.POST("/bindings", rbaccontrol.CreateBindingHandler(rbacSvc), authed(rbacecho.Require(authz, rbac.PermRoleManage))...)
	rbacGroup.DELETE("/bindings/:id", rbaccontrol.DeleteBindingHandler(rbacSvc), authed(rbacecho.Require(authz, rbac.PermRoleManage))...)
	rbacGroup.GET("/config", rbaccontrol.GetConfigHandler(rbacSvc), authed(rbacecho.Require(authz, rbac.PermRoleManage))...)
	rbacGroup.PUT("/config", rbaccontrol.UpdateConfigHandler(rbacSvc), authed(rbacecho.Require(authz, rbac.PermRoleManage))...)
	rbacGroup.POST("/config/reset", rbaccontrol.ResetConfigHandler(rbacSvc), authed(rbacecho.Require(authz, rbac.PermRoleManage))...)

	owner := api.Group("/owner")
	owner.POST("/transfer", rbaccontrol.TransferOwnerHandler(rbacSvc), authed(rbacecho.Require(authz, rbac.PermRoleManage))...)

	admin := api.Group("/admin")
	admin.POST("/activate", auth.ActivateHandler(a.activate), auth.IPRateLimit(a.cfg.LoginRateLimit))
	admin.GET("/invites", auth.InviteListHandler(a.invites), authed(rbacecho.Require(authz, rbac.PermInviteManage))...)
	admin.POST("/invites", auth.InviteCreateHandler(a.invites), authed(rbacecho.Require(authz, rbac.PermInviteManage))...)
	admin.DELETE("/invites/:id", auth.InviteDeleteHandler(a.invites), authed(rbacecho.Require(authz, rbac.PermInviteManage))...)
	return nil
}

// logRoutes prints the mounted route table: one INFO summary and one DEBUG
// line per route. Echo v5 removed the v4 e.Routes() helper, so the table is
// read from the router; the full list only appears at debug level because it
// is startup diagnostics, not daily operational output.
func (a *App) logRoutes() {
	routes := a.echo.Router().Routes()
	log := a.logger.With("module", "router")
	log.Info(fmt.Sprintf("registered %d routes", len(routes)))
	for _, r := range routes {
		log.Debug("route " + r.Method + " " + r.Path)
	}
}
