// Package server assembles every module into a runnable HTTP application.
package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/image"
	"zephyr.vox/server/ce/internal/oss"
	"zephyr.vox/server/ce/internal/presence"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
	"zephyr.vox/server/ce/internal/validation"
)

// App is the fully assembled HTTP application: database, stores, services,
// middleware and every route.
type App struct {
	cfg        *config.App
	roles      *config.Roles
	conn       *sql.DB
	stores     *store.Stores
	principals *auth.PrincipalCache
	authSvc    *auth.AuthService
	register   *auth.RegisterService
	users      *auth.UserService
	invites    *auth.InviteService
	activate   *auth.ActivationManager
	presence   *presence.Presence
	objects    *oss.LocalObjectStorage
	avatar     *image.AvatarService
	echo       *echo.Echo
	logger     *slog.Logger
}

// New assembles the application from validated configuration and the role
// configuration: it opens the database, applies the embedded schema, wires
// every service and mounts all routes. Call Close when done.
func New(cfg *config.App, roles *config.Roles, logger *slog.Logger) (*App, error) {
	if logger == nil {
		return nil, errors.New("server: logger must not be nil")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Server.DBPath), 0o755); err != nil {
		return nil, fmt.Errorf("server: create db dir: %w", err)
	}
	conn, err := store.Open(cfg.Server.DBPath)
	if err != nil {
		return nil, fmt.Errorf("server: open db: %w", err)
	}
	if _, err := conn.Exec(db.SchemaSQL); err != nil {
		conn.Close()
		return nil, fmt.Errorf("server: apply schema: %w", err)
	}

	idGen, err := snowflake.New()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("server: snowflake: %w", err)
	}
	now := func() int64 { return time.Now().UnixMilli() }
	stores := store.New(conn, idGen, now)

	principals := auth.NewPrincipalCache(stores, time.Minute)
	secret := []byte(cfg.JWTSecret)
	authSvc := auth.NewAuthService(stores, principals, secret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, now)
	register := auth.NewRegisterService(stores, roles, auth.RegistrationMode(cfg.RegistrationMode))
	pres := presence.New(time.Now)
	objects, err := oss.NewLocalObjectStorage(cfg.Storage.BaseDir, conn, now)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("server: object storage: %w", err)
	}
	avatarSvc := image.NewAvatarService(stores.Users, objects, idGen, cfg.Avatar)
	users := auth.NewUserService(stores, roles, principals, pres, avatarSvc)
	invites := auth.NewInviteService(stores, roles, now)
	activate := auth.NewActivationManager(stores)

	// Do not let groups claim unmatched paths: an unknown route must surface
	// as a plain 404, not run the group's JWT middleware and return 401.
	// Echo itself logs rarely (one internal error path); tag those lines
	// with the [echo] module so they are identifiable like everything else.
	e := echo.NewWithConfig(echo.Config{Logger: logger.With("module", "echo"), NoGroupAutoRegister404Routes: true})
	e.Validator = validation.New()
	e.HTTPErrorHandler = api.NewErrorHandler(logger)

	app := &App{
		cfg:        cfg,
		roles:      roles,
		conn:       conn,
		stores:     stores,
		principals: principals,
		authSvc:    authSvc,
		register:   register,
		users:      users,
		invites:    invites,
		activate:   activate,
		presence:   pres,
		objects:    objects,
		avatar:     avatarSvc,
		echo:       e,
		logger:     logger,
	}
	if err := app.routes(e); err != nil {
		conn.Close()
		return nil, fmt.Errorf("server: mount routes: %w", err)
	}
	app.logRoutes()
	return app, nil
}

// Echo returns the assembled HTTP handler, used by tests and by the cmd
// entry point to serve requests.
func (a *App) Echo() *echo.Echo {
	return a.echo
}

// Close releases the database connection.
func (a *App) Close() error {
	return a.conn.Close()
}

// EnsureActivationCode makes sure a first-admin activation code exists. ok
// reports whether a code is pending; the plaintext is non-empty only on the
// first call, because the manager keeps only the SHA-256 digest afterwards.
// The caller must log the plaintext when it first appears.
func (a *App) EnsureActivationCode(ctx context.Context) (code string, ok bool, err error) {
	return a.activate.EnsureCode(ctx)
}
