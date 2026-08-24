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
	"sync"
	"time"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/channel"
	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/image"
	"zephyr.vox/server/ce/internal/oss"
	"zephyr.vox/server/ce/internal/presence"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
	"zephyr.vox/server/ce/internal/validation"
)

// App is the fully assembled HTTP application: database, stores, services,
// middleware and every route.
type App struct {
	cfg            *config.App
	conn           *sql.DB
	stores         *store.Stores
	principals     *auth.PrincipalCache
	authSvc        *auth.AuthService
	register       *auth.RegisterService
	users          *auth.UserService
	invites        *auth.InviteService
	activate       *auth.ActivationManager
	channels       *channel.Service
	presence       *presence.Presence
	objects        *oss.LocalObjectStorage
	avatar         *image.AvatarService
	connections    *realtime.ConnectionCoordinator
	voice          *voiceRuntime
	connectionAuth *auth.ConnectionAuthenticator
	upgrades       *realtime.UpgradeLimiter
	metadata       realtime.Metadata

	runtimeMu       sync.RWMutex
	stopMu          sync.Mutex
	state           *realtime.StateStore
	publication     *realtime.StatePublication
	eventBus        *realtime.EventBus
	sequencer       *realtime.PostCommitSequencer
	syncStrategy    realtime.StateSyncStrategy
	connectionState *realtime.ConnectionStatePublisher
	mutationGate    *realtime.MutationGate
	commands        *requestAdmission

	lifecycleMu sync.Mutex
	running     *appRun
	closing     bool
	dbCloseOnce sync.Once
	dbCloseErr  error

	fatalMu       sync.RWMutex
	realtimeFatal func(error)

	echo   *echo.Echo
	logger *slog.Logger
}

// New assembles the application from validated configuration: it opens the
// database, applies the embedded schema, seeds DB-backed RBAC, wires every
// service and mounts all routes. Call Close when done.
func New(cfg *config.App, logger *slog.Logger) (*App, error) {
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
	if err := stores.SeedAndVerify(context.Background()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("server: seed installation: %w", err)
	}

	principals := auth.NewPrincipalCache(stores, time.Minute)
	secret := []byte(cfg.JWTSecret)
	authSvc := auth.NewAuthService(stores, principals, secret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, now)
	register := auth.NewRegisterService(stores, auth.RegistrationMode(cfg.RegistrationMode))
	pres := presence.New(time.Now)
	objects, err := oss.NewLocalObjectStorage(cfg.Storage.BaseDir, conn, now)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("server: object storage: %w", err)
	}
	avatarSvc := image.NewAvatarService(stores.Users, objects, idGen, cfg.Avatar)
	users := auth.NewUserService(stores, principals, pres, avatarSvc)
	connections := realtime.NewConnectionCoordinator()
	voice, err := newVoiceRuntime(cfg.Voice, connections, now)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("server: voice runtime: %w", err)
	}
	authSvc.SetConnectionRevoker(connections)
	users.SetConnectionRevoker(connections)
	connectionAuth := auth.NewConnectionAuthenticator(secret, principals, stores.Sessions, now)
	upgrades := realtime.NewUpgradeLimiter(time.Now)
	invites := auth.NewInviteService(stores, principals, now)
	activate, err := auth.NewActivationManager(stores, secret)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("server: activation manager: %w", err)
	}
	channels := channel.NewService(stores, principals)

	// Do not let groups claim unmatched paths: an unknown route must surface
	// as a plain 404, not run the group's JWT middleware and return 401.
	// Echo itself logs rarely (one internal error path); tag those lines
	// with the [echo] module so they are identifiable like everything else.
	e := echo.NewWithConfig(echo.Config{Logger: logger.With("module", "echo"), NoGroupAutoRegister404Routes: true})
	e.Validator = validation.New()
	e.HTTPErrorHandler = api.NewErrorHandler(logger)

	metadata, err := realtime.NewMetadataFromRegistry(metadataHost(cfg.Server), cfg.Server.VoicePort, voice.registry)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("server: realtime metadata: %w", err)
	}
	app := &App{
		cfg:            cfg,
		conn:           conn,
		stores:         stores,
		principals:     principals,
		authSvc:        authSvc,
		register:       register,
		users:          users,
		invites:        invites,
		activate:       activate,
		channels:       channels,
		presence:       pres,
		objects:        objects,
		avatar:         avatarSvc,
		connections:    connections,
		voice:          voice,
		connectionAuth: connectionAuth,
		upgrades:       upgrades,
		metadata:       metadata,
		mutationGate:   realtime.NewMutationGate(),
		commands:       newRequestAdmission(),
		echo:           e,
		logger:         logger,
	}
	app.realtimeFatal = func(fatal error) {
		logger.Error("realtime sequencer failed before server run", "module", "realtime", "err", fatal)
	}
	if err := app.startRealtime(context.Background()); err != nil {
		conn.Close()
		return nil, err
	}
	register.SetStateMutationGate(app.mutationGate)
	activate.SetStateMutationGate(app.mutationGate)
	users.SetStateMutationGate(app.mutationGate)
	authSvc.SetStateMutationGate(app.mutationGate)
	avatarSvc.SetStateMutationGate(app.mutationGate)
	channels.SetStateMutationGate(app.mutationGate)
	channels.SetStateCommandRuntime(app.state, app.sequencer)
	if cursors, ok := app.syncStrategy.(realtime.StateCursorIssuer); ok {
		channels.SetStateCursorIssuer(cursors)
	}
	register.SetStateChangePublisher(app.publishAccountChange)
	activate.SetStateChangePublisher(app.publishAccountChange)
	users.SetStateChangePublisher(app.publishAccountChange)
	authSvc.SetStateChangePublisher(app.publishAccountChange)
	avatarSvc.SetStatePublisher(func(ctx context.Context, userID int64) error {
		return app.publishAccountChange(ctx, auth.StateChange{EventType: "user.updated", UserID: userID})
	})
	if err := app.routes(e); err != nil {
		_ = app.stopRealtime(context.Background())
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

// Close prevents a later Run, stops active WebSocket admission and the
// realtime worker, and finally releases the SQLite connection. It is safe to
// call concurrently and is idempotent.
func (a *App) Close() error {
	if a == nil {
		return nil
	}
	a.lifecycleMu.Lock()
	a.closing = true
	running := a.running
	a.lifecycleMu.Unlock()
	if running != nil {
		running.supervisor.BeginShutdown()
		<-running.done
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	connectionsErr := a.ShutdownConnections(ctx)
	realtimeErr := a.stopRealtime(ctx)
	if connectionsErr != nil || realtimeErr != nil {
		return errors.Join(connectionsErr, realtimeErr)
	}
	return a.closeDatabase()
}

// EnsureActivationCode makes sure a first-owner activation code exists. ok
// reports whether a code is pending; the plaintext is non-empty only on the
// first call, because the manager keeps only the SHA-256 digest afterwards.
// The caller must log the plaintext when it first appears.
func (a *App) EnsureActivationCode(ctx context.Context) (code string, ok bool, err error) {
	return a.activate.EnsureCode(ctx)
}
