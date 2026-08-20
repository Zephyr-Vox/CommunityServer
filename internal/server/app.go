// Package server assembles every module into a runnable HTTP application.
package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/image"
	"zephyr.vox/server/ce/internal/oss"
	"zephyr.vox/server/ce/internal/presence"
	"zephyr.vox/server/ce/internal/protocol"
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
	presence       *presence.Presence
	objects        *oss.LocalObjectStorage
	avatar         *image.AvatarService
	connections    *realtime.ConnectionCoordinator
	voice          *voiceRuntime
	connectionAuth *auth.ConnectionAuthenticator
	upgrades       *realtime.UpgradeLimiter
	runtimeMu      sync.Mutex
	sequencer      *realtime.PostCommitSequencer
	syncStrategy   realtime.StateSyncStrategy
	lifecycleMu    sync.Mutex
	running        *appRun
	closing        bool
	echo           *echo.Echo
	logger         *slog.Logger
	dbCloseOnce    sync.Once
	dbCloseErr     error
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
	activate := auth.NewActivationManager(stores)

	// Do not let groups claim unmatched paths: an unknown route must surface
	// as a plain 404, not run the group's JWT middleware and return 401.
	// Echo itself logs rarely (one internal error path); tag those lines
	// with the [echo] module so they are identifiable like everything else.
	e := echo.NewWithConfig(echo.Config{Logger: logger.With("module", "echo"), NoGroupAutoRegister404Routes: true})
	e.Validator = validation.New()
	e.HTTPErrorHandler = api.NewErrorHandler(logger)

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
		presence:       pres,
		objects:        objects,
		avatar:         avatarSvc,
		connections:    connections,
		voice:          voice,
		connectionAuth: connectionAuth,
		upgrades:       upgrades,
		echo:           e,
		logger:         logger,
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

// Close prevents a later Run, requests the active Run's supervisor to begin its
// staged shutdown, and waits for Run to finish before it closes the database.
// It is safe to call concurrently and is idempotent. Run remains the sole owner
// of the HTTP listener and staged shutdown ordering, so Close never races an
// active handler with a direct database close.
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
	return errors.Join(a.ShutdownConnections(ctx), a.stopVoice(), a.stopRealtime(ctx), a.closeDatabase())
}

// appRun owns exactly one active Run invocation. It retains the supervisor and
// HTTP server together so App.Close can request shutdown without reaching into
// a handler or closing the database while the serving lifecycle is still live.
type appRun struct {
	supervisor *ProcessSupervisor
	server     *http.Server
	done       chan struct{}
}

// beginRun claims App's one process lifetime and creates its root supervisor.
// A returned appRun remains registered until finishRun signals done.
func (a *App) beginRun(parent context.Context) (*appRun, error) {
	if a == nil {
		return nil, errors.New("server: nil application")
	}
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if a.closing {
		return nil, errors.New("server: application is closed")
	}
	if a.running != nil {
		return nil, errors.New("server: application is already running")
	}
	running := &appRun{supervisor: NewProcessSupervisor(parent), done: make(chan struct{})}
	a.running = running
	return running, nil
}

// setRunServer records the HTTP server created by one active Run. The server is
// still stopped by Run's staged shutdown after its supervisor is canceled.
func (a *App) setRunServer(running *appRun, server *http.Server) {
	if a == nil || running == nil || server == nil {
		return
	}
	a.lifecycleMu.Lock()
	if a.running == running {
		running.server = server
	}
	a.lifecycleMu.Unlock()
}

// finishRun unregisters one completed Run after every handler, listener, and
// worker teardown phase has completed. It releases concurrent Close callers
// only after no later Run code can reach the stores.
func (a *App) finishRun(running *appRun) {
	if a == nil || running == nil {
		return
	}
	a.lifecycleMu.Lock()
	if a.running == running {
		a.running = nil
		close(running.done)
	}
	a.lifecycleMu.Unlock()
}

// ShutdownConnections stops Upgrade admission, requests terminal close from
// every write pump, and waits for hijacked WebSocket handlers to exit. On an
// expired deadline it force-closes raw sockets, then gives their handlers a
// short final drain window before returning the deadline failure.
func (a *App) ShutdownConnections(ctx context.Context) error {
	if a == nil || a.connections == nil || ctx == nil {
		return errors.New("server: invalid connection shutdown")
	}
	a.connections.StopAdmission()
	a.connections.DisconnectAll(4005, "server shutdown")
	if err := a.connections.Wait(ctx); err == nil {
		return nil
	} else {
		a.connections.ForceCloseAll()
		forceCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return errors.Join(err, a.connections.Wait(forceCtx))
	}
}

// startVoice binds and starts the UDP transport after every application
// dependency has been assembled. The listener is process-wide and can only be
// started once; its unexpected read-loop return is reported to supervisor.
func (a *App) startVoice(ctx context.Context, supervisor *ProcessSupervisor) error {
	if a == nil || a.voice == nil || supervisor == nil {
		return errors.New("server: invalid voice startup")
	}
	return a.voice.Start(ctx, a.cfg.Server.Host, a.cfg.Server.VoicePort, supervisor)
}

// startRealtime builds the process-local immutable projection, ring and single
// writer before readiness. A post-commit failure invokes supervisor.Fatal so
// the process cannot continue with DB state ahead of its realtime projection.
func (a *App) startRealtime(ctx context.Context, supervisor *ProcessSupervisor) error {
	if a == nil || supervisor == nil {
		return errors.New("server: invalid realtime startup")
	}
	a.runtimeMu.Lock()
	defer a.runtimeMu.Unlock()
	if a.sequencer != nil {
		return errors.New("server: realtime already started")
	}
	state, err := realtime.NewStateStore(ctx, a.stores)
	if err != nil {
		return fmt.Errorf("server: build state store: %w", err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), nil)
	if err != nil {
		return fmt.Errorf("server: build state publication: %w", err)
	}
	sequencer, err := realtime.NewPostCommitSequencer(publication, a.stores.IDGenerator(), supervisor.Fatal)
	if err != nil {
		return fmt.Errorf("server: start post-commit sequencer: %w", err)
	}
	signer, err := realtime.NewCursorSigner(state.Current().Checkpoint().StreamEpoch)
	if err != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = sequencer.Close(shutdownCtx)
		return fmt.Errorf("server: create state cursor signer: %w", err)
	}
	strategy, err := realtime.NewFullSnapshotSyncStrategy(publication, signer, realtime.NewVisibilityResolver())
	if err != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = sequencer.Close(shutdownCtx)
		return fmt.Errorf("server: create state sync strategy: %w", err)
	}
	a.sequencer = sequencer
	a.syncStrategy = strategy
	return nil
}

// stopRealtime stops the process-local single writer after HTTP and transport
// admission have drained. It is safe before startup and after a fatal failure.
func (a *App) stopRealtime(ctx context.Context) error {
	if a == nil || ctx == nil {
		return nil
	}
	a.runtimeMu.Lock()
	sequencer := a.sequencer
	a.sequencer = nil
	a.syncStrategy = nil
	a.runtimeMu.Unlock()
	if sequencer == nil {
		return nil
	}
	return sequencer.Close(ctx)
}

// currentStateSync returns the strategy published for this Run invocation. It
// is nil before Run completes startup and after staged shutdown begins.
func (a *App) currentStateSync() realtime.StateSyncStrategy {
	if a == nil {
		return nil
	}
	a.runtimeMu.Lock()
	defer a.runtimeMu.Unlock()
	return a.syncStrategy
}

// connectionAuthenticator returns the process-owned WebSocket authentication
// validator. It exists as a method so router wiring does not expose App fields.
func (a *App) connectionAuthenticator() *auth.ConnectionAuthenticator {
	if a == nil {
		return nil
	}
	return a.connectionAuth
}

// upgradeLimiter returns the process-wide per-source WebSocket upgrade limiter.
func (a *App) upgradeLimiter() *realtime.UpgradeLimiter {
	if a == nil {
		return nil
	}
	return a.upgrades
}

// stopVoice closes the UDP listener and waits for its read/purge workers.
func (a *App) stopVoice() error {
	if a == nil || a.voice == nil {
		return nil
	}
	return a.voice.Close()
}

// closeDatabase closes the SQLite handle exactly once after the caller has
// stopped resources that may still use stores or auth caches.
func (a *App) closeDatabase() error {
	a.lifecycleMu.Lock()
	a.closing = true
	a.lifecycleMu.Unlock()
	a.dbCloseOnce.Do(func() { a.dbCloseErr = a.conn.Close() })
	return a.dbCloseErr
}

// voiceRuntime owns the transport-only protocol dependencies assembled at the
// application boundary. Voice authority remains in ConnectionCoordinator; the
// protocol Manager only owns UDP cryptographic session indexes.
type voiceRuntime struct {
	manager  *protocol.Manager
	registry *protocol.ChannelTypeRegistry
	server   *protocol.UDPServer

	closeMu   sync.Mutex
	started   bool
	closed    bool
	closeOnce sync.Once
	closeErr  error
	stopPurge func()
}

// newVoiceRuntime builds sealed-at-start protocol dependencies from validated
// configuration. No listener is bound here, allowing Run to fail atomically if
// either HTTP or UDP bind cannot be acquired.
func newVoiceRuntime(cfg config.VoiceConfig, connections *realtime.ConnectionCoordinator, now func() int64) (*voiceRuntime, error) {
	if connections == nil {
		return nil, errors.New("nil connection coordinator")
	}
	clock := func() time.Time { return time.UnixMilli(now()) }
	limits := cfg.Limits
	if limits.SessionPacketsPerSec == 0 && limits.SessionBurst == 0 && limits.GlobalIngressPacketsPerSec == 0 && limits.GlobalIngressBurst == 0 && limits.SourcePacketsPerSec == 0 && limits.SourceBurst == 0 && limits.SourceEntryLimit == 0 && limits.SourceEntryTTL == 0 {
		// Direct App construction is used by embedding and test callers that do
		// not pass through config.LoadApp. Treat an entirely omitted block like
		// config's documented defaults; any partially supplied block remains an
		// error at the protocol constructor instead of silently mixing policies.
		defaults := protocol.DefaultIngressLimits()
		sessionDefaults := protocol.DefaultLimits()
		limits.GlobalIngressPacketsPerSec = defaults.GlobalPacketsPerSec
		limits.GlobalIngressBurst = defaults.GlobalBurst
		limits.SourcePacketsPerSec = defaults.SourcePacketsPerSec
		limits.SourceBurst = defaults.SourceBurst
		limits.SourceEntryLimit = defaults.SourceEntryLimit
		limits.SourceEntryTTL = defaults.SourceEntryTTL
		limits.SessionPacketsPerSec = sessionDefaults.SessionPacketsPerSec
		limits.SessionBurst = sessionDefaults.SessionBurst
	}
	manager, err := protocol.NewManagerWithLimits(clock, protocol.Limits{
		SessionPacketsPerSec: limits.SessionPacketsPerSec,
		SessionBurst:         limits.SessionBurst,
	})
	if err != nil {
		return nil, err
	}
	connections.SetVoiceSessionDeactivator(func(userID int64, sessionID [16]byte, _ string) {
		// EOF/auth teardown must make UDP media reject immediately. A concurrent
		// staged replacement may already have removed the old session, in which
		// case Delete's not-found result is the intended idempotent no-op.
		_ = manager.Delete(sessionID, userID)
	})
	registry := protocol.NewChannelTypeRegistry()
	if err := registry.Register(1, protocol.Capabilities{Name: "mic"}); err != nil {
		return nil, err
	}
	if err := registry.Register(2, protocol.Capabilities{Name: "desktop_audio"}); err != nil {
		return nil, err
	}
	ingress := protocol.IngressLimits{
		GlobalPacketsPerSec: limits.GlobalIngressPacketsPerSec,
		GlobalBurst:         limits.GlobalIngressBurst,
		SourcePacketsPerSec: limits.SourcePacketsPerSec,
		SourceBurst:         limits.SourceBurst,
		SourceEntryLimit:    limits.SourceEntryLimit,
		SourceEntryTTL:      limits.SourceEntryTTL,
	}
	// Frame relay and staged membership delivery are installed by the channel
	// authority adapter. Until then validated UDP media is deliberately dropped;
	// the transport still applies its hard ingress/session limits.
	server, err := protocol.NewUDPServer(manager, registry, nil, ingress)
	if err != nil {
		return nil, err
	}
	manager.SetRevocationHandler(server.HandleRevocation)
	return &voiceRuntime{manager: manager, registry: registry, server: server}, nil
}

// EnsureActivationCode makes sure a first-owner activation code exists. ok
// reports whether a code is pending; the plaintext is non-empty only on the
// first call, because the manager keeps only the SHA-256 digest afterwards.
// The caller must log the plaintext when it first appears.
func (a *App) EnsureActivationCode(ctx context.Context) (code string, ok bool, err error) {
	return a.activate.EnsureCode(ctx)
}
