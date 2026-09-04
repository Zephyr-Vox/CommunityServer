package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/protocol"
	"zephyr.vox/server/ce/internal/realtime"

	"github.com/labstack/echo/v5"
)

// requestAdmission owns ordinary HTTP mutation admission independently from
// listener lifetime. Stop linearizes with begin, after which Wait can safely
// observe every mutation that may still commit database or realtime state.
type requestAdmission struct {
	mu        sync.Mutex
	accepting bool
	wg        sync.WaitGroup
}

func newRequestAdmission() *requestAdmission {
	return &requestAdmission{accepting: true}
}

func (a *requestAdmission) begin() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.accepting {
		return false
	}
	a.wg.Add(1)
	return true
}

func (a *requestAdmission) done() { a.wg.Done() }

func (a *requestAdmission) stop() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.accepting = false
	a.mu.Unlock()
}

func (a *requestAdmission) wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// commandAdmissionMiddleware tracks only mutation methods. Read-only metadata,
// snapshots and resource GETs remain available while graceful drain begins.
func (a *App) commandAdmissionMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			switch c.Request().Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				if !a.commands.begin() {
					return echo.NewHTTPError(http.StatusServiceUnavailable, "server shutting down")
				}
				defer a.commands.done()
			}
			return next(c)
		}
	}
}

// appRun owns exactly one active Run invocation. It retains the supervisor and
// HTTP server together so App.Close can request shutdown without racing an
// active handler with a direct database close.
type appRun struct {
	supervisor *ProcessSupervisor
	server     *http.Server
	done       chan struct{}
}

// metadataHost returns the already-validated public endpoint host. Direct App
// construction in tests predates advertised_host, so a non-wildcard listener is
// a safe local fallback; wildcard listeners must have an explicit value.
func metadataHost(cfg config.ServerConfig) string {
	if cfg.AdvertisedHost != "" {
		return cfg.AdvertisedHost
	}
	if cfg.Host == "0.0.0.0" || cfg.Host == "::" || cfg.Host == "[::]" {
		return "localhost"
	}
	return cfg.Host
}

// beginRun claims App's one serving lifecycle and creates its root supervisor.
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
	a.setRealtimeFatal(running.supervisor.Fatal)
	a.runtimeMu.RLock()
	sequencer := a.sequencer
	a.runtimeMu.RUnlock()
	if sequencer != nil {
		running.supervisor.Go("realtime sequencer", func(ctx context.Context) error {
			<-sequencer.Done()
			if ctx.Err() != nil {
				return nil
			}
			if err := sequencer.Failure(); err != nil {
				return err
			}
			return errors.New("server: realtime sequencer stopped unexpectedly")
		})
		// The idle/command-completion heartbeat goes silent while the single
		// writer is stuck inside one command or publication phase, which is the
		// spec's stall signal for root cancellation.
		running.supervisor.WatchProgress("sequencer", sequencer.Progress(), sequencerWatchdogTimeout)
	}
	return running, nil
}

// setRunServer records the HTTP server created by one active Run.
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

// finishRun unregisters a completed Run after all resources have stopped.
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
	a.setRealtimeFatal(func(fatal error) {
		a.logger.Error("realtime sequencer failed after server run", "module", "realtime", "err", fatal)
	})
}

// ShutdownConnections stops WebSocket admission, requests terminal close from
// every write pump, and waits for hijacked handlers to exit.
func (a *App) ShutdownConnections(ctx context.Context) error {
	if a == nil || a.connections == nil || ctx == nil {
		return errors.New("server: invalid connection shutdown")
	}
	a.commands.stop()
	commandsErr := a.commands.wait(ctx)
	if a.voice != nil {
		a.voice.beginStopping()
	}
	a.connections.StopAdmission()
	a.connections.SetCloseObserver(nil)
	a.connections.SetVoiceAuthorityObserver(nil)
	a.connections.DisconnectAll(4005, "server shutdown")
	if err := a.connections.Wait(ctx); err == nil {
		return commandsErr
	} else {
		a.connections.ForceCloseAll()
		forceCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return errors.Join(commandsErr, err, a.connections.Wait(forceCtx))
	}
}

// startRealtime constructs the immutable state projection, cursor signer,
// EventBus and single writer before any route can expose state synchronization.
func (a *App) startRealtime(ctx context.Context) error {
	if a == nil {
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
	visibility := realtime.NewVisibilityResolver()
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), visibility, nil)
	if err != nil {
		return fmt.Errorf("server: build state publication: %w", err)
	}
	signer, err := realtime.NewCursorSigner(state.Current().Checkpoint().StreamEpoch)
	if err != nil {
		return fmt.Errorf("server: create state cursor signer: %w", err)
	}
	eventBus, err := realtime.NewEventBus(signer, visibility)
	if err != nil {
		return fmt.Errorf("server: create event bus: %w", err)
	}
	strategy, err := realtime.NewFullSnapshotSyncStrategy(publication, signer, visibility, eventBus)
	if err != nil {
		eventBus.Close()
		return fmt.Errorf("server: create state sync strategy: %w", err)
	}
	sequencer, err := realtime.NewPostCommitSequencer(publication, a.stores.IDGenerator(), a.reportRealtimeFatal)
	if err != nil {
		eventBus.Close()
		return fmt.Errorf("server: start post-commit sequencer: %w", err)
	}
	connectionState, err := realtime.NewConnectionStatePublisher(state, sequencer, a.connections)
	if err != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = sequencer.Close(shutdownCtx)
		eventBus.Close()
		return fmt.Errorf("server: create connection state publisher: %w", err)
	}
	connectionState.SetConnectionLeaseValidator(func(ctx context.Context, ref realtime.ControlConnectionRef) (func(), error) {
		release, err := a.connectionAuth.AcquireCurrent(ctx, ref.UserID, ref.LoginSessionID)
		if errors.Is(err, auth.ErrUserBanned) || errors.Is(err, auth.ErrLoginSessionInvalid) || errors.Is(err, auth.ErrTokenRevoked) {
			return nil, fmt.Errorf("%w: %v", realtime.ErrConnectionUnauthorized, err)
		}
		return release, err
	})
	connectionState.SetRuntimeMutationAdmission(a.mutationGate)
	a.state = state
	a.publication = publication
	a.eventBus = eventBus
	a.sequencer = sequencer
	a.syncStrategy = strategy
	a.connectionState = connectionState
	return nil
}

// stopRealtime closes the sequencer after HTTP and connection admission have
// drained, then prevents later subscribers from using the EventBus.
func (a *App) stopRealtime(ctx context.Context) error {
	if a == nil || ctx == nil {
		return nil
	}
	a.stopMu.Lock()
	defer a.stopMu.Unlock()
	a.runtimeMu.Lock()
	sequencer := a.sequencer
	eventBus := a.eventBus
	connectionState := a.connectionState
	deadlines := a.deadlines
	a.syncStrategy = nil
	a.runtimeMu.Unlock()
	if a.connections != nil {
		a.connections.SetCloseObserver(nil)
		a.connections.SetVoiceAuthorityObserver(nil)
	}
	if connectionState != nil {
		if err := connectionState.Close(ctx); err != nil {
			return err
		}
	}
	if deadlines != nil {
		if err := deadlines.Close(ctx); err != nil {
			return err
		}
	}
	if sequencer != nil {
		if err := sequencer.Close(ctx); err != nil {
			return err
		}
	}
	if eventBus != nil {
		eventBus.Close()
	}
	a.runtimeMu.Lock()
	if a.sequencer == sequencer {
		a.state = nil
		a.publication = nil
		a.eventBus = nil
		a.sequencer = nil
		a.connectionState = nil
	}
	a.runtimeMu.Unlock()
	return nil
}

// currentStateSync returns the strategy published for the current process
// epoch. It becomes nil only after realtime shutdown begins.
func (a *App) currentStateSync() realtime.StateSyncStrategy {
	if a == nil {
		return nil
	}
	a.runtimeMu.RLock()
	defer a.runtimeMu.RUnlock()
	return a.syncStrategy
}

// realtimeComponents returns the live command/runtime dependencies as one
// coherent application-owned bundle. Callers must not retain the result across
// shutdown; route handlers only use it for one bounded request.
func (a *App) realtimeComponents() (*realtime.StateStore, *realtime.PostCommitSequencer, bool) {
	if a == nil {
		return nil, nil, false
	}
	a.runtimeMu.RLock()
	defer a.runtimeMu.RUnlock()
	return a.state, a.sequencer, a.state != nil && a.sequencer != nil
}

// connectionAuthenticator returns the process-owned WebSocket authentication
// adapter without exposing auth package details to realtime.
func (a *App) connectionAuthenticator() realtime.WebSocketAuthenticator {
	if a == nil || a.connectionAuth == nil {
		return nil
	}
	return authWebSocketAuthenticator{authenticator: a.connectionAuth}
}

// connectionStatePublisher returns the current lifecycle-to-publication bridge
// used by WebSocket handlers after upgrade.
func (a *App) connectionStatePublisher() realtime.ControlConnectionPublisher {
	if a == nil {
		return nil
	}
	a.runtimeMu.RLock()
	defer a.runtimeMu.RUnlock()
	return a.connectionState
}

// upgradeLimiter returns the process-wide source-IP upgrade limiter.
func (a *App) upgradeLimiter() *realtime.UpgradeLimiter {
	if a == nil {
		return nil
	}
	return a.upgrades
}

// setRealtimeFatal replaces the process-level fatal callback used by the
// sequencer after a post-commit failure.
func (a *App) setRealtimeFatal(fn func(error)) {
	if a == nil || fn == nil {
		return
	}
	a.fatalMu.Lock()
	a.realtimeFatal = fn
	a.fatalMu.Unlock()
}

// reportRealtimeFatal forwards one sequencer failure to the current process
// supervisor without holding runtime locks.
func (a *App) reportRealtimeFatal(err error) {
	a.fatalMu.RLock()
	fatal := a.realtimeFatal
	a.fatalMu.RUnlock()
	if fatal != nil {
		fatal(err)
	}
}

// stopVoice closes the configured UDP transport. It is safe when Run never
// bound the listener because voiceRuntime.Close is idempotent.
func (a *App) stopVoice() error {
	if a == nil || a.voice == nil {
		return nil
	}
	return a.voice.Close()
}

// closeDatabase closes SQLite exactly once after every worker that can use a
// store has stopped.
func (a *App) closeDatabase() error {
	if a == nil {
		return nil
	}
	a.lifecycleMu.Lock()
	a.closing = true
	a.lifecycleMu.Unlock()
	a.dbCloseOnce.Do(func() { a.dbCloseErr = a.conn.Close() })
	return a.dbCloseErr
}

// voiceRuntime owns transport-only voice dependencies assembled at the
// application boundary. Channel authority remains outside protocol.Manager.
type voiceRuntime struct {
	manager     *protocol.Manager
	registry    *protocol.ChannelTypeRegistry
	server      *protocol.UDPServer
	revocations chan protocol.RevocationCleanup
	expiries    chan voiceExpiry
	connections *realtime.ConnectionCoordinator
	fatal       func(error)

	closeMu   sync.Mutex
	started   bool
	closed    bool
	stopped   bool
	closeOnce sync.Once
	closeErr  error
	stopPurge func()
}

type voiceExpiry struct {
	userID    int64
	sessionID [16]byte
}

// beginStopping marks the voice runtime as intentionally shutting down. After
// this point a full cleanup reserve degrades to a silent drop because
// best-effort UDP notifications are never required for teardown convergence.
func (v *voiceRuntime) beginStopping() {
	if v == nil {
		return
	}
	v.closeMu.Lock()
	v.stopped = true
	v.closeMu.Unlock()
}

// stopping reports whether intentional teardown has begun.
func (v *voiceRuntime) stopping() bool {
	if v == nil {
		return false
	}
	v.closeMu.Lock()
	defer v.closeMu.Unlock()
	return v.stopped
}

// fail reports a voice lifecycle failure to the process supervisor when the
// runtime has been started. Before Run, construction failures are returned by
// the caller directly and no asynchronous worker exists yet. An intentional
// shutdown swallows late reserve pressure instead of faking a fatal cause.
func (v *voiceRuntime) fail(err error) {
	if v == nil || err == nil {
		return
	}
	v.closeMu.Lock()
	fatal := v.fatal
	stopping := v.stopped
	v.closeMu.Unlock()
	if fatal != nil && !stopping {
		fatal(err)
	}
}

// newVoiceRuntime builds the protocol dependencies without binding UDP. Run
// owns listener startup once channel authority has been assembled.
func newVoiceRuntime(cfg config.VoiceConfig, connections *realtime.ConnectionCoordinator, now func() int64) (*voiceRuntime, error) {
	if connections == nil || now == nil {
		return nil, errors.New("nil voice runtime dependency")
	}
	clock := func() time.Time { return time.UnixMilli(now()) }
	limits := cfg.Limits
	if limits.SessionPacketsPerSec == 0 && limits.SessionBurst == 0 && limits.GlobalIngressPacketsPerSec == 0 && limits.GlobalIngressBurst == 0 && limits.SourcePacketsPerSec == 0 && limits.SourceBurst == 0 && limits.SourceEntryLimit == 0 && limits.SourceEntryTTL == 0 {
		ingressDefaults := protocol.DefaultIngressLimits()
		sessionDefaults := protocol.DefaultLimits()
		limits.GlobalIngressPacketsPerSec = ingressDefaults.GlobalPacketsPerSec
		limits.GlobalIngressBurst = ingressDefaults.GlobalBurst
		limits.SourcePacketsPerSec = ingressDefaults.SourcePacketsPerSec
		limits.SourceBurst = ingressDefaults.SourceBurst
		limits.SourceEntryLimit = ingressDefaults.SourceEntryLimit
		limits.SourceEntryTTL = ingressDefaults.SourceEntryTTL
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
	registry := protocol.NewChannelTypeRegistry()
	if err := registry.Register(1, protocol.Capabilities{Name: "mic", MuteKind: "voice"}); err != nil {
		return nil, err
	}
	if err := registry.Register(2, protocol.Capabilities{Name: "desktop_audio", MuteKind: "desktop_audio"}); err != nil {
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
	server, err := protocol.NewUDPServer(manager, registry, nil, ingress)
	if err != nil {
		return nil, err
	}
	manager.SetRevocationHandler(server.HandleRevocation)
	runtime := &voiceRuntime{
		manager:     manager,
		registry:    registry,
		server:      server,
		revocations: make(chan protocol.RevocationCleanup, realtime.MaxControlTeardownQueueItems),
		expiries:    make(chan voiceExpiry, realtime.MaxControlTeardownQueueItems),
		connections: connections,
	}
	connections.SetVoiceAuthorityDeactivator(func(authority realtime.VoiceAuthority, _ string) {
		cleanup, err := manager.RevokeStaged(authority.VoiceSessionID, authority.UserID)
		if err != nil && !errors.Is(err, protocol.ErrSessionNotFound) {
			runtime.fail(fmt.Errorf("voice revoke: %w", err))
			return
		}
		if cleanup == nil {
			return
		}
		select {
		case runtime.revocations <- cleanup:
		default:
			runtime.fail(errors.New("voice revoke cleanup reserve exhausted"))
		}
	})
	manager.SetExpiryHandler(func(userID int64, sessionID [16]byte) {
		select {
		case runtime.expiries <- voiceExpiry{userID: userID, sessionID: sessionID}:
		default:
			runtime.fail(errors.New("voice expiry cleanup reserve exhausted"))
		}
	})
	return runtime, nil
}

// authWebSocketAuthenticator adapts auth.ConnectionAuthenticator to the small
// realtime interface, keeping auth's token/session types out of the realtime
// dependency graph.
type authWebSocketAuthenticator struct {
	authenticator *auth.ConnectionAuthenticator
}

// Authenticate validates token and maps the authenticated identity.
func (a authWebSocketAuthenticator) Authenticate(ctx context.Context, token string, reserve func(realtime.WebSocketIdentity) error) (realtime.WebSocketIdentity, error) {
	identity, err := a.authenticator.Authenticate(ctx, token, func(identity auth.ConnectionAuth) error {
		return reserve(realtime.WebSocketIdentity{UserID: identity.UserID, LoginSessionID: identity.LoginSessionID, AccessExpiresAt: identity.AccessExpiresAt})
	})
	if err != nil {
		return realtime.WebSocketIdentity{}, err
	}
	return realtime.WebSocketIdentity{UserID: identity.UserID, LoginSessionID: identity.LoginSessionID, AccessExpiresAt: identity.AccessExpiresAt}, nil
}

// UpdateLease validates a same-user, same-session token update and maps its
// new expiration to realtime.
func (a authWebSocketAuthenticator) UpdateLease(ctx context.Context, token string, userID, loginSessionID int64, update func(realtime.WebSocketIdentity) error) (realtime.WebSocketIdentity, error) {
	identity, err := a.authenticator.UpdateLease(ctx, token, userID, loginSessionID, func(identity auth.ConnectionAuth) error {
		return update(realtime.WebSocketIdentity{UserID: identity.UserID, LoginSessionID: identity.LoginSessionID, AccessExpiresAt: identity.AccessExpiresAt})
	})
	if err != nil {
		return realtime.WebSocketIdentity{}, err
	}
	return realtime.WebSocketIdentity{UserID: identity.UserID, LoginSessionID: identity.LoginSessionID, AccessExpiresAt: identity.AccessExpiresAt}, nil
}
