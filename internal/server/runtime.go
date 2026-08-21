package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/protocol"
	rbaccontrol "zephyr.vox/server/ce/internal/rbac/control"
	"zephyr.vox/server/ce/internal/realtime"
)

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
	a.runtimeMu.Lock()
	sequencer := a.sequencer
	eventBus := a.eventBus
	a.state = nil
	a.publication = nil
	a.eventBus = nil
	a.sequencer = nil
	a.syncStrategy = nil
	a.connectionState = nil
	a.runtimeMu.Unlock()
	if a.connections != nil {
		a.connections.SetCloseObserver(nil)
	}
	if eventBus != nil {
		eventBus.Close()
	}
	if sequencer == nil {
		return nil
	}
	return sequencer.Close(ctx)
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

// publishAccountChange refreshes the persistent projection after an account
// transaction has committed and emits canonical user/self event DTOs. Existing
// account services retain their domain transactions; this bridge serializes the
// following state publication before their HTTP handler reports success.
func (a *App) publishAccountChange(ctx context.Context, change auth.StateChange) error {
	if change.UserID <= 0 || (change.EventType != "user.created" && change.EventType != "user.updated" && change.EventType != "user.deleted") {
		return errors.New("server: invalid account state change")
	}
	state, sequencer, ok := a.realtimeComponents()
	if !ok {
		return errors.New("server: realtime unavailable")
	}
	_, err := sequencer.Submit(ctx, realtime.PostCommitCommand{
		QueueBytes: 1,
		Execute: func(ctx context.Context, _ int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			candidate, err := state.BuildPersistentCandidate(ctx)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			events, err := accountStateEvents(change, candidate.Version())
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			visibilityUserIDs := make([]int64, 0)
			for _, user := range candidate.Version().Users() {
				visibilityUserIDs = append(visibilityUserIDs, user.ID)
			}
			visibilityUserIDs = append(visibilityUserIDs, change.UserID)
			if _, err := execution.Reserve(realtime.PublicationRequest{
				Candidate:         candidate,
				Events:            events,
				VisibilityUserIDs: visibilityUserIDs,
			}); err != nil {
				return realtime.CommandOutput{}, err
			}
			if err := execution.MarkRuntimeReady(); err != nil {
				return realtime.CommandOutput{}, err
			}
			return realtime.CommandOutput{}, nil
		},
	})
	if err != nil {
		a.reportRealtimeFatal(fmt.Errorf("account state publication: %w", err))
	}
	return err
}

// accountStateEvents creates canonical public user data and targeted self data
// from the exact candidate that StatePublication will make visible.
func accountStateEvents(change auth.StateChange, version *realtime.StateVersion) ([]realtime.StateEventTemplate, error) {
	if change.EventType == "user.deleted" {
		data, err := json.Marshal(struct {
			UserID string `json:"user_id"`
		}{UserID: strconv.FormatInt(change.UserID, 10)})
		if err != nil {
			return nil, err
		}
		return []realtime.StateEventTemplate{{EventType: "user.deleted", Scope: realtime.Scope{Type: "server"}, Data: data}}, nil
	}
	if _, exists := version.User(change.UserID); !exists {
		return nil, errors.New("server: account missing from realtime projection")
	}
	userData, err := json.Marshal(struct {
		User realtime.SnapshotUserPresence `json:"user"`
	}{User: realtime.SnapshotUserPresenceFor(change.UserID, change.UserID, version)})
	if err != nil {
		return nil, err
	}
	events := []realtime.StateEventTemplate{{
		EventType:     change.EventType,
		Scope:         realtime.Scope{Type: "server"},
		Data:          userData,
		SubjectUserID: change.UserID,
	}}
	if change.EventType == "user.updated" {
		selfData, err := json.Marshal(struct {
			Self realtime.SnapshotSelf `json:"self"`
		}{Self: realtime.SnapshotSelfFor(change.UserID, version)})
		if err != nil {
			return nil, err
		}
		events = append(events, realtime.StateEventTemplate{
			EventType:                "self.updated",
			Scope:                    realtime.Scope{Type: "server"},
			Data:                     selfData,
			DeliveryPolicy:           realtime.StateDeliveryDirectTransition,
			RecipientUserID:          change.UserID,
			CursorVisibilityEpoch:    version.VisibilityEpoch(change.UserID),
			HasCursorVisibilityEpoch: true,
		})
	}
	return events, nil
}

// publishRBACChange refreshes the persistent projection after a committed role,
// binding, owner-transfer or permission-config mutation. It emits full role
// DTOs and targeted self.updated state for affected principals.
func (a *App) publishRBACChange(ctx context.Context, change rbaccontrol.StateChange) error {
	state, sequencer, ok := a.realtimeComponents()
	if !ok {
		return errors.New("server: realtime unavailable")
	}
	_, err := sequencer.Submit(ctx, realtime.PostCommitCommand{
		QueueBytes: 1,
		Execute: func(ctx context.Context, _ int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			candidate, err := state.BuildPersistentCandidate(ctx)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			events, err := rbacStateEvents(change, candidate.Version())
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			visibilityUserIDs := make([]int64, 0)
			for _, user := range candidate.Version().Users() {
				visibilityUserIDs = append(visibilityUserIDs, user.ID)
			}
			if _, err := execution.Reserve(realtime.PublicationRequest{
				Candidate:         candidate,
				Events:            events,
				VisibilityUserIDs: visibilityUserIDs,
			}); err != nil {
				return realtime.CommandOutput{}, err
			}
			if err := execution.MarkRuntimeReady(); err != nil {
				return realtime.CommandOutput{}, err
			}
			return realtime.CommandOutput{}, nil
		},
	})
	if err != nil {
		a.reportRealtimeFatal(fmt.Errorf("RBAC state publication: %w", err))
	}
	return err
}

// rbacStateEvents creates one canonical role/config invalidation event plus
// targeted complete self DTOs for users whose permissions may have changed.
func rbacStateEvents(change rbaccontrol.StateChange, version *realtime.StateVersion) ([]realtime.StateEventTemplate, error) {
	events := make([]realtime.StateEventTemplate, 0, 1+len(change.UserIDs))
	switch change.EventType {
	case "rbac.role.created", "rbac.role.updated":
		role, ok := version.Role(change.RoleKey)
		if !ok {
			return nil, errors.New("server: role missing from realtime projection")
		}
		data, err := json.Marshal(realtime.SnapshotRole{
			Key:         role.Key,
			DisplayName: role.DisplayName,
			Rank:        strconv.FormatInt(role.Rank, 10),
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
			Scope struct {
				Type string `json:"type"`
			} `json:"scope"`
			EntityVersion string `json:"entity_version"`
		}{Scope: struct {
			Type string `json:"type"`
		}{Type: "server"}, EntityVersion: strconv.FormatUint(version.Number(), 10)})
		if err != nil {
			return nil, err
		}
		events = append(events, realtime.StateEventTemplate{EventType: change.EventType, Scope: realtime.Scope{Type: "server"}, Data: data})
	default:
		return nil, errors.New("server: invalid RBAC state change")
	}
	for _, userID := range change.UserIDs {
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
			EventType:                "self.updated",
			Scope:                    realtime.Scope{Type: "server"},
			Data:                     data,
			DeliveryPolicy:           realtime.StateDeliveryDirectTransition,
			RecipientUserID:          userID,
			CursorVisibilityEpoch:    version.VisibilityEpoch(userID),
			HasCursorVisibilityEpoch: true,
		})
	}
	return events, nil
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
	connections.SetVoiceSessionDeactivator(func(userID int64, sessionID [16]byte, _ string) {
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
	server, err := protocol.NewUDPServer(manager, registry, nil, ingress)
	if err != nil {
		return nil, err
	}
	manager.SetRevocationHandler(server.HandleRevocation)
	return &voiceRuntime{manager: manager, registry: registry, server: server}, nil
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
