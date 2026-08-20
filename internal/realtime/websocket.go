package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/auth"
)

const (
	// MaxInboundWebSocketMessage is the fixed v1 message-size limit. It is set
	// on the underlying WebSocket before the read loop begins.
	MaxInboundWebSocketMessage = 64 << 10
	// MaxWebSocketStateItems and MaxWebSocketStateBytes bound regular
	// state/control delivery. Response and terminal lanes are reserved outside
	// this budget so a slow state consumer cannot strand a command ACK or close.
	MaxWebSocketStateItems = 256
	MaxWebSocketStateBytes = 1 << 20

	websocketHelloTimeout   = 10 * time.Second
	websocketResyncTimeout  = 30 * time.Second
	websocketPingInterval   = 20 * time.Second
	websocketLivenessWindow = 60 * time.Second
	websocketWriteDeadline  = 10 * time.Second
	websocketCommandTimeout = 10 * time.Second
	websocketCommandRate    = 20.0
	websocketCommandBurst   = 40.0

	// MaxWebSocketResponseItems and MaxWebSocketResponseBytes reserve delivery
	// capacity for result-bearing command ACKs independently of the ordinary
	// state/control queue. A read pump does not execute such a command until it
	// owns one slot, so a slow state consumer cannot make a committed auth lease
	// lose its required command result.
	MaxWebSocketResponseItems = 16
	MaxWebSocketResponseBytes = 64 << 10

	websocketMalformedCommandLimit = 3
	websocketRateLimitCloseLimit   = 3

	websocketCloseProtocol = 4000
	websocketCloseExpired  = 4001
	websocketCloseRevoked  = 4002
	websocketCloseAbuse    = 4003
	websocketCloseSync     = 4004
	websocketCloseShutdown = 4005
	websocketCloseSlow     = 4006
)

const maxWebSocketResponseFrameBytes = MaxWebSocketResponseBytes / MaxWebSocketResponseItems

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

type syncPhase uint8

const (
	syncPhaseInitial syncPhase = iota + 1
	syncPhaseResyncRequired
	syncPhaseLive
)

// WebSocketHandler is the GET /api/v0/ws adapter. It reserves
// global/user/source admission before upgrading, authenticates and reserves
// opening state inside the principal read barrier, then maintains auth lease,
// sync-hello and liveness deadlines until the coordinator owns a terminal close
// transition. Server routes must not mount it until a StateSyncStrategy and its
// HTTP snapshot endpoint are assembled; the current server deliberately keeps
// this adapter unpublished.
func WebSocketHandler(authenticator *auth.ConnectionAuthenticator, coordinator *ConnectionCoordinator, upgrades *UpgradeLimiter, syncStrategy func() StateSyncStrategy) echo.HandlerFunc {
	return func(c *echo.Context) error {
		if authenticator == nil || coordinator == nil || upgrades == nil || syncStrategy == nil {
			return errors.New("realtime: WebSocket handler is not initialized")
		}
		strategy := syncStrategy()
		if strategy == nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "state sync unavailable")
		}
		if !coordinator.AdmissionOpen() {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "server shutting down")
		}
		sourceIP, ok := requestSourceIP(c.Request())
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid remote address")
		}
		if !upgrades.Allow(sourceIP) {
			return echo.NewHTTPError(http.StatusTooManyRequests, "websocket upgrade rate limited")
		}
		accessToken, ok := bearerAccessToken(c.Request().Header.Get(echo.HeaderAuthorization))
		if !ok {
			return echo.ErrUnauthorized
		}

		var reservation *ConnectionReservation
		identity, err := authenticator.Authenticate(c.Request().Context(), accessToken, func(identity auth.ConnectionAuth) error {
			var reserveErr error
			reservation, reserveErr = coordinator.ReserveConnectFrom(identity.UserID, identity.LoginSessionID, sourceIP)
			return reserveErr
		})
		if err != nil {
			return webSocketAuthenticationError(err)
		}
		if reservation == nil {
			return errors.New("realtime: authentication completed without a connection reservation")
		}

		conn, err := (&websocket.Upgrader{}).Upgrade(c.Response(), c.Request(), nil)
		if err != nil {
			reservation.Abort()
			return nil
		}
		pump := newWebSocketWritePump(conn)
		ref, lease, err := reservation.Activate(pump, identity.AccessExpiresAt)
		if err != nil {
			pump.RequestClose(websocketCloseRevoked, "connection revoked")
			<-pump.Done()
			reservation.Abort()
			return nil
		}
		syncConnection := &webSocketSyncConnection{ref: ref, pump: pump, coordinator: coordinator}

		conn.SetReadLimit(MaxInboundWebSocketMessage)
		if err := conn.SetReadDeadline(time.Now().Add(websocketLivenessWindow)); err != nil {
			coordinator.BeginDisconnect(ref, websocketCloseProtocol, "read deadline failure")
			<-pump.Done()
			coordinator.FinishDisconnect(ref)
			return nil
		}
		conn.SetPongHandler(func(string) error {
			return conn.SetReadDeadline(time.Now().Add(websocketLivenessWindow))
		})
		conn.SetPingHandler(func(data string) error {
			pump.RequestPong([]byte(data))
			return nil
		})
		// The writer pump sends the server's terminal close frame. Suppressing
		// Gorilla's default close echo prevents the read goroutine from becoming a
		// second concurrent socket writer.
		conn.SetCloseHandler(func(int, string) error { return nil })

		if !pump.Enqueue(webSocketReadyFrame(ref, identity.AccessExpiresAt)) {
			coordinator.BeginDisconnect(ref, websocketCloseSlow, "writer unavailable")
			<-pump.Done()
			coordinator.FinishDisconnect(ref)
			return nil
		}

		syncDeadline := newSyncDeadline(coordinator, ref)
		syncDeadline.Schedule(websocketHelloTimeout)
		leaseTimer := newAuthLeaseTimer(coordinator, ref)
		leaseTimer.Schedule(lease)
		stopPing := make(chan struct{})
		go runWebSocketPings(pump, stopPing)

		// Every exit path converges on the coordinator. The timer/ping producers
		// stop first; after the writer exits, FinishDisconnect removes only this
		// generation and releases its shutdown WaitGroup slot.
		defer func() {
			close(stopPing)
			syncDeadline.Stop()
			leaseTimer.Stop()
			strategy.OnDisconnect(ref)
			coordinator.BeginDisconnect(ref, int(websocket.CloseNormalClosure), "closed")
			<-pump.Done()
			coordinator.FinishDisconnect(ref)
		}()

		phase := syncPhaseInitial
		commands := newWebSocketCommandLimiter(time.Now)
		malformedCommands := 0
		rateLimitViolations := 0
		for {
			messageType, payload, readErr := conn.ReadMessage()
			if readErr != nil {
				if networkErr, ok := errors.AsType[net.Error](readErr); ok && networkErr.Timeout() {
					coordinator.BeginDisconnect(ref, websocketCloseProtocol, "liveness timeout")
				}
				return nil
			}
			if messageType != websocket.TextMessage {
				coordinator.BeginDisconnect(ref, websocketCloseProtocol, "protocol error")
				return nil
			}
			if lease, ok := coordinator.AuthLease(ref); !ok || coordinator.ExpireAuthLease(ref, lease, time.Now().UnixMilli()) {
				return nil
			}

			var envelope webSocketClientEnvelope
			if err := json.Unmarshal(payload, &envelope); err != nil || envelope.Type == "" {
				coordinator.BeginDisconnect(ref, websocketCloseProtocol, "protocol error")
				return nil
			}
			if err := conn.SetReadDeadline(time.Now().Add(websocketLivenessWindow)); err != nil {
				coordinator.BeginDisconnect(ref, websocketCloseProtocol, "read deadline failure")
				return nil
			}
			switch envelope.Type {
			case "sync.hello":
				if phase == syncPhaseLive {
					coordinator.BeginDisconnect(ref, websocketCloseSync, "invalid sync state")
					return nil
				}
				cursor, ok := syncHelloCursor(envelope.Data)
				if !ok {
					coordinator.BeginDisconnect(ref, websocketCloseSync, "invalid sync state")
					return nil
				}
				if !commands.Allow() {
					coordinator.BeginDisconnect(ref, websocketCloseAbuse, "command rate limited")
					return nil
				}
				result, err := strategy.OnHello(syncConnection, cursor)
				if err != nil {
					if errors.Is(err, ErrEventConsumerSlow) || errors.Is(err, ErrSyncAttemptClosed) {
						return nil
					}
					coordinator.BeginDisconnect(ref, websocketCloseProtocol, "state sync failure")
					return nil
				}
				if result.RequiredReason != "" {
					if phase == syncPhaseInitial {
						phase = syncPhaseResyncRequired
						syncDeadline.Schedule(websocketResyncTimeout)
					}
					if !pump.Enqueue(webSocketSyncRequiredFrame(result.RequiredReason)) {
						coordinator.BeginDisconnect(ref, websocketCloseSlow, "writer unavailable")
						return nil
					}
					continue
				}
				phase = syncPhaseLive
				syncDeadline.Stop()
			case "auth.update":
				if !requestIDPattern.MatchString(envelope.RequestID) {
					coordinator.BeginDisconnect(ref, websocketCloseProtocol, "protocol error")
					return nil
				}
				response := pump.ReserveResponse()
				if response == nil {
					coordinator.BeginDisconnect(ref, websocketCloseSlow, "response lane full")
					return nil
				}
				if !commands.Allow() {
					rateLimitViolations++
					if !enqueueCommandError(pump, response, envelope.RequestID, envelope.Type, 1008, "rate limited", true) {
						coordinator.BeginDisconnect(ref, websocketCloseSlow, "writer unavailable")
						return nil
					}
					if rateLimitViolations >= websocketRateLimitCloseLimit {
						coordinator.BeginDisconnect(ref, websocketCloseAbuse, "command rate limited")
						return nil
					}
					continue
				}
				rateLimitViolations = 0
				accessToken, ok := authUpdateToken(envelope.Data)
				if !ok {
					malformedCommands++
					if !enqueueCommandError(pump, response, envelope.RequestID, envelope.Type, 1001, "malformed request", false) {
						coordinator.BeginDisconnect(ref, websocketCloseSlow, "writer unavailable")
						return nil
					}
					if malformedCommands >= websocketMalformedCommandLimit {
						coordinator.BeginDisconnect(ref, websocketCloseProtocol, "protocol error")
					}
					continue
				}
				malformedCommands = 0
				commandCtx, cancel := context.WithTimeout(context.Background(), websocketCommandTimeout)
				var renewed AuthLease
				updated, err := authenticator.UpdateLease(commandCtx, accessToken, ref.UserID, ref.LoginSessionID, func(identity auth.ConnectionAuth) error {
					var renewErr error
					renewed, renewErr = coordinator.RenewAuthLease(ref, identity.AccessExpiresAt, time.Now().UnixMilli())
					return renewErr
				})
				cancel()
				if err != nil {
					response.release()
					coordinator.BeginDisconnect(ref, websocketCloseExpired, "unauthorized")
					return nil
				}
				leaseTimer.Schedule(renewed)
				if !pump.EnqueueResponse(response, webSocketAuthUpdatedFrame(envelope.RequestID, updated.AccessExpiresAt)) {
					coordinator.BeginDisconnect(ref, websocketCloseSlow, "writer unavailable")
					return nil
				}
			case "presence.set":
				if !requestIDPattern.MatchString(envelope.RequestID) {
					coordinator.BeginDisconnect(ref, websocketCloseProtocol, "protocol error")
					return nil
				}
				response := pump.ReserveResponse()
				if response == nil {
					coordinator.BeginDisconnect(ref, websocketCloseSlow, "response lane full")
					return nil
				}
				if !commands.Allow() {
					rateLimitViolations++
					if !enqueueCommandError(pump, response, envelope.RequestID, envelope.Type, 1008, "rate limited", true) {
						coordinator.BeginDisconnect(ref, websocketCloseSlow, "writer unavailable")
						return nil
					}
					if rateLimitViolations >= websocketRateLimitCloseLimit {
						coordinator.BeginDisconnect(ref, websocketCloseAbuse, "command rate limited")
						return nil
					}
					continue
				}
				rateLimitViolations = 0
				if phase != syncPhaseLive {
					// Defined result-bearing commands before sync.complete preserve
					// correlation rather than being misclassified as protocol errors.
					if !enqueueCommandError(pump, response, envelope.RequestID, envelope.Type, 1, "sync incomplete", true) {
						coordinator.BeginDisconnect(ref, websocketCloseSlow, "writer unavailable")
						return nil
					}
					continue
				}
				if !enqueueCommandError(pump, response, envelope.RequestID, envelope.Type, 1, "presence unavailable", true) {
					coordinator.BeginDisconnect(ref, websocketCloseSlow, "writer unavailable")
					return nil
				}
			default:
				coordinator.BeginDisconnect(ref, websocketCloseProtocol, "protocol error")
				return nil
			}
		}
	}
}

type webSocketClientEnvelope struct {
	Type      string          `json:"type"`
	RequestID string          `json:"request_id"`
	Data      json.RawMessage `json:"data"`
}

// webSocketCommandLimiter is one connection's fixed inbound command budget.
// The read pump is its only caller in production, but the mutex keeps it safe
// for deterministic tests and future command admission refactors.
type webSocketCommandLimiter struct {
	mu     sync.Mutex
	now    func() time.Time
	tokens float64
	last   time.Time
}

// newWebSocketCommandLimiter constructs a full 20/s burst-40 budget.
func newWebSocketCommandLimiter(now func() time.Time) *webSocketCommandLimiter {
	if now == nil {
		now = time.Now
	}
	current := now()
	return &webSocketCommandLimiter{now: now, tokens: websocketCommandBurst, last: current}
}

// Allow consumes one command token after refilling elapsed time. Rejected
// commands leave the remaining budget unchanged.
func (l *webSocketCommandLimiter) Allow() bool {
	if l == nil {
		return false
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
		l.tokens = min(websocketCommandBurst, l.tokens+elapsed*websocketCommandRate)
		l.last = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// syncDeadline controls initial hello and the later full-snapshot resync grace.
// Schedule replaces an older deadline; Stop is idempotent and prevents all
// later callbacks from transitioning the connection.
type syncDeadline struct {
	mu          sync.Mutex
	coordinator *ConnectionCoordinator
	ref         ControlConnectionRef
	timer       *time.Timer
	stopped     bool
	revision    uint64
}

// newSyncDeadline creates an unscheduled sync-state deadline.
func newSyncDeadline(coordinator *ConnectionCoordinator, ref ControlConnectionRef) *syncDeadline {
	return &syncDeadline{coordinator: coordinator, ref: ref}
}

// Schedule starts a deadline for the current sync phase.
func (d *syncDeadline) Schedule(after time.Duration) {
	if d == nil || after <= 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return
	}
	if d.timer != nil {
		d.timer.Stop()
	}
	d.revision++
	revision := d.revision
	d.timer = time.AfterFunc(after, func() {
		d.expire(revision)
	})
}

// expire closes only when revision still names the current deadline. A hello
// that raced a just-fired initial timer increments revision before installing
// the resync grace, so the old callback becomes a no-op.
func (d *syncDeadline) expire(revision uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.stopped && d.revision == revision {
		// Schedule takes the same mutex. Holding it through the coordinator's
		// conditional close claim makes an expiring old deadline linearize before
		// or after a new resync deadline, never between its validation and close.
		d.coordinator.BeginDisconnect(d.ref, websocketCloseSync, "sync timeout")
	}
}

// Stop cancels the active sync deadline and suppresses future scheduling.
func (d *syncDeadline) Stop() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.stopped = true
	d.revision++
	if d.timer != nil {
		d.timer.Stop()
	}
	d.mu.Unlock()
}

// authLeaseTimer owns a connection's current expiry timer. Replacing a timer
// leaves any callback already in flight harmless because it carries the old
// lease revision and ConnectionCoordinator compares it atomically.
type authLeaseTimer struct {
	mu          sync.Mutex
	coordinator *ConnectionCoordinator
	ref         ControlConnectionRef
	timer       *time.Timer
	stopped     bool
}

// newAuthLeaseTimer creates an unscheduled access-token expiry timer.
func newAuthLeaseTimer(coordinator *ConnectionCoordinator, ref ControlConnectionRef) *authLeaseTimer {
	return &authLeaseTimer{coordinator: coordinator, ref: ref}
}

// Schedule replaces the current expiry timer with a callback for lease.
func (t *authLeaseTimer) Schedule(lease AuthLease) {
	if t == nil || lease.Revision == 0 || lease.ExpiresAt <= 0 {
		return
	}
	delay := time.Until(time.UnixMilli(lease.ExpiresAt))
	if delay < 0 {
		delay = 0
	}
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	if t.timer != nil {
		t.timer.Stop()
	}
	t.timer = time.AfterFunc(delay, func() {
		t.coordinator.ExpireAuthLease(t.ref, lease, time.Now().UnixMilli())
	})
	t.mu.Unlock()
}

// Stop prevents future timer callbacks and cancels the currently scheduled one.
func (t *authLeaseTimer) Stop() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.stopped = true
	if t.timer != nil {
		t.timer.Stop()
	}
	t.mu.Unlock()
}

// runWebSocketPings periodically asks the sole write pump to send ping frames.
// Pongs and legal client frames advance the read deadline; a silent peer causes
// the read pump to wake at websocketLivenessWindow and begin terminal teardown.
func runWebSocketPings(pump *webSocketWritePump, stop <-chan struct{}) {
	ticker := time.NewTicker(websocketPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pump.RequestPing()
		case <-stop:
			return
		case <-pump.Done():
			return
		}
	}
}

// syncHelloCursor requires a JSON object with a string cursor.
func syncHelloCursor(data json.RawMessage) (string, bool) {
	var hello struct {
		Cursor *string `json:"cursor"`
	}
	if len(data) == 0 || json.Unmarshal(data, &hello) != nil {
		return "", false
	}
	return dereferenceString(hello.Cursor)
}

// dereferenceString returns one present JSON string without leaking a mutable
// pointer from the sync envelope decoder.
func dereferenceString(value *string) (string, bool) {
	if value == nil {
		return "", false
	}
	return *value, true
}

// authUpdateToken validates and extracts auth.update's access token payload.
func authUpdateToken(data json.RawMessage) (string, bool) {
	var update struct {
		AccessToken string `json:"access_token"`
	}
	if len(data) == 0 || json.Unmarshal(data, &update) != nil || update.AccessToken == "" {
		return "", false
	}
	return update.AccessToken, true
}

// webSocketReadyFrame serializes the first server frame emitted after a
// connection becomes active.
func webSocketReadyFrame(ref ControlConnectionRef, accessExpiresAt int64) []byte {
	frame := struct {
		Type string `json:"type"`
		Data struct {
			ControlConnectionID string `json:"control_connection_id"`
			AccessExpiresAt     int64  `json:"access_expires_at"`
		} `json:"data"`
	}{Type: "connection.ready"}
	frame.Data.ControlConnectionID = ref.IDHex()
	frame.Data.AccessExpiresAt = accessExpiresAt
	encoded, _ := json.Marshal(frame)
	return encoded
}

// webSocketSyncRequiredFrame tells a successfully acknowledged hello to obtain
// a full snapshot before state replay is available in this implementation step.
func webSocketSyncRequiredFrame(reason string) []byte {
	encoded, _ := json.Marshal(struct {
		Type string `json:"type"`
		Data struct {
			Reason string `json:"reason"`
		} `json:"data"`
	}{
		Type: "sync.required",
		Data: struct {
			Reason string `json:"reason"`
		}{Reason: reason},
	})
	return encoded
}

// webSocketAuthUpdatedFrame serializes auth.update's successful connection
// local acknowledgement without allocating a state command or GEID.
func webSocketAuthUpdatedFrame(requestID string, expiresAt int64) []byte {
	encoded, _ := json.Marshal(struct {
		Type      string `json:"type"`
		RequestID string `json:"request_id"`
		Data      struct {
			CommandType string `json:"command_type"`
			ExpiresAt   int64  `json:"expires_at"`
		} `json:"data"`
	}{
		Type:      "command.ok",
		RequestID: requestID,
		Data: struct {
			CommandType string `json:"command_type"`
			ExpiresAt   int64  `json:"expires_at"`
		}{CommandType: "auth.update", ExpiresAt: expiresAt},
	})
	return encoded
}

// enqueueCommandError reserves one response-lane frame for a command whose
// type/request_id is valid but whose payload or admission failed. It returns
// false only when the write pump can no longer deliver the bounded response.
func enqueueCommandError(pump *webSocketWritePump, response *webSocketResponseSlot, requestID, commandType string, code int, message string, retryable bool) bool {
	encoded, err := json.Marshal(struct {
		Type      string `json:"type"`
		RequestID string `json:"request_id"`
		Data      struct {
			CommandType string `json:"command_type"`
			Code        int    `json:"code"`
			Message     string `json:"message"`
			Retryable   bool   `json:"retryable"`
		} `json:"data"`
	}{
		Type:      "command.error",
		RequestID: requestID,
		Data: struct {
			CommandType string `json:"command_type"`
			Code        int    `json:"code"`
			Message     string `json:"message"`
			Retryable   bool   `json:"retryable"`
		}{CommandType: commandType, Code: code, Message: message, Retryable: retryable},
	})
	return err == nil && pump.EnqueueResponse(response, encoded)
}

// requestSourceIP extracts the direct peer IP. The server deliberately ignores
// forwarding headers because trusted-proxy policy is not configured in v1.
func requestSourceIP(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// bearerAccessToken extracts one RFC 6750 Bearer credential without accepting
// extra fields, alternate schemes, or an empty token.
func bearerAccessToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// webSocketAuthenticationError maps handshake authentication/admission errors
// before the connection is upgraded. Access-token failures remain intentionally
// indistinguishable while capacity and shutdown return retryable HTTP errors.
func webSocketAuthenticationError(err error) error {
	if errors.Is(err, auth.ErrUserBanned) {
		return echo.ErrForbidden
	}
	if errors.Is(err, ErrConnectionAdmissionClosed) {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "server shutting down")
	}
	if errors.Is(err, ErrControlConnectionLimit) || errors.Is(err, ErrSourceConnectionLimit) {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "control connection capacity reached")
	}
	return echo.ErrUnauthorized
}

// webSocketWritePump is the sole owner of normal WebSocket writes, including
// application frames, ping/pong controls and terminal close frames. ForceClose
// is the shutdown-deadline exception and only closes the underlying socket.
type webSocketWritePump struct {
	conn *websocket.Conn

	state     *webSocketStateLane
	responses *webSocketResponseLane
	pings     chan struct{}
	pongs     chan []byte
	terminal  chan webSocketTerminal
	done      chan struct{}
	force     sync.Once
}

// webSocketSyncConnection adapts one write pump and coordinator generation to
// EventBus's bounded state sink. It performs no socket I/O in EventBus callers.
type webSocketSyncConnection struct {
	ref         ControlConnectionRef
	pump        *webSocketWritePump
	coordinator *ConnectionCoordinator
}

// ControlRef returns the exact coordinator generation owned by this sink.
func (c *webSocketSyncConnection) ControlRef() ControlConnectionRef {
	if c == nil {
		return ControlConnectionRef{}
	}
	return c.ref
}

// ApplyStateBatch atomically prunes revoked scope work and appends one replay or
// live publication batch.
func (c *webSocketSyncConnection) ApplyStateBatch(revoked []Scope, items []StateQueueItem) bool {
	return c != nil && c.pump != nil && c.pump.ApplyStateBatch(revoked, items)
}

// DisconnectSlowConsumer converges EventBus backpressure on the coordinator's
// once-only close path after StatePublication has released its lock.
func (c *webSocketSyncConnection) DisconnectSlowConsumer() {
	if c == nil || c.coordinator == nil {
		return
	}
	c.coordinator.BeginDisconnect(c.ref, websocketCloseSlow, "slow consumer")
}

type webSocketTerminal struct {
	status int
	reason string
}

// webSocketResponseLane tracks capacity reserved by accepted result-bearing
// commands. Each slot reserves one sixteenth of the lane's byte budget, making
// all accepted v1 control responses deliverable even if the writer is blocked.
// Future commands with larger ACKs must use a different transport shape rather
// than silently violating the response reservation invariant.
type webSocketResponseLane struct {
	mu    sync.Mutex
	items int
	bytes int
	queue chan webSocketResponse
}

type webSocketResponse struct {
	frame []byte
	slot  *webSocketResponseSlot
}

// webSocketResponseSlot belongs to exactly one accepted result-bearing command.
// The write pump releases it only after the frame is written or discarded.
type webSocketResponseSlot struct {
	lane *webSocketResponseLane
	once sync.Once
}

// webSocketStateLane bounds ordinary state/control frames by both item count
// and bytes. It deliberately has no blocking enqueue: publication/relay code
// must disconnect this one slow connection instead of holding a global writer.
type webSocketStateLane struct {
	mu     sync.Mutex
	items  int
	bytes  int
	queue  []webSocketStateFrame
	ready  chan struct{}
	closed bool
}

type webSocketStateFrame struct {
	item  StateQueueItem
	bytes int
}

// newWebSocketStateLane returns the v1 regular state/control delivery lane.
func newWebSocketStateLane() *webSocketStateLane {
	return &webSocketStateLane{ready: make(chan struct{}, 1)}
}

// enqueue copies frame and reserves its byte/item capacity atomically.
func (l *webSocketStateLane) enqueue(frame []byte) bool {
	return l.applyBatch(nil, []StateQueueItem{{Frame: frame, Policy: StateDeliveryControl}})
}

// applyBatch prunes revoked ordinary scope payload and appends every item under
// one queue lock after validating the complete item/byte reservation. The
// writer cannot claim between privacy prune and transition append, nor claim a
// replay prefix when the complete handoff exceeds either hard limit.
func (l *webSocketStateLane) applyBatch(revoked []Scope, items []StateQueueItem) bool {
	if l == nil || (len(items) != 0 && !stateItemBatchWithinLimits(items)) {
		return false
	}
	batch := make([]webSocketStateFrame, len(items))
	batchBytes := 0
	for index, item := range cloneStateQueueItems(items) {
		batch[index] = webSocketStateFrame{item: item, bytes: len(item.Frame)}
		batchBytes += len(item.Frame)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.pruneLocked(revoked)
	if l.items+len(batch) > MaxWebSocketStateItems || l.bytes+batchBytes > MaxWebSocketStateBytes {
		return false
	}
	l.queue = append(l.queue, batch...)
	l.items += len(batch)
	l.bytes += batchBytes
	l.signalLocked()
	return true
}

// pruneLocked removes unclaimed visible-after items for revoked scopes. Caller
// holds mu, which is also the writer's claim gate.
func (l *webSocketStateLane) pruneLocked(revoked []Scope) {
	if len(revoked) == 0 || len(l.queue) == 0 {
		return
	}
	revokedSet := scopesToSet(revoked)
	kept := l.queue[:0]
	for _, frame := range l.queue {
		if frame.item.Policy == StateDeliveryVisibleAfter {
			if _, remove := revokedSet[frame.item.Scope]; remove {
				l.items--
				l.bytes -= frame.bytes
				continue
			}
		}
		kept = append(kept, frame)
	}
	clear(l.queue[len(kept):])
	l.queue = kept
}

// claim removes the oldest queued frame while retaining its capacity until the
// writer finishes or abandons the socket write.
func (l *webSocketStateLane) claim() (webSocketStateFrame, bool) {
	if l == nil {
		return webSocketStateFrame{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || len(l.queue) == 0 {
		return webSocketStateFrame{}, false
	}
	frame := l.queue[0]
	l.queue[0] = webSocketStateFrame{}
	l.queue = l.queue[1:]
	if len(l.queue) != 0 {
		l.signalLocked()
	}
	return frame, true
}

// release returns one dequeued state frame's reserved capacity.
func (l *webSocketStateLane) release(frame webSocketStateFrame) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.items--
	l.bytes -= frame.bytes
	l.mu.Unlock()
}

// close clears reservations for frames abandoned by terminal shutdown and
// rejects every enqueue racing the write pump's exit.
func (l *webSocketStateLane) close() {
	if l == nil {
		return
	}
	l.stop()
	l.mu.Lock()
	l.items = 0
	l.bytes = 0
	l.mu.Unlock()
}

// stop rejects later state delivery and discards every frame not yet claimed by
// the writer. Claim and stop share mu, so a frame is unambiguously ordered
// before terminal close or removed; socket I/O never occurs under this gate.
func (l *webSocketStateLane) stop() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		for _, frame := range l.queue {
			l.items--
			l.bytes -= frame.bytes
		}
		clear(l.queue)
		l.queue = nil
	}
	l.mu.Unlock()
}

// signalLocked wakes the writer once for any non-empty queue. Caller holds mu.
func (l *webSocketStateLane) signalLocked() {
	select {
	case l.ready <- struct{}{}:
	default:
	}
}

// newWebSocketResponseLane returns an empty response lane with the v1 fixed
// item and byte reservations.
func newWebSocketResponseLane() *webSocketResponseLane {
	return &webSocketResponseLane{queue: make(chan webSocketResponse, MaxWebSocketResponseItems)}
}

// reserve claims one response item and its fixed maximum byte allocation.
func (l *webSocketResponseLane) reserve() *webSocketResponseSlot {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.items >= MaxWebSocketResponseItems || l.bytes+maxWebSocketResponseFrameBytes > MaxWebSocketResponseBytes {
		return nil
	}
	l.items++
	l.bytes += maxWebSocketResponseFrameBytes
	return &webSocketResponseSlot{lane: l}
}

// release returns one accepted command's response reservation. It is idempotent
// so write failure, terminal shutdown and caller cleanup can race safely.
func (s *webSocketResponseSlot) release() {
	if s == nil || s.lane == nil {
		return
	}
	s.once.Do(func() {
		s.lane.mu.Lock()
		s.lane.items--
		s.lane.bytes -= maxWebSocketResponseFrameBytes
		s.lane.mu.Unlock()
	})
}

// releaseQueued frees reservations whose ACKs were still queued when a terminal
// close or write error stopped the response writer.
func (l *webSocketResponseLane) releaseQueued() {
	if l == nil {
		return
	}
	for {
		select {
		case response := <-l.queue:
			response.slot.release()
		default:
			return
		}
	}
}

// newWebSocketWritePump starts the one writer for conn.
func newWebSocketWritePump(conn *websocket.Conn) *webSocketWritePump {
	pump := &webSocketWritePump{
		conn:      conn,
		state:     newWebSocketStateLane(),
		responses: newWebSocketResponseLane(),
		pings:     make(chan struct{}, 1),
		pongs:     make(chan []byte, 2),
		terminal:  make(chan webSocketTerminal, 1),
		done:      make(chan struct{}),
	}
	go pump.run()
	return pump
}

// ReserveResponse reserves one ACK slot before a result-bearing command
// performs authentication, state mutation, or lease replacement.
func (p *webSocketWritePump) ReserveResponse() *webSocketResponseSlot {
	if p == nil {
		return nil
	}
	select {
	case <-p.done:
		return nil
	default:
		return p.responses.reserve()
	}
}

// EnqueueResponse consumes response's reservation by queuing its bounded ACK.
// It never competes with ordinary state/control frames; the writer releases the
// reservation after the ACK is written or terminal shutdown discards it.
func (p *webSocketWritePump) EnqueueResponse(response *webSocketResponseSlot, frame []byte) bool {
	if p == nil || response == nil || response.lane != p.responses || len(frame) == 0 || len(frame) > maxWebSocketResponseFrameBytes {
		response.release()
		return false
	}
	queued := webSocketResponse{frame: append([]byte(nil), frame...), slot: response}
	select {
	case <-p.done:
		response.release()
		return false
	case p.responses.queue <- queued:
		return true
	}
}

// Enqueue queues one already-serialized connection-local control frame without
// blocking the caller. Replay and live EventBus delivery uses ApplyStateBatch
// so a whole handoff is admitted atomically.
func (p *webSocketWritePump) Enqueue(frame []byte) bool {
	if p == nil || len(frame) == 0 {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
	}
	return p.state.enqueue(frame)
}

// ApplyStateBatch atomically prunes revoked scope work and appends a replay/live
// handoff in wire order. The EventBus uses this operation while holding the
// connection delivery gate; lifecycle control frames continue to use Enqueue.
func (p *webSocketWritePump) ApplyStateBatch(revoked []Scope, items []StateQueueItem) bool {
	if p == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
	}
	return p.state.applyBatch(revoked, items)
}

// RequestPing queues one liveness ping without allowing periodic ticks to
// build an unbounded backlog behind a blocked application frame.
func (p *webSocketWritePump) RequestPing() {
	if p == nil {
		return
	}
	select {
	case p.pings <- struct{}{}:
	case <-p.done:
	default:
	}
}

// RequestPong queues the response to an inbound ping through the same writer.
func (p *webSocketWritePump) RequestPong(payload []byte) {
	if p == nil {
		return
	}
	copyPayload := append([]byte(nil), payload...)
	select {
	case p.pongs <- copyPayload:
	case <-p.done:
	default:
	}
}

// RequestClose implements ConnectionTransport by non-blockingly reserving the
// write pump's terminal lane. The first request wins; duplicate lifecycle
// callbacks are already no-ops at the coordinator and cannot write directly.
func (p *webSocketWritePump) RequestClose(statusCode int, reason string) {
	if p == nil {
		return
	}
	// Stop and claim share the state-lane gate. An item already claimed is
	// ordered before this close; every unclaimed item is discarded here.
	p.state.stop()
	terminal := webSocketTerminal{status: statusCode, reason: reason}
	select {
	case <-p.done:
		return
	default:
	}
	select {
	case p.terminal <- terminal:
	case <-p.done:
	default:
	}
}

// ForceClose implements ConnectionTransport's shutdown-deadline path. It
// unblocks a stuck write/read operation after graceful terminal delivery has
// exceeded the process deadline.
func (p *webSocketWritePump) ForceClose() {
	if p == nil {
		return
	}
	p.force.Do(func() { _ = p.conn.Close() })
}

// Done closes after the write pump has completed its terminal close path.
func (p *webSocketWritePump) Done() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.done
}

// run serializes application and control writes. It checks terminal work first
// so a lifecycle close cannot be starved by future state-event producers.
func (p *webSocketWritePump) run() {
	defer func() {
		p.state.close()
		p.responses.releaseQueued()
		close(p.done)
	}()
	for {
		select {
		case terminal := <-p.terminal:
			p.closeTerminal(terminal)
			return
		default:
		}
		select {
		case terminal := <-p.terminal:
			p.closeTerminal(terminal)
			return
		case response := <-p.responses.queue:
			if !p.writeFrame(response.frame) {
				response.slot.release()
				return
			}
			response.slot.release()
		case <-p.pings:
			if !p.writeControl(websocket.PingMessage, nil) {
				return
			}
		case payload := <-p.pongs:
			if !p.writeControl(websocket.PongMessage, payload) {
				return
			}
		case <-p.state.ready:
			frame, ok := p.state.claim()
			if !ok {
				continue
			}
			if !p.writeFrame(frame.item.Frame) {
				p.state.release(frame)
				return
			}
			p.state.release(frame)
		}
	}
}

// writeFrame writes one text frame through the sole write pump.
func (p *webSocketWritePump) writeFrame(frame []byte) bool {
	deadline := time.Now().Add(websocketWriteDeadline)
	if err := p.conn.SetWriteDeadline(deadline); err != nil || p.conn.WriteMessage(websocket.TextMessage, frame) != nil {
		p.ForceClose()
		return false
	}
	return true
}

// writeControl writes one ping or pong with the fixed socket write deadline.
func (p *webSocketWritePump) writeControl(messageType int, payload []byte) bool {
	if err := p.conn.WriteControl(messageType, payload, time.Now().Add(websocketWriteDeadline)); err != nil {
		p.ForceClose()
		return false
	}
	return true
}

// closeTerminal writes the one terminal close frame before closing the raw
// socket. The deadline bounds peer-induced stalls during graceful teardown.
func (p *webSocketWritePump) closeTerminal(terminal webSocketTerminal) {
	_ = p.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(terminal.status, terminal.reason), time.Now().Add(websocketWriteDeadline))
	p.ForceClose()
}
