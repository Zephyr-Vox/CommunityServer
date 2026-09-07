package realtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labstack/echo/v5"

	versioninfo "zephyr.vox/server/ce"
	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
)

var (
	// ErrInvalidStateSync is returned when a sync strategy lacks the immutable
	// publication and cursor dependencies required to issue authoritative state.
	ErrInvalidStateSync = errors.New("realtime: invalid state sync strategy")
)

const maxSyncReplayBytes = 256 << 10

// StateSyncStrategy supplies the immutable HTTP snapshot and WebSocket hello
// handoff for one process epoch. Implementations must never combine state from
// separately captured StateVersion and ring high-water values.
type StateSyncStrategy interface {
	CaptureSnapshot(userID int64) (StateSnapshot, error)
	OnHello(connection StateSyncConnection, cursor string) (SyncHello, error)
	OnDisconnect(ref ControlConnectionRef)
}

// StateCursorIssuer issues an opaque cursor for an already-published immutable
// state version. Sequenced HTTP mutations use it to return the exact checkpoint
// they committed rather than recapturing a possibly newer snapshot.
type StateCursorIssuer interface {
	IssueStateCursor(userID int64, version *StateVersion) (string, error)
}

// StateSnapshot is the complete replace-style v1 state response for one user.
type StateSnapshot struct {
	Cursor       string        `json:"cursor"`
	StreamEpoch  string        `json:"stream_epoch"`
	GEID         string        `json:"geid"`
	StateVersion string        `json:"state_version"`
	State        SnapshotState `json:"state"`
}

// SnapshotState is the fixed v1 authoritative state DTO. Runtime presence and
// voice membership are initially empty until their sequenced adapters publish
// them; clients still receive the complete persistent visibility projection.
type SnapshotState struct {
	Server           SnapshotServer            `json:"server"`
	Self             SnapshotSelf              `json:"self"`
	Users            []SnapshotUserPresence    `json:"users"`
	Roles            []SnapshotRole            `json:"roles"`
	Groups           []SnapshotGroup           `json:"groups"`
	Channels         []SnapshotChannel         `json:"channels"`
	VoiceMemberships []SnapshotVoiceMembership `json:"voice_memberships"`
}

// SnapshotServer is server-global immutable metadata retained by the state DTO.
type SnapshotServer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SnapshotSelf is the recipient's own account, role and runtime projection.
type SnapshotSelf struct {
	User              SnapshotUser            `json:"user"`
	ServerRoleKeys    []string                `json:"server_role_keys"`
	ServerPermissions []string                `json:"server_permissions"`
	Presence          SnapshotPresence        `json:"presence"`
	VoiceAuthority    *SnapshotVoiceAuthority `json:"voice_authority"`
}

// SnapshotUser is one credential-free user identity.
type SnapshotUser struct {
	ID       string  `json:"id"`
	Username string  `json:"username"`
	Nickname string  `json:"nickname"`
	Avatar   *string `json:"avatar"`
}

// SnapshotPresence is the v1 server-global presence representation.
type SnapshotPresence struct {
	Status   string            `json:"status"`
	Activity *PresenceActivity `json:"activity,omitempty"`
}

// SnapshotUserPresence is another user's privacy-projected identity/presence.
type SnapshotUserPresence struct {
	UserID   string           `json:"user_id"`
	Nickname string           `json:"nickname"`
	Avatar   *string          `json:"avatar"`
	Presence SnapshotPresence `json:"presence"`
}

// SnapshotRole is one role definition visible to all authenticated users.
type SnapshotRole struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
	Rank        int64  `json:"rank"`
	Builtin     bool   `json:"builtin"`
}

// SnapshotGroup is one visible channel group.
type SnapshotGroup struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Position   int64  `json:"position"`
	Visibility string `json:"visibility"`
	Version    string `json:"version"`
}

// SnapshotChannel is one visible channel.
type SnapshotChannel struct {
	ID         string  `json:"id"`
	GroupID    *string `json:"group_id"`
	Name       string  `json:"name"`
	Mode       string  `json:"mode"`
	Temporary  bool    `json:"temporary"`
	Visibility string  `json:"visibility"`
	Capacity   int64   `json:"capacity"`
	Position   int64   `json:"position"`
	Pinned     bool    `json:"pinned"`
	Version    string  `json:"version"`
}

// SnapshotVoiceMembership is one visible runtime membership. It remains empty
// until the voice authority adapter starts publishing memberships.
type SnapshotVoiceMembership struct {
	UserID    string `json:"user_id"`
	ChannelID string `json:"channel_id"`
	JoinedAt  int64  `json:"joined_at"`
}

// SnapshotVoiceAuthority is the recipient-owned complete authority tuple. IDs
// and generations use decimal strings because they are snowflake/protocol
// identifiers, while joined_at remains a Unix-millisecond number.
type SnapshotVoiceAuthority struct {
	ChannelID                string `json:"channel_id"`
	ControlConnectionID      string `json:"control_connection_id"`
	VoiceSessionID           string `json:"voice_session_id"`
	VoiceAuthorityGeneration string `json:"voice_authority_generation"`
}

// SyncHello reports whether a hello requires a replacement HTTP snapshot. A
// successful result has an empty reason because the strategy has already
// atomically admitted replay, sync.complete and post-replay state to the sink.
type SyncHello struct {
	RequiredReason string
}

// SyncStage identifies a deterministic hook point in replay/live handoff tests.
type SyncStage uint8

const (
	// SyncAfterRegistration runs after the connection is registered as syncing
	// and StatePublication has released its capture lock, but before replay is
	// encoded. Publications at this point must enter post-replay delivery.
	SyncAfterRegistration SyncStage = iota + 1
)

// SyncHook observes a deterministic sync stage. It exists for concurrency
// tests and must not call OnHello for the same connection.
type SyncHook func(SyncStage)

// FullSnapshotSyncStrategy implements v1 full HTTP snapshots and ring replay.
type FullSnapshotSyncStrategy struct {
	publication *StatePublication
	signer      *CursorSigner
	visibility  *VisibilityResolver
	eventBus    *EventBus

	hookMu              sync.RWMutex
	hook                SyncHook
	lastSnapshotLatency atomic.Int64
}

// NewFullSnapshotSyncStrategy creates a v1 strategy backed by one process
// publication boundary, EventBus and their matching cursor signer.
func NewFullSnapshotSyncStrategy(publication *StatePublication, signer *CursorSigner, visibility *VisibilityResolver, eventBus *EventBus) (*FullSnapshotSyncStrategy, error) {
	if publication == nil || signer == nil || visibility == nil || eventBus == nil || publication.visibility != visibility || eventBus.signer != signer || eventBus.visibility != visibility {
		return nil, ErrInvalidStateSync
	}
	if err := publication.BindEventBus(eventBus); err != nil {
		return nil, err
	}
	return &FullSnapshotSyncStrategy{publication: publication, signer: signer, visibility: visibility, eventBus: eventBus}, nil
}

// SetHook replaces the deterministic replay/live handoff test hook. It is safe
// to update concurrently; an in-flight hello keeps the hook it loaded.
func (s *FullSnapshotSyncStrategy) SetHook(hook SyncHook) {
	if s == nil {
		return
	}
	s.hookMu.Lock()
	s.hook = hook
	s.hookMu.Unlock()
}

// CaptureSnapshot serializes one user-visible projection from a single
// publication capture and issues a cursor bound to that capture's checkpoint.
func (s *FullSnapshotSyncStrategy) CaptureSnapshot(userID int64) (StateSnapshot, error) {
	if s == nil || userID <= 0 {
		return StateSnapshot{}, ErrInvalidStateSync
	}
	started := time.Now()
	defer func() {
		s.lastSnapshotLatency.Store(time.Since(started).Nanoseconds())
	}()
	capture := s.publication.Capture()
	if capture.Version == nil {
		return StateSnapshot{}, ErrInvalidStateSync
	}
	if _, ok := capture.Version.User(userID); !ok {
		return StateSnapshot{}, ErrInvalidStateSync
	}
	checkpoint := capture.Version.Checkpoint()
	cursor, err := s.signer.Issue(userID, checkpoint, capture.Version.VisibilityEpoch(userID))
	if err != nil {
		return StateSnapshot{}, err
	}
	return StateSnapshot{
		Cursor:       cursor,
		StreamEpoch:  checkpoint.StreamEpoch,
		GEID:         strconv.FormatUint(checkpoint.GEID, 10),
		StateVersion: strconv.FormatUint(capture.Version.Number(), 10),
		State:        snapshotStateFor(userID, capture.Version, s.visibility),
	}, nil
}

// SnapshotLatency returns the duration of the most recent HTTP snapshot
// capture, including immutable projection serialization and cursor issuance.
func (s *FullSnapshotSyncStrategy) SnapshotLatency() time.Duration {
	if s == nil {
		return 0
	}
	return time.Duration(s.lastSnapshotLatency.Load())
}

// IssueStateCursor returns a cursor bound to userID and version's final
// checkpoint and visibility epoch. The caller must supply a version published
// by this strategy's StatePublication; another stream epoch is rejected.
func (s *FullSnapshotSyncStrategy) IssueStateCursor(userID int64, version *StateVersion) (string, error) {
	if s == nil || s.signer == nil || version == nil || userID <= 0 {
		return "", ErrInvalidStateSync
	}
	if _, exists := version.User(userID); !exists {
		return "", ErrInvalidStateSync
	}
	return s.signer.Issue(userID, version.Checkpoint(), version.VisibilityEpoch(userID))
}

// OnHello validates cursor and registers connection under one publication
// capture. A valid cursor atomically queues retained replay, sync.complete and
// any live events published while replay was encoded. Cursor mismatches require
// a fresh snapshot without installing a subscription.
func (s *FullSnapshotSyncStrategy) OnHello(connection StateSyncConnection, cursor string) (SyncHello, error) {
	if s == nil || connection == nil {
		return SyncHello{}, ErrInvalidStateSync
	}
	ref := connection.ControlRef()
	if !validConnectionRef(ref) {
		return SyncHello{}, ErrInvalidConnection
	}
	userID := ref.UserID
	parsed, err := s.signer.Parse(userID, cursor)
	if err != nil {
		return SyncHello{RequiredReason: syncRequiredReason(err)}, nil
	}
	capture, attempt, requiredReason, err := s.beginSync(connection, parsed)
	if err != nil {
		return SyncHello{}, err
	}
	if requiredReason != "" {
		return SyncHello{RequiredReason: requiredReason}, nil
	}
	defer func() {
		if attempt != nil {
			s.eventBus.abortSync(attempt)
		}
	}()
	s.callHook(SyncAfterRegistration)
	frames, err := s.replayFrames(userID, capture.version, capture.events)
	if err != nil {
		if errors.Is(err, ErrEventConsumerSlow) {
			connection.DisconnectSlowConsumer()
		}
		return SyncHello{}, err
	}
	completeCursor, err := s.signer.Issue(userID, Checkpoint{StreamEpoch: capture.version.Checkpoint().StreamEpoch, GEID: capture.highWater}, capture.visibilityEpoch)
	if err != nil {
		return SyncHello{}, err
	}
	complete, err := syncCompleteFrame(completeCursor)
	if err != nil {
		return SyncHello{}, err
	}
	frames = append(frames, complete)
	if err := s.eventBus.completeSync(attempt, frames); err != nil {
		return SyncHello{}, err
	}
	attempt = nil
	return SyncHello{}, nil
}

// OnDisconnect removes exactly ref's syncing or live EventBus subscription.
// It is idempotent and cannot affect another connection for the same user.
func (s *FullSnapshotSyncStrategy) OnDisconnect(ref ControlConnectionRef) {
	if s == nil || s.eventBus == nil {
		return
	}
	s.eventBus.unsubscribe(ref)
}

type syncPublicationCapture struct {
	version         *StateVersion
	events          []StateEvent
	highWater       uint64
	visibilityEpoch uint64
}

// beginSync validates state-dependent cursor fields and installs the syncing
// subscription before releasing StatePublication's read lock. A concurrent
// Commit therefore falls entirely before replay capture or into pending live
// delivery.
func (s *FullSnapshotSyncStrategy) beginSync(connection StateSyncConnection, cursor Cursor) (syncPublicationCapture, *eventSyncAttempt, string, error) {
	s.publication.mu.RLock()
	defer s.publication.mu.RUnlock()
	if s.publication.eventBus != s.eventBus {
		return syncPublicationCapture{}, nil, "", ErrInvalidStateSync
	}
	version := s.publication.state.Current()
	events, highWater := s.publication.ring.snapshotRefs()
	if version == nil || version.Checkpoint().GEID != highWater {
		return syncPublicationCapture{}, nil, "", ErrInvalidStateSync
	}
	userID := connection.ControlRef().UserID
	visibilityEpoch := version.VisibilityEpoch(userID)
	if cursor.VisibilityEpoch != visibilityEpoch {
		return syncPublicationCapture{}, nil, "visibility_changed", nil
	}
	if cursor.Checkpoint.GEID > highWater {
		return syncPublicationCapture{}, nil, "invalid_cursor", nil
	}
	replay, replayable := eventsAfterCapture(events, highWater, cursor.Checkpoint.GEID)
	if !replayable {
		return syncPublicationCapture{}, nil, "ring_miss", nil
	}
	attempt, err := s.eventBus.beginSync(connection, version)
	if err != nil {
		return syncPublicationCapture{}, nil, "", err
	}
	return syncPublicationCapture{version: version, events: replay, highWater: highWater, visibilityEpoch: visibilityEpoch}, attempt, "", nil
}

// replayFrames groups materialized events into bounded sync.replay frames.
func (s *FullSnapshotSyncStrategy) replayFrames(userID int64, version *StateVersion, events []StateEvent) ([][]byte, error) {
	var frames [][]byte
	var batch []json.RawMessage
	var from, to uint64
	batchBytes := 0
	frameBytes := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		encoded, err := syncReplayFrame(from, to, batch)
		if err != nil {
			return err
		}
		if len(encoded) > maxSyncReplayBytes {
			return ErrStateEventTooLarge
		}
		// Reserve one queue item for sync.complete. Pending live events share the
		// remaining budget and make completeSync reject the connection if they fill
		// it while replay is encoded.
		if len(frames)+1 >= MaxWebSocketStateItems || frameBytes+len(encoded) > MaxWebSocketStateBytes {
			return ErrEventConsumerSlow
		}
		frames = append(frames, encoded)
		frameBytes += len(encoded)
		batch = nil
		batchBytes = 0
		return nil
	}
	for _, event := range events {
		if !eventVisibleTo(userID, event, version, s.visibility) {
			continue
		}
		cursor, err := s.signer.Issue(userID, Checkpoint{StreamEpoch: version.Checkpoint().StreamEpoch, GEID: event.GEID}, cursorEpochForEvent(event, userID, version))
		if err != nil {
			return nil, err
		}
		encoded, err := encodeEventForRecipient(event, userID, version, cursor)
		if err != nil {
			return nil, err
		}
		candidateFrom := from
		if len(batch) == 0 {
			candidateFrom = event.GEID
		}
		candidateBytes := batchBytes + len(encoded)
		candidateCount := len(batch) + 1
		if len(batch) != 0 && syncReplayFrameSize(candidateFrom, event.GEID, candidateBytes, candidateCount) > maxSyncReplayBytes {
			if err := flush(); err != nil {
				return nil, err
			}
			candidateFrom = event.GEID
			candidateBytes = len(encoded)
			candidateCount = 1
		}
		if syncReplayFrameSize(candidateFrom, event.GEID, candidateBytes, candidateCount) > maxSyncReplayBytes {
			return nil, ErrStateEventTooLarge
		}
		if len(batch) == 0 {
			from = candidateFrom
		}
		batch = append(batch, json.RawMessage(encoded))
		batchBytes = candidateBytes
		to = event.GEID
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return frames, nil
}

// syncReplayFrameSize returns the exact compact JSON size produced by
// syncReplayFrame for already-encoded event values.
func syncReplayFrameSize(from, to uint64, eventBytes, eventCount int) int {
	const fixed = len(`{"type":"sync.replay","data":{"from_geid":"","to_geid":"","events":[]}}`)
	commas := 0
	if eventCount > 1 {
		commas = eventCount - 1
	}
	return fixed + len(strconv.FormatUint(from, 10)) + len(strconv.FormatUint(to, 10)) + eventBytes + commas
}

// syncReplayFrame serializes one complete bounded wire chunk. Size probes use
// this exact envelope so from/to fields and outer framing cannot exceed 256 KiB.
func syncReplayFrame(from, to uint64, events []json.RawMessage) ([]byte, error) {
	return json.Marshal(struct {
		Type string `json:"type"`
		Data struct {
			FromGEID string            `json:"from_geid"`
			ToGEID   string            `json:"to_geid"`
			Events   []json.RawMessage `json:"events"`
		} `json:"data"`
	}{Type: "sync.replay", Data: struct {
		FromGEID string            `json:"from_geid"`
		ToGEID   string            `json:"to_geid"`
		Events   []json.RawMessage `json:"events"`
	}{FromGEID: strconv.FormatUint(from, 10), ToGEID: strconv.FormatUint(to, 10), Events: events}})
}

// syncCompleteFrame serializes the durable cursor at replay high-water.
func syncCompleteFrame(cursor string) ([]byte, error) {
	return json.Marshal(struct {
		Type string `json:"type"`
		Data struct {
			Cursor string `json:"cursor"`
		} `json:"data"`
	}{Type: "sync.complete", Data: struct {
		Cursor string `json:"cursor"`
	}{Cursor: cursor}})
}

// callHook invokes the sync hook without retaining its configuration lock.
func (s *FullSnapshotSyncStrategy) callHook(stage SyncStage) {
	s.hookMu.RLock()
	hook := s.hook
	s.hookMu.RUnlock()
	if hook != nil {
		hook(stage)
	}
}

// SnapshotHandler handles authenticated GET /api/v0/state/snapshot.
//
// Errors:
//   - 1002 unauthorized: missing or invalid access token
//   - 1009 internal: state capture failed
func SnapshotHandler(strategy func() StateSyncStrategy) echo.HandlerFunc {
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		if strategy == nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "state sync unavailable")
		}
		current := strategy()
		if current == nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "state sync unavailable")
		}
		snapshot, err := current.CaptureSnapshot(principal.UserID)
		if err != nil {
			return err
		}
		c.Response().Header().Set(echo.HeaderCacheControl, "private, no-store")
		return api.OK(c, http.StatusOK, snapshot)
	})
}

// snapshotStateFor builds the fixed replacement state from one immutable view.
func snapshotStateFor(userID int64, version *StateVersion, visibility *VisibilityResolver) SnapshotState {
	selfUser, _ := version.User(userID)
	state := SnapshotState{
		Server: SnapshotServer{Name: "ZephyrVox", Version: versioninfo.Version},
		Self: SnapshotSelf{
			User:           snapshotUser(selfUser),
			Presence:       snapshotPresenceFor(userID, userID, version),
			VoiceAuthority: snapshotVoiceAuthorityFor(userID, version),
		},
		Users:            []SnapshotUserPresence{},
		Roles:            []SnapshotRole{},
		Groups:           []SnapshotGroup{},
		Channels:         []SnapshotChannel{},
		VoiceMemberships: []SnapshotVoiceMembership{},
	}
	for _, binding := range version.Bindings(userID) {
		if binding.Scope.Type == "server" {
			state.Self.ServerRoleKeys = append(state.Self.ServerRoleKeys, binding.RoleKey)
		}
	}
	sort.Strings(state.Self.ServerRoleKeys)
	state.Self.ServerPermissions = snapshotServerPermissions(state.Self.ServerRoleKeys, version)
	for _, user := range version.Users() {
		state.Users = append(state.Users, snapshotUserPresenceFor(userID, user.ID, version))
	}
	for _, role := range version.Roles() {
		state.Roles = append(state.Roles, SnapshotRole{Key: role.Key, DisplayName: role.DisplayName, Rank: role.Rank, Builtin: role.Builtin})
	}
	groups := version.Groups()
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	for _, group := range groups {
		if visibility.CanSeeGroup(userID, group.ID, version) {
			state.Groups = append(state.Groups, SnapshotGroup{ID: strconv.FormatInt(group.ID, 10), Name: group.Name, Position: group.Position, Visibility: group.Visibility, Version: strconv.FormatInt(group.Version, 10)})
		}
	}
	channels := version.Channels()
	sort.Slice(channels, func(i, j int) bool { return channels[i].ID < channels[j].ID })
	for _, channel := range channels {
		if !visibility.CanAccessChannel(userID, channel.ID, version) {
			continue
		}
		var groupID *string
		if channel.GroupID != nil {
			id := strconv.FormatInt(*channel.GroupID, 10)
			groupID = &id
		}
		state.Channels = append(state.Channels, SnapshotChannel{ID: strconv.FormatInt(channel.ID, 10), GroupID: groupID, Name: channel.Name, Mode: channel.Mode, Temporary: channel.Temporary, Visibility: channel.Visibility, Capacity: channel.Capacity, Position: channel.Position, Pinned: channel.Pinned, Version: strconv.FormatInt(channel.Version, 10)})
	}
	for _, authority := range version.VoiceAuthorities() {
		if visibility.CanAccessChannel(userID, authority.ChannelID, version) {
			state.VoiceMemberships = append(state.VoiceMemberships, SnapshotVoiceMembership{UserID: strconv.FormatInt(authority.UserID, 10), ChannelID: strconv.FormatInt(authority.ChannelID, 10), JoinedAt: authority.JoinedAt})
		}
	}
	return state
}

// snapshotVoiceAuthorityFor projects the recipient's own authoritative binding.
func snapshotVoiceAuthorityFor(userID int64, version *StateVersion) *SnapshotVoiceAuthority {
	authority, ok := version.VoiceAuthority(userID)
	if !ok {
		return nil
	}
	return snapshotVoiceAuthorityValue(&authority)
}

// snapshotVoiceAuthorityValue converts one complete authority tuple to the
// recipient-owned wire projection without consulting mutable coordinator state.
func snapshotVoiceAuthorityValue(authority *VoiceAuthority) *SnapshotVoiceAuthority {
	if authority == nil {
		return nil
	}
	return &SnapshotVoiceAuthority{
		ChannelID:                strconv.FormatInt(authority.ChannelID, 10),
		ControlConnectionID:      fmt.Sprintf("%x", authority.ControlConnectionID),
		VoiceSessionID:           fmt.Sprintf("%x", authority.VoiceSessionID),
		VoiceAuthorityGeneration: strconv.FormatUint(authority.VoiceAuthorityGeneration, 10),
	}
}

// SnapshotUserPresenceFor exposes the canonical privacy projection used by
// snapshot serialization, visibility fragments and user/presence event
// materialization. recipientID receives private activity only for itself.
func SnapshotUserPresenceFor(recipientID, subjectID int64, version *StateVersion) SnapshotUserPresence {
	return snapshotUserPresenceFor(recipientID, subjectID, version)
}

// SnapshotSelfFor returns the complete recipient-owned snapshot subdocument.
// It is used by targeted self.updated events after permission or profile
// mutations, so those events use exactly the snapshot representation.
func SnapshotSelfFor(userID int64, version *StateVersion) SnapshotSelf {
	return snapshotStateFor(userID, version, NewVisibilityResolver()).Self
}

// snapshotUserPresenceFor projects subject's presence for recipient. Invisible
// and private activity remain visible only to the subject itself.
func snapshotUserPresenceFor(recipientID, subjectID int64, version *StateVersion) SnapshotUserPresence {
	user, _ := version.User(subjectID)
	return snapshotUserPresenceFromState(recipientID, eventSubjectState{user: user, presence: version.Presence(subjectID)})
}

// snapshotUserPresenceFromState projects one compact event-time subject state
// without retaining the complete StateVersion in the replay ring.
func snapshotUserPresenceFromState(recipientID int64, state eventSubjectState) SnapshotUserPresence {
	return SnapshotUserPresence{
		UserID:   strconv.FormatInt(state.user.ID, 10),
		Nickname: state.user.Nickname,
		Avatar:   cloneString(state.user.Avatar),
		Presence: snapshotPresenceValue(recipientID, state.user.ID, state.presence),
	}
}

// snapshotPresenceFor converts one runtime presence value to its privacy-safe
// wire projection for recipientID.
func snapshotPresenceFor(recipientID, subjectID int64, version *StateVersion) SnapshotPresence {
	return snapshotPresenceValue(recipientID, subjectID, version.Presence(subjectID))
}

// snapshotPresenceValue applies privacy to one immutable presence value.
func snapshotPresenceValue(recipientID, subjectID int64, presence Presence) SnapshotPresence {
	if recipientID != subjectID && presence.Status == "invisible" {
		return SnapshotPresence{Status: "offline"}
	}
	projected := SnapshotPresence{Status: presence.Status}
	if presence.Activity != nil && (recipientID == subjectID || presence.Activity.Privacy == "public") {
		activity := *presence.Activity
		projected.Activity = &activity
	}
	return projected
}

// snapshotServerPermissions resolves stable effective server permissions from
// the immutable root config rather than querying mutable SQLite during snapshot
// serialization. Owner's mandatory wildcard is represented directly.
func snapshotServerPermissions(roleKeys []string, version *StateVersion) []string {
	for _, roleKey := range roleKeys {
		if roleKey == "owner" {
			return []string{"*"}
		}
	}
	config, ok := version.Config(Scope{Type: "server"})
	if !ok {
		return []string{}
	}
	var grants map[string][]string
	if json.Unmarshal([]byte(config.Config), &grants) != nil {
		return []string{}
	}
	seen := make(map[string]struct{})
	permissions := make([]string, 0)
	for _, roleKey := range roleKeys {
		for _, permission := range grants[roleKey] {
			if _, exists := seen[permission]; exists {
				continue
			}
			seen[permission] = struct{}{}
			permissions = append(permissions, permission)
		}
	}
	sort.Strings(permissions)
	return permissions
}

// encodeEventForRecipient applies v1's recipient-specific user/presence
// projection before serializing an otherwise immutable ring event.
func encodeEventForRecipient(event StateEvent, recipientID int64, version *StateVersion, cursor string) ([]byte, error) {
	data := event.Data
	if event.SubjectUserID > 0 && (event.EventType == "user.created" || event.EventType == "user.updated" || event.EventType == "presence.updated") {
		var projectedUser SnapshotUserPresence
		if event.subjectState != nil {
			projectedUser = snapshotUserPresenceFromState(recipientID, *event.subjectState)
		} else {
			projectedUser = SnapshotUserPresenceFor(recipientID, event.SubjectUserID, version)
		}
		projected, err := json.Marshal(struct {
			User SnapshotUserPresence `json:"user"`
		}{User: projectedUser})
		if err != nil {
			return nil, err
		}
		data = projected
	}
	return event.EncodedWithDataAndCursor(data, cursor)
}

// snapshotUser converts the store projection's credential-free user DTO.
func snapshotUser(user User) SnapshotUser {
	return SnapshotUser{ID: strconv.FormatInt(user.ID, 10), Username: user.Username, Nickname: user.Nickname, Avatar: user.Avatar}
}

// eventsAfterCapture mirrors StateRing.EventsAfter for an immutable publication
// capture without reading a newer ring after the version was captured.
func eventsAfterCapture(events []StateEvent, highWater, geid uint64) ([]StateEvent, bool) {
	if geid > highWater {
		return nil, false
	}
	if len(events) == 0 {
		return nil, geid == highWater
	}
	if geid < events[0].GEID-1 {
		return nil, false
	}
	start := len(events)
	for i, event := range events {
		if event.GEID > geid {
			start = i
			break
		}
	}
	return events[start:], true
}

// eventVisibleTo applies the same immutable resolver used by snapshots.
func eventVisibleTo(userID int64, event StateEvent, version *StateVersion, visibility *VisibilityResolver) bool {
	if event.DeliveryPolicy == StateDeliveryDirectTransition || event.DeliveryPolicy == StateDeliveryUserTargeted {
		return event.RecipientUserID == userID
	}
	if event.DeliveryPolicy == StateDeliveryVisibleBefore {
		for _, visibleUserID := range event.VisibleBeforeUserIDs {
			if visibleUserID == userID {
				return true
			}
		}
		return false
	}
	switch event.Scope.Type {
	case "server":
		_, ok := version.User(userID)
		return ok
	case "group":
		return visibility.CanSeeGroup(userID, event.Scope.ID, version)
	case "channel":
		return visibility.CanAccessChannel(userID, event.Scope.ID, version)
	default:
		return false
	}
}

// syncRequiredReason maps opaque cursor errors to the fixed wire allowlist.
func syncRequiredReason(err error) string {
	switch {
	case errors.Is(err, ErrCursorEpoch):
		return "epoch_changed"
	case errors.Is(err, ErrCursorSchema):
		return "schema_changed"
	default:
		return "invalid_cursor"
	}
}
