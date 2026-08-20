package realtime

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v5"

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
	OnHello(userID int64, cursor string) (SyncHello, error)
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
	User              SnapshotUser     `json:"user"`
	ServerRoleKeys    []string         `json:"server_role_keys"`
	ServerPermissions []string         `json:"server_permissions"`
	Presence          SnapshotPresence `json:"presence"`
	VoiceAuthority    json.RawMessage  `json:"voice_authority"`
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
	Status string `json:"status"`
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
	Rank        string `json:"rank"`
	Builtin     bool   `json:"builtin"`
}

// SnapshotGroup is one visible channel group.
type SnapshotGroup struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Position   string `json:"position"`
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
	Capacity   string  `json:"capacity"`
	Position   string  `json:"position"`
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

// SyncHello contains either replay/complete frames or a sync.required reason.
// Frames are already encoded wire messages for direct writer-pump delivery.
type SyncHello struct {
	RequiredReason string
	Frames         [][]byte
}

// FullSnapshotSyncStrategy implements v1 full HTTP snapshots and ring replay.
type FullSnapshotSyncStrategy struct {
	publication *StatePublication
	signer      *CursorSigner
	visibility  *VisibilityResolver
}

// NewFullSnapshotSyncStrategy creates a v1 strategy backed by one process
// publication boundary and its matching cursor signer.
func NewFullSnapshotSyncStrategy(publication *StatePublication, signer *CursorSigner, visibility *VisibilityResolver) (*FullSnapshotSyncStrategy, error) {
	if publication == nil || signer == nil || visibility == nil {
		return nil, ErrInvalidStateSync
	}
	return &FullSnapshotSyncStrategy{publication: publication, signer: signer, visibility: visibility}, nil
}

// CaptureSnapshot serializes one user-visible projection from a single
// publication capture and issues a cursor bound to that capture's checkpoint.
func (s *FullSnapshotSyncStrategy) CaptureSnapshot(userID int64) (StateSnapshot, error) {
	if s == nil || userID <= 0 {
		return StateSnapshot{}, ErrInvalidStateSync
	}
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

// OnHello validates cursor against one publication capture. A valid cursor
// replays every still-retained visible event followed by sync.complete; any
// epoch/schema/principal/visibility/ring mismatch requires a fresh snapshot.
func (s *FullSnapshotSyncStrategy) OnHello(userID int64, cursor string) (SyncHello, error) {
	if s == nil || userID <= 0 {
		return SyncHello{}, ErrInvalidStateSync
	}
	parsed, err := s.signer.Parse(userID, cursor)
	if err != nil {
		return SyncHello{RequiredReason: syncRequiredReason(err)}, nil
	}
	capture := s.publication.Capture()
	if capture.Version == nil || parsed.VisibilityEpoch != capture.Version.VisibilityEpoch(userID) {
		return SyncHello{RequiredReason: "visibility_changed"}, nil
	}
	if parsed.Checkpoint.GEID > capture.HighWater {
		return SyncHello{RequiredReason: "invalid_cursor"}, nil
	}
	events, replayable := eventsAfterCapture(capture.Events, capture.HighWater, parsed.Checkpoint.GEID)
	if !replayable {
		return SyncHello{RequiredReason: "ring_miss"}, nil
	}
	frames, err := s.replayFrames(userID, capture.Version, events)
	if err != nil {
		return SyncHello{}, err
	}
	completeCursor, err := s.signer.Issue(userID, capture.Version.Checkpoint(), capture.Version.VisibilityEpoch(userID))
	if err != nil {
		return SyncHello{}, err
	}
	complete, err := json.Marshal(struct {
		Type string `json:"type"`
		Data struct {
			Cursor string `json:"cursor"`
		} `json:"data"`
	}{Type: "sync.complete", Data: struct {
		Cursor string `json:"cursor"`
	}{Cursor: completeCursor}})
	if err != nil {
		return SyncHello{}, err
	}
	frames = append(frames, complete)
	return SyncHello{Frames: frames}, nil
}

// replayFrames groups materialized events into bounded sync.replay frames.
func (s *FullSnapshotSyncStrategy) replayFrames(userID int64, version *StateVersion, events []StateEvent) ([][]byte, error) {
	var frames [][]byte
	var batch []json.RawMessage
	var from, to uint64
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		encoded, err := json.Marshal(struct {
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
		}{FromGEID: strconv.FormatUint(from, 10), ToGEID: strconv.FormatUint(to, 10), Events: batch}})
		if err != nil {
			return err
		}
		frames = append(frames, encoded)
		batch = nil
		return nil
	}
	for _, event := range events {
		if !eventVisibleTo(userID, event, version, s.visibility) {
			continue
		}
		cursor, err := s.signer.Issue(userID, Checkpoint{StreamEpoch: version.Checkpoint().StreamEpoch, GEID: event.GEID}, version.VisibilityEpoch(userID))
		if err != nil {
			return nil, err
		}
		encoded, err := event.EncodedWithCursor(cursor)
		if err != nil {
			return nil, err
		}
		candidate := append(append([]json.RawMessage(nil), batch...), json.RawMessage(encoded))
		probe, err := json.Marshal(struct {
			Events []json.RawMessage `json:"events"`
		}{Events: candidate})
		if err != nil {
			return nil, err
		}
		if len(batch) != 0 && len(probe) > maxSyncReplayBytes {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		if len(batch) == 0 {
			from = event.GEID
		}
		batch = append(batch, json.RawMessage(encoded))
		to = event.GEID
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return frames, nil
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
		Server: SnapshotServer{},
		Self: SnapshotSelf{
			User:           snapshotUser(selfUser),
			Presence:       SnapshotPresence{Status: "offline"},
			VoiceAuthority: json.RawMessage("null"),
		},
		VoiceMemberships: []SnapshotVoiceMembership{},
	}
	for _, binding := range version.Bindings(userID) {
		if binding.Scope.Type == "server" {
			state.Self.ServerRoleKeys = append(state.Self.ServerRoleKeys, binding.RoleKey)
		}
	}
	for _, user := range version.Users() {
		state.Users = append(state.Users, SnapshotUserPresence{UserID: strconv.FormatInt(user.ID, 10), Nickname: user.Nickname, Avatar: user.Avatar, Presence: SnapshotPresence{Status: "offline"}})
	}
	for _, role := range version.Roles() {
		state.Roles = append(state.Roles, SnapshotRole{Key: role.Key, DisplayName: role.DisplayName, Rank: strconv.FormatInt(role.Rank, 10), Builtin: role.Builtin})
	}
	for _, group := range version.Groups() {
		if visibility.CanSeeGroup(userID, group.ID, version) {
			state.Groups = append(state.Groups, SnapshotGroup{ID: strconv.FormatInt(group.ID, 10), Name: group.Name, Position: strconv.FormatInt(group.Position, 10), Visibility: group.Visibility, Version: strconv.FormatInt(group.Version, 10)})
		}
	}
	for _, channel := range version.Channels() {
		if !visibility.CanAccessChannel(userID, channel.ID, version) {
			continue
		}
		var groupID *string
		if channel.GroupID != nil {
			id := strconv.FormatInt(*channel.GroupID, 10)
			groupID = &id
		}
		state.Channels = append(state.Channels, SnapshotChannel{ID: strconv.FormatInt(channel.ID, 10), GroupID: groupID, Name: channel.Name, Mode: channel.Mode, Temporary: channel.Temporary, Visibility: channel.Visibility, Capacity: strconv.FormatInt(channel.Capacity, 10), Position: strconv.FormatInt(channel.Position, 10), Pinned: channel.Pinned, Version: strconv.FormatInt(channel.Version, 10)})
	}
	return state
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
