// Package realtime provides the application-level immutable state projection
// and command infrastructure shared by HTTP, WebSocket and voice adapters.
package realtime

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/store"
)

var (
	// ErrInvalidStreamEpoch is returned when a stream epoch is not exactly 16
	// random bytes represented as 32 lowercase hexadecimal characters.
	ErrInvalidStreamEpoch = errors.New("realtime: invalid stream epoch")
	// ErrInvalidProjection is returned when rows supplied by a projection loader
	// cannot form one internally consistent immutable projection.
	ErrInvalidProjection = errors.New("realtime: invalid state projection")
)

const streamEpochBytes = 16

// Scope identifies one visibility or configuration target. Server scope uses
// ID zero; group and channel scopes require a positive ID.
type Scope struct {
	Type string
	ID   int64
}

// Key returns Scope's canonical identity for hashing and deterministic sorting.
func (s Scope) Key() string {
	if s.Type == "server" {
		return "server"
	}
	return fmt.Sprintf("%s:%d", s.Type, s.ID)
}

// Valid reports whether Scope has one supported type and the matching ID shape.
func (s Scope) Valid() bool {
	if s.Type == "server" {
		return s.ID == 0
	}
	return (s.Type == "group" || s.Type == "channel") && s.ID > 0
}

// Checkpoint identifies one immutable state version's position in the current
// stream epoch. GEID remains an integer internally and is encoded as decimal
// text only at JSON and HTTP boundaries.
type Checkpoint struct {
	StreamEpoch string
	GEID        uint64
}

// User is the credential-free account view retained by the StateStore.
type User struct {
	ID          int64
	Username    string
	Nickname    string
	Avatar      *string
	AuthVersion int64
	Banned      bool
	CreatedAt   int64
	UpdatedAt   int64
}

// Role is one immutable role definition in the state projection.
type Role struct {
	Key         string
	DisplayName string
	Rank        int64
	Builtin     bool
	Immutable   bool
	CreatedAt   int64
	UpdatedAt   int64
	Version     int64
}

// Group is one immutable channel group in the state projection.
type Group struct {
	ID         int64
	Name       string
	Position   int64
	Visibility string
	CreatedAt  int64
	UpdatedAt  int64
	Version    int64
}

// Channel is one immutable persisted channel in the state projection.
type Channel struct {
	ID         int64
	GroupID    *int64
	Name       string
	Mode       string
	Temporary  bool
	Visibility string
	Capacity   int64
	Position   int64
	Pinned     bool
	CreatedBy  *int64
	CreatedAt  int64
	UpdatedAt  int64
	Version    int64
}

// AccessEntry identifies one user or role principal granted access to a group
// or channel. Exactly one of UserID and RoleKey is set by the database schema.
type AccessEntry struct {
	ID            int64
	PrincipalType string
	UserID        *int64
	RoleKey       *string
	CreatedAt     int64
}

// RoleBinding identifies one persisted role binding for a user.
type RoleBinding struct {
	ID        int64
	RoleKey   string
	Scope     Scope
	CreatedAt int64
}

// PermissionConfig is one local permission configuration row. The absence of
// a group or channel Scope from the projection represents inheritance.
type PermissionConfig struct {
	Scope     Scope
	Config    string
	UpdatedAt int64
	Version   int64
}

// Mute is one immutable moderation mute retained for later state and relay
// decisions. It intentionally keeps no delivery-specific projection.
type Mute struct {
	ID        int64
	Scope     Scope
	UserID    int64
	Kind      string
	ExpiresAt *int64
	CreatedBy *int64
	Reason    string
	CreatedAt int64
	Version   int64
}

// PresenceActivity is an optional user-selected activity. Private activities
// are only materialized for the subject's own snapshot and state events.
type PresenceActivity struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Privacy string `json:"privacy"`
}

// Presence is the server-global runtime presence state retained in each
// immutable StateVersion. It is never persisted and starts offline after a
// process restart until a control connection becomes active.
type Presence struct {
	Status   string
	Activity *PresenceActivity
}

type persistentState struct {
	users         map[int64]User
	roles         map[string]Role
	groups        map[int64]Group
	channels      map[int64]Channel
	groupAccess   map[int64][]AccessEntry
	channelAccess map[int64][]AccessEntry
	bindings      map[int64][]RoleBinding
	configs       map[Scope]PermissionConfig
	mutes         map[int64]Mute
}

type runtimeState struct {
	visibilityEpochs map[int64]uint64
	moderationEpoch  uint64
	presences        map[int64]Presence
	voiceAuthorities map[int64]VoiceAuthority
	temporaryExpiry  map[int64]ExpirySchedule
	muteExpiry       map[int64]ExpirySchedule
}

// ExpirySchedule is a generation-guarded runtime deadline. Deadline zero
// represents a cancelled timer while retaining a higher generation for stale
// callback rejection.
type ExpirySchedule struct {
	Generation uint64
	Deadline   int64
}

// StateVersion is an immutable server-state projection. Its accessors return
// value copies, so callers cannot mutate a published version or another
// concurrent reader's view.
type StateVersion struct {
	number     uint64
	checkpoint Checkpoint
	persistent persistentState
	runtime    runtimeState
}

// Number returns the server-local, monotonically increasing state version.
func (v *StateVersion) Number() uint64 {
	return v.number
}

// Checkpoint returns the immutable stream checkpoint associated with v.
func (v *StateVersion) Checkpoint() Checkpoint {
	return v.checkpoint
}

// User returns one credential-free account copy by ID.
func (v *StateVersion) User(id int64) (User, bool) {
	user, ok := v.persistent.users[id]
	return cloneUser(user), ok
}

// Users returns all credential-free accounts in ascending ID order.
func (v *StateVersion) Users() []User {
	ids := sortedIntKeys(v.persistent.users)
	users := make([]User, 0, len(ids))
	for _, id := range ids {
		users = append(users, cloneUser(v.persistent.users[id]))
	}
	return users
}

// Role returns one role definition copy by immutable role key.
func (v *StateVersion) Role(key string) (Role, bool) {
	role, ok := v.persistent.roles[key]
	return role, ok
}

// Roles returns role definitions in ascending immutable key order. Snapshot
// arrays use keys as their stable identity, so display-name and rank edits must
// not reorder otherwise unchanged role data for clients.
func (v *StateVersion) Roles() []Role {
	roles := make([]Role, 0, len(v.persistent.roles))
	for _, role := range v.persistent.roles {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Key < roles[j].Key })
	return roles
}

// Group returns one channel group copy by ID.
func (v *StateVersion) Group(id int64) (Group, bool) {
	group, ok := v.persistent.groups[id]
	return group, ok
}

// Groups returns all channel groups in stable display order.
func (v *StateVersion) Groups() []Group {
	groups := make([]Group, 0, len(v.persistent.groups))
	for _, group := range v.persistent.groups {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Position != groups[j].Position {
			return groups[i].Position < groups[j].Position
		}
		return groups[i].ID < groups[j].ID
	})
	return groups
}

// Channel returns one channel copy by ID.
func (v *StateVersion) Channel(id int64) (Channel, bool) {
	channel, ok := v.persistent.channels[id]
	return cloneChannel(channel), ok
}

// Channels returns all channels in stable display order.
func (v *StateVersion) Channels() []Channel {
	channels := make([]Channel, 0, len(v.persistent.channels))
	for _, channel := range v.persistent.channels {
		channels = append(channels, cloneChannel(channel))
	}
	sort.Slice(channels, func(i, j int) bool {
		if channels[i].Position != channels[j].Position {
			return channels[i].Position < channels[j].Position
		}
		return channels[i].ID < channels[j].ID
	})
	return channels
}

// GroupAccess returns every ACL entry for groupID in ascending entry ID order.
func (v *StateVersion) GroupAccess(groupID int64) []AccessEntry {
	return cloneAccessEntries(v.persistent.groupAccess[groupID])
}

// ChannelAccess returns every ACL entry for channelID in ascending entry ID
// order.
func (v *StateVersion) ChannelAccess(channelID int64) []AccessEntry {
	return cloneAccessEntries(v.persistent.channelAccess[channelID])
}

// Bindings returns all role bindings for userID in ascending binding ID order.
func (v *StateVersion) Bindings(userID int64) []RoleBinding {
	return cloneRoleBindings(v.persistent.bindings[userID])
}

// Config returns one local configuration row for scope. A false result for a
// group or channel scope represents inherited configuration.
func (v *StateVersion) Config(scope Scope) (PermissionConfig, bool) {
	config, ok := v.persistent.configs[scope]
	return config, ok
}

// Mute returns one moderation mute copy by ID.
func (v *StateVersion) Mute(id int64) (Mute, bool) {
	mute, ok := v.persistent.mutes[id]
	return cloneMute(mute), ok
}

// Mutes returns every persisted moderation mute in ascending ID order.
func (v *StateVersion) Mutes() []Mute {
	if v == nil {
		return nil
	}
	ids := sortedIntKeys(v.persistent.mutes)
	mutes := make([]Mute, 0, len(ids))
	for _, id := range ids {
		mutes = append(mutes, cloneMute(v.persistent.mutes[id]))
	}
	return mutes
}

// VisibilityEpoch returns userID's monotonic visible-scope-set epoch. It is
// zero until a later StatePublication records that user's first transition.
func (v *StateVersion) VisibilityEpoch(userID int64) uint64 {
	return v.runtime.visibilityEpochs[userID]
}

// ModerationEpoch returns the server-global moderation epoch retained by v.
func (v *StateVersion) ModerationEpoch() uint64 {
	return v.runtime.moderationEpoch
}

// TemporaryExpiry returns one temporary channel's current empty-delete schedule.
func (v *StateVersion) TemporaryExpiry(channelID int64) (ExpirySchedule, bool) {
	schedule, ok := v.runtime.temporaryExpiry[channelID]
	return schedule, ok
}

// MuteExpiry returns one moderation mute's current expiry cleanup schedule.
func (v *StateVersion) MuteExpiry(muteID int64) (ExpirySchedule, bool) {
	schedule, ok := v.runtime.muteExpiry[muteID]
	return schedule, ok
}

// Presence returns userID's runtime presence. Users without an explicit
// runtime entry are offline, which is also the post-restart default.
func (v *StateVersion) Presence(userID int64) Presence {
	if v == nil {
		return Presence{Status: "offline"}
	}
	presence, ok := v.runtime.presences[userID]
	if !ok {
		return Presence{Status: "offline"}
	}
	return clonePresence(presence)
}

// VoiceAuthority returns userID's immutable voice authority tuple when that
// user has an active runtime binding in this state version.
func (v *StateVersion) VoiceAuthority(userID int64) (VoiceAuthority, bool) {
	if v == nil {
		return VoiceAuthority{}, false
	}
	authority, ok := v.runtime.voiceAuthorities[userID]
	return authority, ok
}

// VoiceAuthorities returns all active runtime authorities ordered by user ID.
// Snapshot and fragment serialization derive membership solely from this map.
func (v *StateVersion) VoiceAuthorities() []VoiceAuthority {
	if v == nil {
		return nil
	}
	ids := sortedIntKeys(v.runtime.voiceAuthorities)
	authorities := make([]VoiceAuthority, 0, len(ids))
	for _, userID := range ids {
		authorities = append(authorities, v.runtime.voiceAuthorities[userID])
	}
	return authorities
}

// ProjectionLoader loads the complete persisted state from one database view.
// *store.Stores implements it through LoadStateProjection.
type ProjectionLoader interface {
	LoadStateProjection(context.Context) (*store.StateProjection, error)
}

// StateStore holds the current immutable state pointer. It does not itself
// publish candidates: StatePublication owns that atomic commit boundary in the
// next infrastructure layer.
type StateStore struct {
	loader  ProjectionLoader
	current atomic.Pointer[StateVersion]
}

// NewStateStore loads version zero with a freshly generated stream epoch.
func NewStateStore(ctx context.Context, loader ProjectionLoader) (*StateStore, error) {
	epoch, err := NewStreamEpoch()
	if err != nil {
		return nil, err
	}
	return NewStateStoreWithEpoch(ctx, loader, epoch)
}

// NewStateStoreWithEpoch loads version zero using streamEpoch. It exists for
// deterministic tests and for startup assembly that already generated the
// process-wide epoch before creating related services.
func NewStateStoreWithEpoch(ctx context.Context, loader ProjectionLoader, streamEpoch string) (*StateStore, error) {
	if loader == nil {
		return nil, errors.New("realtime: nil projection loader")
	}
	if err := validateStreamEpoch(streamEpoch); err != nil {
		return nil, err
	}
	projection, err := loader.LoadStateProjection(ctx)
	if err != nil {
		return nil, err
	}
	persistent, err := newPersistentState(projection)
	if err != nil {
		return nil, err
	}
	state := &StateStore{loader: loader}
	state.current.Store(&StateVersion{
		checkpoint: Checkpoint{StreamEpoch: streamEpoch},
		persistent: persistent,
		runtime: runtimeState{
			visibilityEpochs: make(map[int64]uint64),
			presences:        make(map[int64]Presence),
			voiceAuthorities: make(map[int64]VoiceAuthority),
			temporaryExpiry:  make(map[int64]ExpirySchedule),
			muteExpiry:       make(map[int64]ExpirySchedule),
		},
	})
	return state, nil
}

// BuildRuntimeCandidate creates an unpublished successor that keeps the
// current persistent projection and clones only runtime state. Runtime commands
// such as control-connection presence transitions use it instead of reading the
// database, while StatePublication still assigns the next version/checkpoint.
func (s *StateStore) BuildRuntimeCandidate() (*StateCandidate, error) {
	if s == nil || s.Current() == nil {
		return nil, ErrInvalidProjection
	}
	base := s.Current()
	return &StateCandidate{
		base: base,
		version: &StateVersion{
			number:     base.number + 1,
			checkpoint: base.checkpoint,
			persistent: base.persistent,
			runtime:    base.runtime.clone(),
		},
	}, nil
}

// Current returns the current immutable state version without taking a global
// write lock. The returned value must be treated as read-only.
func (s *StateStore) Current() *StateVersion {
	return s.current.Load()
}

// BuildPersistentCandidate loads post-commit persistent rows into an
// unpublished version derived from the current runtime state. StatePublication
// will later verify candidate.Base against Current before making it visible.
func (s *StateStore) BuildPersistentCandidate(ctx context.Context) (*StateCandidate, error) {
	return s.BuildPersistentCandidateFrom(ctx, s.loader)
}

// BuildPersistentCandidateFrom loads an unpublished persistent version using
// loader while retaining s's current runtime state. Persistent commands pass a
// transaction-bound store so the candidate, its reserved checkpoint, and the
// durable idempotency result all describe the same rollbackable database view.
func (s *StateStore) BuildPersistentCandidateFrom(ctx context.Context, loader ProjectionLoader) (*StateCandidate, error) {
	if s == nil || loader == nil {
		return nil, ErrInvalidProjection
	}
	base := s.Current()
	projection, err := loader.LoadStateProjection(ctx)
	if err != nil {
		return nil, err
	}
	persistent, err := newPersistentState(projection)
	if err != nil {
		return nil, err
	}
	runtime := base.runtime.clone()
	// Persistent cascades (owner transfer, account deletion, channel deletion)
	// may remove scheduled entities outside their owning runtime service. Prune
	// only absent IDs here; deadline/value changes remain generation-guarded by
	// the corresponding sequenced command.
	for channelID := range runtime.temporaryExpiry {
		if _, exists := persistent.channels[channelID]; !exists {
			delete(runtime.temporaryExpiry, channelID)
		}
	}
	for muteID := range runtime.muteExpiry {
		if _, exists := persistent.mutes[muteID]; !exists {
			delete(runtime.muteExpiry, muteID)
		}
	}
	return &StateCandidate{
		base: base,
		version: &StateVersion{
			number:     base.number + 1,
			checkpoint: base.checkpoint,
			persistent: persistent,
			runtime:    runtime,
		},
	}, nil
}

// StateCandidate is a fully built but unpublished StateVersion. It is safe to
// inspect concurrently after construction; only StatePublication may commit it.
type StateCandidate struct {
	base    *StateVersion
	version *StateVersion
}

// Base returns the immutable version from which this candidate was built.
func (c *StateCandidate) Base() *StateVersion {
	return c.base
}

// Version returns the unpublished immutable candidate version.
func (c *StateCandidate) Version() *StateVersion {
	return c.version
}

// SetPresence updates one candidate's runtime presence. userID must exist in
// the candidate projection and presence must use a protocol-supported status
// and activity privacy shape.
func (c *StateCandidate) SetPresence(userID int64, presence Presence) error {
	if c == nil || c.version == nil {
		return ErrInvalidProjection
	}
	if _, exists := c.version.persistent.users[userID]; !exists || !validPresence(presence) {
		return ErrInvalidProjection
	}
	c.version.runtime.presences[userID] = clonePresence(presence)
	return nil
}

// ClearPresence removes one user's runtime presence entry. It is used when an
// account-wide access revocation must publish offline before its user event;
// missing entries are intentionally a no-op.
func (c *StateCandidate) ClearPresence(userID int64) error {
	if c == nil || c.version == nil || userID <= 0 {
		return ErrInvalidProjection
	}
	delete(c.version.runtime.presences, userID)
	return nil
}

// IncrementModerationEpoch advances the server-global mute enforcement epoch
// for a persistent moderation mutation. Relay workers use this value to reject
// queued media validated before the new mute state was published.
func (c *StateCandidate) IncrementModerationEpoch() error {
	if c == nil || c.version == nil {
		return ErrInvalidProjection
	}
	c.version.runtime.moderationEpoch++
	return nil
}

// ScheduleTemporaryExpiry records a new empty-channel delete deadline and
// increments generation so stale callbacks cannot delete a rejoined channel.
func (c *StateCandidate) ScheduleTemporaryExpiry(channelID, deadline int64) (ExpirySchedule, error) {
	if c == nil || c.version == nil || deadline <= 0 {
		return ExpirySchedule{}, ErrInvalidProjection
	}
	channel, exists := c.version.persistent.channels[channelID]
	if !exists || !channel.Temporary {
		return ExpirySchedule{}, ErrInvalidProjection
	}
	previous := c.version.runtime.temporaryExpiry[channelID]
	schedule := ExpirySchedule{Generation: previous.Generation + 1, Deadline: deadline}
	c.version.runtime.temporaryExpiry[channelID] = schedule
	return schedule, nil
}

// ClearTemporaryExpiry invalidates a temporary channel's timer and returns the
// previous schedule so the owning service can cancel its external timer after
// this candidate becomes visible. It does not create a runtime entry when no
// timer or cancellation generation exists, and removes entries for channels
// that are no longer temporary.
func (c *StateCandidate) ClearTemporaryExpiry(channelID int64) (ExpirySchedule, bool) {
	if c == nil || c.version == nil {
		return ExpirySchedule{}, false
	}
	previous, exists := c.version.runtime.temporaryExpiry[channelID]
	channel, existsChannel := c.version.persistent.channels[channelID]
	if !existsChannel || !channel.Temporary || channel.Mode != "voice" {
		delete(c.version.runtime.temporaryExpiry, channelID)
		return previous, exists && previous.Generation > 0 && previous.Deadline > 0
	}
	if !exists {
		return ExpirySchedule{}, false
	}
	c.version.runtime.temporaryExpiry[channelID] = ExpirySchedule{Generation: previous.Generation + 1}
	return previous, previous.Generation > 0 && previous.Deadline > 0
}

// ScheduleMuteExpiry records an exact timed mute cleanup deadline.
func (c *StateCandidate) ScheduleMuteExpiry(muteID, deadline int64) (ExpirySchedule, error) {
	if c == nil || c.version == nil || deadline <= 0 {
		return ExpirySchedule{}, ErrInvalidProjection
	}
	mute, exists := c.version.persistent.mutes[muteID]
	if !exists || mute.ExpiresAt == nil || *mute.ExpiresAt != deadline {
		return ExpirySchedule{}, ErrInvalidProjection
	}
	previous := c.version.runtime.muteExpiry[muteID]
	schedule := ExpirySchedule{Generation: previous.Generation + 1, Deadline: deadline}
	c.version.runtime.muteExpiry[muteID] = schedule
	return schedule, nil
}

// ClearMuteExpiry invalidates an active mute cleanup timer.
func (c *StateCandidate) ClearMuteExpiry(muteID int64) {
	previous := c.version.runtime.muteExpiry[muteID]
	c.version.runtime.muteExpiry[muteID] = ExpirySchedule{Generation: previous.Generation + 1}
}

// SetVoiceAuthority conditionally stores authority as the candidate's runtime
// truth. A nil authority clears userID's binding. Non-nil values must be a
// complete tuple for an existing user and channel, so snapshots cannot expose
// a half-applied voice membership.
func (c *StateCandidate) SetVoiceAuthority(userID int64, authority *VoiceAuthority) error {
	if c == nil || c.version == nil || userID <= 0 {
		return ErrInvalidProjection
	}
	if authority == nil {
		delete(c.version.runtime.voiceAuthorities, userID)
		return nil
	}
	if authority.UserID != userID || !authority.Valid() {
		return ErrInvalidProjection
	}
	if _, exists := c.version.persistent.users[userID]; !exists {
		return ErrInvalidProjection
	}
	if _, exists := c.version.persistent.channels[authority.ChannelID]; !exists {
		return ErrInvalidProjection
	}
	c.version.runtime.voiceAuthorities[userID] = *authority
	return nil
}

// TransitionVoiceAuthority conditionally applies one exact coordinator tuple
// transition. A stale callback whose previous generation no longer matches the
// runtime version returns false without altering a newer voice binding.
func (c *StateCandidate) TransitionVoiceAuthority(previous, current *VoiceAuthority) (bool, error) {
	var userID int64
	if current != nil {
		userID = current.UserID
	} else if previous != nil {
		userID = previous.UserID
	}
	if userID <= 0 || (previous != nil && !previous.Valid()) || (current != nil && !current.Valid()) {
		return false, ErrInvalidProjection
	}
	existing, exists := c.version.runtime.voiceAuthorities[userID]
	if previous == nil {
		if exists {
			return false, nil
		}
	} else if !exists || existing != *previous {
		return false, nil
	}
	if err := c.SetVoiceAuthority(userID, current); err != nil {
		return false, err
	}
	return true, nil
}

// NewStreamEpoch returns a cryptographically random 128-bit stream epoch in
// the protocol's required lowercase hexadecimal representation.
func NewStreamEpoch() (string, error) {
	buf := make([]byte, streamEpochBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("realtime: generate stream epoch: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// newPersistentState converts SQL rows into a credential-free projection with
// private maps and copied optional values. Database foreign keys protect most
// references; this function still rejects duplicate primary keys so a faulty
// loader can never silently overwrite an immutable entity.
func newPersistentState(projection *store.StateProjection) (persistentState, error) {
	if projection == nil {
		return persistentState{}, fmt.Errorf("%w: nil loader result", ErrInvalidProjection)
	}
	state := persistentState{
		users:         make(map[int64]User, len(projection.Users)),
		roles:         make(map[string]Role, len(projection.Roles)),
		groups:        make(map[int64]Group, len(projection.Groups)),
		channels:      make(map[int64]Channel, len(projection.Channels)),
		groupAccess:   make(map[int64][]AccessEntry),
		channelAccess: make(map[int64][]AccessEntry),
		bindings:      make(map[int64][]RoleBinding),
		configs:       make(map[Scope]PermissionConfig, len(projection.Configs)),
		mutes:         make(map[int64]Mute, len(projection.Mutes)),
	}
	for _, row := range projection.Users {
		if _, exists := state.users[row.ID]; exists {
			return persistentState{}, duplicateProjection("user", fmt.Sprint(row.ID))
		}
		state.users[row.ID] = userFromDB(row)
	}
	for _, row := range projection.Roles {
		if _, exists := state.roles[row.Key]; exists {
			return persistentState{}, duplicateProjection("role", row.Key)
		}
		state.roles[row.Key] = roleFromDB(row)
	}
	for _, row := range projection.Groups {
		if _, exists := state.groups[row.ID]; exists {
			return persistentState{}, duplicateProjection("group", fmt.Sprint(row.ID))
		}
		state.groups[row.ID] = groupFromDB(row)
	}
	for _, row := range projection.Channels {
		if _, exists := state.channels[row.ID]; exists {
			return persistentState{}, duplicateProjection("channel", fmt.Sprint(row.ID))
		}
		state.channels[row.ID] = channelFromDB(row)
	}
	for _, row := range projection.GroupAccess {
		state.groupAccess[row.GroupID] = append(state.groupAccess[row.GroupID], accessFromGroupDB(row))
	}
	for _, row := range projection.ChannelAccess {
		state.channelAccess[row.ChannelID] = append(state.channelAccess[row.ChannelID], accessFromChannelDB(row))
	}
	for _, row := range projection.Bindings {
		binding, err := bindingFromDB(row)
		if err != nil {
			return persistentState{}, err
		}
		state.bindings[row.UserID] = append(state.bindings[row.UserID], binding)
	}
	for _, row := range projection.Configs {
		config, err := configFromDB(row)
		if err != nil {
			return persistentState{}, err
		}
		if _, exists := state.configs[config.Scope]; exists {
			return persistentState{}, duplicateProjection("permission config", config.Scope.Key())
		}
		state.configs[config.Scope] = config
	}
	for _, row := range projection.Mutes {
		mute, err := muteFromDB(row)
		if err != nil {
			return persistentState{}, err
		}
		if _, exists := state.mutes[mute.ID]; exists {
			return persistentState{}, duplicateProjection("mute", fmt.Sprint(mute.ID))
		}
		state.mutes[mute.ID] = mute
	}
	for userID := range state.bindings {
		sort.Slice(state.bindings[userID], func(i, j int) bool {
			return state.bindings[userID][i].ID < state.bindings[userID][j].ID
		})
	}
	for groupID := range state.groupAccess {
		sort.Slice(state.groupAccess[groupID], func(i, j int) bool {
			return state.groupAccess[groupID][i].ID < state.groupAccess[groupID][j].ID
		})
	}
	for channelID := range state.channelAccess {
		sort.Slice(state.channelAccess[channelID], func(i, j int) bool {
			return state.channelAccess[channelID][i].ID < state.channelAccess[channelID][j].ID
		})
	}
	return state, nil
}

// duplicateProjection constructs a stable projection-loader error.
func duplicateProjection(kind, id string) error {
	return fmt.Errorf("%w: duplicate %s %s", ErrInvalidProjection, kind, id)
}

// validateStreamEpoch checks the protocol's fixed epoch representation.
func validateStreamEpoch(streamEpoch string) error {
	if len(streamEpoch) != streamEpochBytes*2 || streamEpoch != strings.ToLower(streamEpoch) {
		return ErrInvalidStreamEpoch
	}
	decoded, err := hex.DecodeString(streamEpoch)
	if err != nil || len(decoded) != streamEpochBytes {
		return ErrInvalidStreamEpoch
	}
	return nil
}

// userFromDB removes credentials and converts nullable database values.
func userFromDB(row db.User) User {
	return User{
		ID:          row.ID,
		Username:    row.Username,
		Nickname:    row.Nickname,
		Avatar:      optionalString(row.Avatar),
		AuthVersion: row.AuthVersion,
		Banned:      row.BannedAt.Valid,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
}

// roleFromDB converts a persisted role to its immutable state representation.
func roleFromDB(row db.Role) Role {
	return Role{
		Key:         row.Key,
		DisplayName: row.DisplayName,
		Rank:        row.Rank,
		Builtin:     row.Builtin != 0,
		Immutable:   row.Immutable != 0,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
		Version:     row.Version,
	}
}

// groupFromDB converts a persisted group to its immutable state representation.
func groupFromDB(row db.ChannelGroup) Group {
	return Group{
		ID:         row.ID,
		Name:       row.Name,
		Position:   row.Position,
		Visibility: row.Visibility,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
		Version:    row.Version,
	}
}

// channelFromDB converts a persisted channel to its immutable state representation.
func channelFromDB(row db.Channel) Channel {
	return Channel{
		ID:         row.ID,
		GroupID:    optionalInt64(row.GroupID),
		Name:       row.Name,
		Mode:       row.Mode,
		Temporary:  row.Temporary != 0,
		Visibility: row.Visibility,
		Capacity:   row.Capacity,
		Position:   row.Position,
		Pinned:     row.Pinned != 0,
		CreatedBy:  optionalInt64(row.CreatedBy),
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
		Version:    row.Version,
	}
}

// accessFromGroupDB converts a group ACL row to its common representation.
func accessFromGroupDB(row db.GroupAccess) AccessEntry {
	return AccessEntry{
		ID:            row.ID,
		PrincipalType: row.PrincipalType,
		UserID:        optionalInt64(row.UserID),
		RoleKey:       optionalString(row.RoleKey),
		CreatedAt:     row.CreatedAt,
	}
}

// accessFromChannelDB converts a channel ACL row to its common representation.
func accessFromChannelDB(row db.ChannelAccess) AccessEntry {
	return AccessEntry{
		ID:            row.ID,
		PrincipalType: row.PrincipalType,
		UserID:        optionalInt64(row.UserID),
		RoleKey:       optionalString(row.RoleKey),
		CreatedAt:     row.CreatedAt,
	}
}

// bindingFromDB converts a scoped binding and verifies its exact scope shape.
func bindingFromDB(row db.UserRoleBinding) (RoleBinding, error) {
	scope, err := scopeFromNullable(row.ScopeType, row.GroupID.Valid, row.GroupID.Int64, row.ChannelID.Valid, row.ChannelID.Int64)
	if err != nil {
		return RoleBinding{}, err
	}
	return RoleBinding{ID: row.ID, RoleKey: row.RoleKey, Scope: scope, CreatedAt: row.CreatedAt}, nil
}

// configFromDB converts a local permission-config row and verifies its scope.
func configFromDB(row db.ScopePermissionConfig) (PermissionConfig, error) {
	scope, err := scopeFromNullable(row.ScopeType, row.GroupID.Valid, row.GroupID.Int64, row.ChannelID.Valid, row.ChannelID.Int64)
	if err != nil {
		return PermissionConfig{}, err
	}
	return PermissionConfig{Scope: scope, Config: row.Config, UpdatedAt: row.UpdatedAt, Version: row.Version}, nil
}

// muteFromDB converts a mute row and verifies its scope shape.
func muteFromDB(row db.ModerationMute) (Mute, error) {
	scope, err := scopeFromNullable(row.ScopeType, row.GroupID.Valid, row.GroupID.Int64, row.ChannelID.Valid, row.ChannelID.Int64)
	if err != nil {
		return Mute{}, err
	}
	return Mute{
		ID:        row.ID,
		Scope:     scope,
		UserID:    row.UserID,
		Kind:      row.Kind,
		ExpiresAt: optionalInt64(row.ExpiresAt),
		CreatedBy: optionalInt64(row.CreatedBy),
		Reason:    row.Reason,
		CreatedAt: row.CreatedAt,
		Version:   row.Version,
	}, nil
}

// scopeFromNullable converts the three database scope layouts into one Scope.
func scopeFromNullable(scopeType string, groupValid bool, groupID int64, channelValid bool, channelID int64) (Scope, error) {
	switch scopeType {
	case "server":
		if !groupValid && !channelValid {
			return Scope{Type: "server"}, nil
		}
	case "group":
		if groupValid && groupID > 0 && !channelValid {
			return Scope{Type: "group", ID: groupID}, nil
		}
	case "channel":
		if !groupValid && channelValid && channelID > 0 {
			return Scope{Type: "channel", ID: channelID}, nil
		}
	}
	return Scope{}, fmt.Errorf("%w: invalid %s scope", ErrInvalidProjection, scopeType)
}

// clone returns an independent copy of runtime state for an unpublished candidate.
func (r runtimeState) clone() runtimeState {
	cloned := runtimeState{
		visibilityEpochs: make(map[int64]uint64, len(r.visibilityEpochs)),
		moderationEpoch:  r.moderationEpoch,
		presences:        make(map[int64]Presence, len(r.presences)),
		voiceAuthorities: make(map[int64]VoiceAuthority, len(r.voiceAuthorities)),
		temporaryExpiry:  make(map[int64]ExpirySchedule, len(r.temporaryExpiry)),
		muteExpiry:       make(map[int64]ExpirySchedule, len(r.muteExpiry)),
	}
	for userID, epoch := range r.visibilityEpochs {
		cloned.visibilityEpochs[userID] = epoch
	}
	for userID, presence := range r.presences {
		cloned.presences[userID] = clonePresence(presence)
	}
	for userID, authority := range r.voiceAuthorities {
		cloned.voiceAuthorities[userID] = authority
	}
	for channelID, schedule := range r.temporaryExpiry {
		cloned.temporaryExpiry[channelID] = schedule
	}
	for muteID, schedule := range r.muteExpiry {
		cloned.muteExpiry[muteID] = schedule
	}
	return cloned
}

// validPresence enforces the v1 status and activity privacy vocabulary before
// data can become part of an immutable synchronized state version.
func validPresence(presence Presence) bool {
	switch presence.Status {
	case "online", "dnd", "afk", "offline", "invisible":
	default:
		return false
	}
	if presence.Activity == nil {
		return true
	}
	return presence.Activity.Type != "" && presence.Activity.Name != "" && (presence.Activity.Privacy == "public" || presence.Activity.Privacy == "private")
}

// clonePresence gives immutable state versions independent activity storage.
func clonePresence(presence Presence) Presence {
	cloned := presence
	if presence.Activity != nil {
		activity := *presence.Activity
		cloned.Activity = &activity
	}
	return cloned
}

// cloneUser returns a user with independent optional values.
func cloneUser(user User) User {
	user.Avatar = cloneString(user.Avatar)
	return user
}

// cloneChannel returns a channel with independent optional IDs.
func cloneChannel(channel Channel) Channel {
	channel.GroupID = cloneInt64(channel.GroupID)
	channel.CreatedBy = cloneInt64(channel.CreatedBy)
	return channel
}

// cloneAccessEntries returns ACL entries with independent optional principals.
func cloneAccessEntries(entries []AccessEntry) []AccessEntry {
	cloned := make([]AccessEntry, len(entries))
	for i, entry := range entries {
		cloned[i] = entry
		cloned[i].UserID = cloneInt64(entry.UserID)
		cloned[i].RoleKey = cloneString(entry.RoleKey)
	}
	return cloned
}

// cloneRoleBindings returns bindings with independent Scope values.
func cloneRoleBindings(bindings []RoleBinding) []RoleBinding {
	return append([]RoleBinding(nil), bindings...)
}

// cloneMute returns a mute with independent optional IDs and timestamps.
func cloneMute(mute Mute) Mute {
	mute.ExpiresAt = cloneInt64(mute.ExpiresAt)
	mute.CreatedBy = cloneInt64(mute.CreatedBy)
	return mute
}

// optionalInt64 converts one nullable database integer into an independent pointer.
func optionalInt64(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	got := value.Int64
	return &got
}

// optionalString converts one nullable database string into an independent pointer.
func optionalString(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	got := value.String
	return &got
}

// cloneInt64 copies an optional integer.
func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	got := *value
	return &got
}

// cloneString copies an optional string.
func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	got := *value
	return &got
}

// sortedIntKeys returns map keys in ascending numeric order.
func sortedIntKeys[T any](values map[int64]T) []int64 {
	keys := make([]int64, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
