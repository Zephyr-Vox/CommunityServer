package realtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrInvalidPublication is returned when a publication lacks a candidate or
	// uses a candidate that cannot be the immediate successor of current state.
	ErrInvalidPublication = errors.New("realtime: invalid state publication")
	// ErrStaleStateCandidate is returned when another publication made the
	// candidate's base version obsolete before it reached the commit boundary.
	ErrStaleStateCandidate = errors.New("realtime: stale state candidate")
)

// PublicationStage identifies a test hook point inside StatePublication's
// commit lock. Hooks must not re-enter the publication and are intended only
// for deterministic barriers around otherwise atomic publication work.
type PublicationStage uint8

const (
	// PublicationBeforeRingAppend runs after candidate validation and before the
	// newly allocated events become visible in the ring.
	PublicationBeforeRingAppend PublicationStage = iota
	// PublicationAfterRingAppend runs after ring append but before StateStore's
	// current pointer is swapped to the candidate version.
	PublicationAfterRingAppend
	// PublicationBeforeStateSwap runs immediately before the current pointer is
	// made visible to lock-free StateStore readers.
	PublicationBeforeStateSwap
	// PublicationAfterStateSwap runs after StateStore has the new current
	// pointer, while this publication's capture lock is still held.
	PublicationAfterStateSwap
)

// PublicationHook observes one locked publication stage. It is called while
// StatePublication's lock is held and therefore must not call Commit, Capture,
// or SetHook on the same publication.
type PublicationHook func(PublicationStage)

// PublicationCaptureStage identifies a deterministic capture hook point. The
// before stage runs immediately before Capture attempts the publication read
// lock; the after stage runs after that lock has been acquired.
type PublicationCaptureStage uint8

const (
	// PublicationBeforeCaptureLock runs immediately before Capture calls RLock.
	PublicationBeforeCaptureLock PublicationCaptureStage = iota
	// PublicationAfterCaptureLock runs while Capture holds the read lock.
	PublicationAfterCaptureLock
)

// PublicationCaptureHook observes Capture's read-lock progress. It exists for
// deterministic concurrency tests; the after-lock callback must not call
// Capture or Commit on the same publication.
type PublicationCaptureHook func(PublicationCaptureStage)

type publicationCaptureHookValue struct {
	hook PublicationCaptureHook
}

// PublicationRequest supplies the complete unpublished state and event work
// for one linearized state command. VisibilityUserIDs must contain every user
// whose visible-scope set may change for this mutation.
type PublicationRequest struct {
	Candidate         *StateCandidate
	Events            []StateEventTemplate
	VisibilityUserIDs []int64
	// CommitRuntime applies a staged coordinator transition while the
	// publication lock excludes half-published state. It must not perform socket
	// I/O, UDP sends, or wait for another goroutine. Any returned cleanup runs
	// after the publication and delivery locks have been released.
	CommitRuntime func() (cleanup func(), err error)
}

// PublicationResult describes the immutable state and replayable events made
// visible by one successful StatePublication commit.
type PublicationResult struct {
	Version           *StateVersion
	Checkpoint        Checkpoint
	Events            []StateEvent
	VisibilityChanges map[int64]VisibilityChange
}

// PublicationReservation holds StatePublication's commit lock after all final
// event IDs, visibility epochs, and the successor checkpoint have been
// calculated. Persistent commands use Result while their database transaction
// is still rollbackable, then publish only after that transaction commits.
// Exactly one of Publish, PublishRuntime, or Abort releases the reservation.
type PublicationReservation struct {
	publication   *StatePublication
	result        PublicationResult
	runtimeCommit func() (cleanup func(), err error)

	mu        sync.Mutex
	completed bool
}

// PublicationSnapshot is one coherent capture of StateStore and ring state.
// It is the required read path for snapshot and replay code that must not pair
// a version with a different ring high-water mark.
type PublicationSnapshot struct {
	Version   *StateVersion
	Events    []StateEvent
	HighWater uint64
}

// StatePublication owns the sole in-process state commit boundary. It makes a
// candidate version, its checkpoint, ring entries and visibility epochs visible
// under one lock; immutable StateStore reads remain lock-free outside Capture.
type StatePublication struct {
	state      *StateStore
	ring       *StateRing
	visibility *VisibilityResolver
	eventBus   *EventBus
	now        func() int64

	mu          sync.RWMutex
	hook        PublicationHook
	captureHook atomic.Pointer[publicationCaptureHookValue]
}

// BindEventBus attaches the process-local live delivery registry to p. It must
// be called before connections may begin synchronization. A publication may
// only ever use one EventBus because its ring, cursor signer and live handoff
// share one stream epoch.
func (p *StatePublication) BindEventBus(eventBus *EventBus) error {
	if p == nil || eventBus == nil || eventBus.visibility != p.visibility {
		return ErrInvalidPublication
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.eventBus != nil && p.eventBus != eventBus {
		return ErrInvalidPublication
	}
	p.eventBus = eventBus
	return nil
}

// NewStatePublication creates the state commit boundary over state and ring.
// now is injectable for deterministic event timestamps; nil uses wall-clock
// Unix milliseconds.
func NewStatePublication(state *StateStore, ring *StateRing, visibility *VisibilityResolver, now func() int64) (*StatePublication, error) {
	if state == nil || state.Current() == nil || ring == nil || visibility == nil {
		return nil, ErrInvalidPublication
	}
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	if ring.HighWater() != state.Current().checkpoint.GEID {
		return nil, ErrInvalidPublication
	}
	return &StatePublication{state: state, ring: ring, visibility: visibility, now: now}, nil
}

// SetHook replaces the deterministic test hook. It waits for any in-flight
// publication, so a newly installed hook cannot observe a partial commit.
func (p *StatePublication) SetHook(hook PublicationHook) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hook = hook
}

// SetCaptureHook installs a deterministic read-side hook. It is safe to call
// concurrently with Capture; an in-flight capture keeps the hook value it
// loaded before attempting the publication lock.
func (p *StatePublication) SetCaptureHook(hook PublicationCaptureHook) {
	if hook == nil {
		p.captureHook.Store(nil)
		return
	}
	p.captureHook.Store(&publicationCaptureHookValue{hook: hook})
}

// Commit reserves and immediately publishes request as the immediate successor
// to StateStore's current version. Persistent commands must instead Reserve
// before their database commit so their durable result can contain this exact
// checkpoint and a cursor signed from the final visibility epoch.
func (p *StatePublication) Commit(request PublicationRequest) (PublicationResult, error) {
	reservation, err := p.Reserve(request)
	if err != nil {
		return PublicationResult{}, err
	}
	return reservation.Publish()
}

// Reserve calculates request's final StatePublication result and keeps the
// publication lock held without making it visible. The caller must use the
// returned result only to persist facts that belong to the same database
// transaction, then call Publish after commit or Abort on every rollback path.
func (p *StatePublication) Reserve(request PublicationRequest) (*PublicationReservation, error) {
	p.mu.Lock()
	result, err := p.reserveLocked(request)
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	return &PublicationReservation{publication: p, result: result, runtimeCommit: request.CommitRuntime}, nil
}

// Result returns an independent copy of the final, still-unpublished result.
// Its Version carries the final visibility epochs needed to issue response
// cursors in the enclosing rollbackable transaction.
func (r *PublicationReservation) Result() PublicationResult {
	if r == nil {
		return PublicationResult{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return clonePublicationResult(r.result)
}

// Abort discards r's unpublished work and releases its publication lock. It is
// idempotent so transaction rollback defers may safely call it after errors.
func (r *PublicationReservation) Abort() {
	if !r.claimCompletion() {
		return
	}
	r.publication.mu.Unlock()
}

// Publish makes r's precomputed state, ring entries, and visibility epochs
// visible as one atomic publication. It must run only after the enclosing
// persistent transaction commits; callers treat an error as process-fatal.
func (r *PublicationReservation) Publish() (PublicationResult, error) {
	return r.publish(nil)
}

// PublishRuntime publishes a runtime-only reservation unless ctx was canceled
// before the first ring mutation. The cancellation check immediately before
// ring append is the runtime command's commit linearization point; cancellation
// after that point cannot roll back an already-started atomic publication.
func (r *PublicationReservation) PublishRuntime(ctx context.Context) (PublicationResult, error) {
	if ctx == nil {
		return PublicationResult{}, ErrInvalidPublication
	}
	return r.publish(ctx)
}

// publish completes one reservation. A non-nil runtimeCtx is checked after the
// before-append test hook and immediately before any externally observable
// mutation; persistent publications pass nil because their DB commit is final.
func (r *PublicationReservation) publish(runtimeCtx context.Context) (result PublicationResult, err error) {
	if !r.claimCompletion() {
		return PublicationResult{}, ErrInvalidPublication
	}

	p := r.publication
	var slow []StateSyncConnection
	var cleanup func()
	defer func() {
		p.mu.Unlock()
		for _, connection := range slow {
			connection.DisconnectSlowConsumer()
		}
		if err == nil && cleanup != nil {
			cleanup()
		}
	}()
	p.callHook(PublicationBeforeRingAppend)
	if runtimeCtx != nil {
		if err = runtimeCtx.Err(); err != nil {
			return PublicationResult{}, err
		}
	}
	if r.runtimeCommit != nil {
		cleanup, err = r.runtimeCommit()
		if err != nil {
			return PublicationResult{}, err
		}
	}
	if err = p.ring.Append(r.result.Events); err != nil {
		return PublicationResult{}, err
	}
	p.callHook(PublicationAfterRingAppend)
	p.callHook(PublicationBeforeStateSwap)
	p.state.current.Store(r.result.Version)
	p.callHook(PublicationAfterStateSwap)
	if p.eventBus != nil {
		slow, err = p.eventBus.fanout(r.result.Version, r.result.Events, r.result.VisibilityChanges)
		if err != nil {
			return PublicationResult{}, err
		}
	}
	return clonePublicationResult(r.result), nil
}

// claimCompletion grants the one release operation for r. The corresponding
// StatePublication lock is intentionally acquired by Reserve and released by
// the winning caller, preventing another state command from changing its final
// checkpoint between durable persistence and publication.
func (r *PublicationReservation) claimCompletion() bool {
	if r == nil || r.publication == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.completed {
		return false
	}
	r.completed = true
	return true
}

// reserveLocked calculates one final publication while p.mu is held. It leaves
// the calculated version unpublished so a transaction can atomically persist a
// response containing its final checkpoint before Publish exposes it.
func (p *StatePublication) reserveLocked(request PublicationRequest) (PublicationResult, error) {

	if request.Candidate == nil || request.Candidate.base == nil || request.Candidate.version == nil {
		return PublicationResult{}, ErrInvalidPublication
	}
	before := p.state.Current()
	if request.Candidate.base != before {
		return PublicationResult{}, ErrStaleStateCandidate
	}
	// Keep the caller-owned candidate immutable. The committed version gets a
	// fresh runtime map and checkpoint, so a barrier test or future reader that
	// still inspects the unpublished candidate cannot race this commit.
	after := &StateVersion{
		number:     request.Candidate.version.number,
		checkpoint: request.Candidate.version.checkpoint,
		persistent: request.Candidate.version.persistent,
		runtime:    request.Candidate.version.runtime.clone(),
	}
	if after.number != before.number+1 || after.checkpoint.StreamEpoch != before.checkpoint.StreamEpoch || p.ring.HighWater() != before.checkpoint.GEID {
		return PublicationResult{}, ErrInvalidPublication
	}

	changes, epochs, err := p.visibilityChanges(before, after, request.VisibilityUserIDs)
	if err != nil {
		return PublicationResult{}, err
	}
	// Transition serialization needs both the old version and the candidate's
	// final epoch. Updating the unpublished candidate here cannot leak because
	// the publication lock still excludes every snapshot and subscriber.
	for userID, epoch := range epochs {
		after.runtime.visibilityEpochs[userID] = epoch
	}
	templates, err := appendVisibilityTransitions(request.Events, before, after, changes)
	if err != nil {
		return PublicationResult{}, err
	}
	events, err := p.materializeEvents(templates, before.checkpoint.GEID, after)
	if err != nil {
		return PublicationResult{}, err
	}
	overrides := make([]cursorVisibilityEpoch, 0, len(changes))
	for _, userID := range sortedIntKeys(changes) {
		overrides = append(overrides, cursorVisibilityEpoch{userID: userID, epoch: before.VisibilityEpoch(userID)})
	}
	for index := range events {
		if events[index].HasCursorVisibilityEpoch || len(changes) == 0 {
			continue
		}
		events[index].cursorVisibilityEpochs = overrides
	}
	// Nothing outside this lock can observe after until the ring has accepted all
	// event refs. The candidate itself is unpublished, so updating its runtime
	// epochs and checkpoint here cannot leak a half-committed view.
	if len(events) != 0 {
		after.checkpoint.GEID = events[len(events)-1].GEID
	}
	if err := p.ring.ValidateAppend(events); err != nil {
		return PublicationResult{}, err
	}
	return PublicationResult{
		Version:           after,
		Checkpoint:        after.checkpoint,
		Events:            cloneStateEvents(events),
		VisibilityChanges: cloneVisibilityChanges(changes),
	}, nil
}

const maxVisibilityFragmentBytes = 128 << 10

// appendVisibilityTransitions adds recipient-targeted revoke/grant control
// events after caller-supplied mutation events. All transition scope events use
// the old epoch; exactly one complete event per affected user uses the new
// epoch, making persistence of that cursor proof that every fragment arrived.
func appendVisibilityTransitions(templates []StateEventTemplate, before, after *StateVersion, changes map[int64]VisibilityChange) ([]StateEventTemplate, error) {
	combined := append([]StateEventTemplate(nil), templates...)
	causationID := int64(0)
	for _, template := range templates {
		if template.CausationID != 0 {
			causationID = template.CausationID
			break
		}
	}
	userIDs := sortedIntKeys(changes)
	for _, userID := range userIDs {
		change := changes[userID]
		oldEpoch := before.VisibilityEpoch(userID)
		newEpoch := after.VisibilityEpoch(userID)
		for _, scope := range change.Revoked {
			data, err := marshalVisibilityScope(scope)
			if err != nil {
				return nil, err
			}
			combined = append(combined,
				directTransitionTemplate("visibility.tombstone", scope, userID, oldEpoch, causationID, data),
				directTransitionTemplate("visibility.revoked", scope, userID, oldEpoch, causationID, data),
			)
		}
		for _, scope := range change.Granted {
			data, err := marshalVisibilityScope(scope)
			if err != nil {
				return nil, err
			}
			combined = append(combined, directTransitionTemplate("visibility.grant.begin", scope, userID, oldEpoch, causationID, data))
			fragments, err := visibilityFragmentPayloads(userID, scope, after)
			if err != nil {
				return nil, err
			}
			fragmentID := fmt.Sprintf("%d-%d-%s", userID, after.Number(), scope.Key())
			for index, fragment := range fragments {
				data, err := json.Marshal(struct {
					FragmentID string          `json:"fragment_id"`
					Scope      eventScope      `json:"scope"`
					PartIndex  int             `json:"part_index"`
					PartCount  int             `json:"part_count"`
					Data       json.RawMessage `json:"data"`
				}{
					FragmentID: fragmentID,
					Scope:      stateEventScope(scope),
					PartIndex:  index,
					PartCount:  len(fragments),
					Data:       fragment,
				})
				if err != nil || len(data) > maxVisibilityFragmentBytes {
					return nil, ErrStateEventTooLarge
				}
				combined = append(combined, directTransitionTemplate("visibility.fragment", scope, userID, oldEpoch, causationID, data))
			}
			combined = append(combined, directTransitionTemplate("visibility.granted", scope, userID, oldEpoch, causationID, mustMarshalVisibilityScope(scope)))
		}
		digest := visibilityChangeDigest(change)
		data, err := json.Marshal(struct {
			ChangedScopeIDsDigest string `json:"changed_scope_ids_digest"`
		}{ChangedScopeIDsDigest: digest})
		if err != nil {
			return nil, err
		}
		combined = append(combined, directTransitionTemplate("visibility.transition.complete", Scope{Type: "server"}, userID, newEpoch, causationID, data))
	}
	return combined, nil
}

// directTransitionTemplate creates one ring event delivered only to userID.
func directTransitionTemplate(eventType string, scope Scope, userID int64, epoch uint64, causationID int64, data json.RawMessage) StateEventTemplate {
	return StateEventTemplate{
		EventType:                eventType,
		Scope:                    scope,
		CausationID:              causationID,
		Data:                     data,
		DeliveryPolicy:           StateDeliveryDirectTransition,
		RecipientUserID:          userID,
		CursorVisibilityEpoch:    epoch,
		HasCursorVisibilityEpoch: true,
	}
}

// marshalVisibilityScope encodes one sanitized scope reference for transition
// control events without exposing names, ACLs, or membership data.
func marshalVisibilityScope(scope Scope) (json.RawMessage, error) {
	data, err := json.Marshal(struct {
		Scope eventScope `json:"scope"`
	}{Scope: stateEventScope(scope)})
	return data, err
}

// mustMarshalVisibilityScope is used only after a matching marshal succeeded
// for the same validated scope in appendVisibilityTransitions.
func mustMarshalVisibilityScope(scope Scope) json.RawMessage {
	data, _ := marshalVisibilityScope(scope)
	return data
}

// visibilityChangeDigest produces the fixed SHA-256 digest of all scopes
// changed for one user by one mutation.
func visibilityChangeDigest(change VisibilityChange) string {
	lines := make([]string, 0, len(change.Granted)+len(change.Revoked))
	for _, scope := range change.Granted {
		lines = append(lines, scope.Key()+"\n")
	}
	for _, scope := range change.Revoked {
		lines = append(lines, scope.Key()+"\n")
	}
	sort.Strings(lines)
	hash := sha256.Sum256([]byte(joinStrings(lines)))
	return hex.EncodeToString(hash[:])
}

// joinStrings avoids allocating a formatting buffer for the deterministic
// visibility digest input.
func joinStrings(values []string) string {
	length := 0
	for _, value := range values {
		length += len(value)
	}
	buffer := make([]byte, 0, length)
	for _, value := range values {
		buffer = append(buffer, value...)
	}
	return string(buffer)
}

// visibilityFragmentPayloads returns replace-style scope subsets split so each
// embedded data field remains within the 128 KiB fragment hard limit.
func visibilityFragmentPayloads(userID int64, scope Scope, version *StateVersion) ([]json.RawMessage, error) {
	state := snapshotStateFor(userID, version, NewVisibilityResolver())
	switch scope.Type {
	case "group":
		var group SnapshotGroup
		found := false
		for _, candidate := range state.Groups {
			if candidate.ID == fmt.Sprint(scope.ID) {
				group, found = candidate, true
				break
			}
		}
		if !found {
			return nil, ErrInvalidPublication
		}
		childIDs := make([]string, 0)
		for _, channel := range state.Channels {
			if channel.GroupID != nil && *channel.GroupID == group.ID {
				childIDs = append(childIDs, channel.ID)
			}
		}
		// Fragment replace semantics require the stable snapshot ordering: the
		// display accessor sorts by position, so re-sort by numeric ID here.
		sort.Slice(childIDs, func(i, j int) bool { return childIDs[i] < childIDs[j] })
		return splitGroupFragment(group, childIDs)
	case "channel":
		for _, channel := range state.Channels {
			if channel.ID != fmt.Sprint(scope.ID) {
				continue
			}
			var parent *SnapshotGroup
			if channel.GroupID != nil {
				for _, group := range state.Groups {
					if group.ID == *channel.GroupID {
						copy := group
						parent = &copy
						break
					}
				}
			}
			members := make([]SnapshotVoiceMembership, 0)
			for _, membership := range state.VoiceMemberships {
				if membership.ChannelID == channel.ID {
					members = append(members, membership)
				}
			}
			data, err := json.Marshal(struct {
				ParentShell *SnapshotGroup            `json:"parent_shell,omitempty"`
				Channel     SnapshotChannel           `json:"channel"`
				Members     []SnapshotVoiceMembership `json:"members"`
			}{ParentShell: parent, Channel: channel, Members: members})
			if err != nil || len(data) > maxVisibilityFragmentBytes {
				return nil, ErrStateEventTooLarge
			}
			return []json.RawMessage{data}, nil
		}
	}
	return nil, ErrInvalidPublication
}

// splitGroupFragment creates one or more independently valid group fragments.
func splitGroupFragment(group SnapshotGroup, childIDs []string) ([]json.RawMessage, error) {
	encode := func(ids []string) (json.RawMessage, error) {
		return json.Marshal(struct {
			Group           SnapshotGroup `json:"group"`
			VisibleChildIDs []string      `json:"visible_child_ids"`
		}{Group: group, VisibleChildIDs: ids})
	}
	if len(childIDs) == 0 {
		data, err := encode([]string{})
		if err != nil || len(data) > maxVisibilityFragmentBytes {
			return nil, ErrStateEventTooLarge
		}
		return []json.RawMessage{data}, nil
	}
	parts := make([]json.RawMessage, 0, 1)
	start := 0
	for start < len(childIDs) {
		end := start + 1
		for end <= len(childIDs) {
			data, err := encode(childIDs[start:end])
			if err != nil {
				return nil, err
			}
			if len(data) > maxVisibilityFragmentBytes {
				if end == start+1 {
					return nil, ErrStateEventTooLarge
				}
				end--
				data, err = encode(childIDs[start:end])
				if err != nil {
					return nil, err
				}
				parts = append(parts, data)
				start = end
				break
			}
			if end == len(childIDs) {
				parts = append(parts, data)
				start = end
				break
			}
			end++
		}
	}
	return parts, nil
}

// Capture returns one version/ring pair while excluding a concurrent commit.
// Snapshot and replay callers must use it instead of separately reading
// StateStore.Current and StateRing.Snapshot.
func (p *StatePublication) Capture() PublicationSnapshot {
	hookValue := p.captureHook.Load()
	if hookValue != nil {
		hookValue.hook(PublicationBeforeCaptureLock)
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if hookValue != nil {
		hookValue.hook(PublicationAfterCaptureLock)
	}
	events, highWater := p.ring.Snapshot()
	return PublicationSnapshot{Version: p.state.Current(), Events: events, HighWater: highWater}
}

// visibilityChanges calculates the requested transitions and the next epochs
// without mutating the unpublished candidate until every publication check has
// succeeded.
func (p *StatePublication) visibilityChanges(before, after *StateVersion, userIDs []int64) (map[int64]VisibilityChange, map[int64]uint64, error) {
	ids := sortedUniqueUserIDs(userIDs)
	changes := make(map[int64]VisibilityChange)
	epochs := make(map[int64]uint64)
	for _, userID := range ids {
		if userID <= 0 {
			return nil, nil, ErrInvalidPublication
		}
		change := p.visibility.Diff(userID, before, after)
		if !change.Changed() {
			continue
		}
		changes[userID] = change
		epochs[userID] = before.runtime.visibilityEpochs[userID] + 1
	}
	return changes, epochs, nil
}

// materializeEvents assigns publication-owned GEIDs and one event timestamp to
// each event in request. The all-or-nothing result is validated before ring
// mutation, so invalid event data cannot consume a GEID.
func (p *StatePublication) materializeEvents(templates []StateEventTemplate, baseGEID uint64, version *StateVersion) ([]StateEvent, error) {
	events := make([]StateEvent, len(templates))
	serverTime := p.now()
	for i, template := range templates {
		event, err := stateEventFromTemplate(template, baseGEID+uint64(i)+1, serverTime)
		if err != nil {
			return nil, err
		}
		if template.SubjectUserID > 0 {
			if user, ok := version.User(template.SubjectUserID); ok {
				event.subjectState = &eventSubjectState{user: user, presence: version.Presence(template.SubjectUserID)}
			}
		}
		events[i] = event
	}
	return events, nil
}

// callHook invokes the current hook while the publication lock is held.
func (p *StatePublication) callHook(stage PublicationStage) {
	if p.hook != nil {
		p.hook(stage)
	}
}

// sortedUniqueUserIDs creates the deterministic mutation target set used for
// visibility updates. The caller's slice is never retained or reordered.
func sortedUniqueUserIDs(userIDs []int64) []int64 {
	ids := append([]int64(nil), userIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) == 0 {
		return nil
	}
	unique := ids[:1]
	for _, userID := range ids[1:] {
		if userID != unique[len(unique)-1] {
			unique = append(unique, userID)
		}
	}
	return unique
}

// cloneVisibilityChanges returns independent scope slices for publication
// callers that retain results beyond subsequent command processing.
func cloneVisibilityChanges(changes map[int64]VisibilityChange) map[int64]VisibilityChange {
	cloned := make(map[int64]VisibilityChange, len(changes))
	for userID, change := range changes {
		cloned[userID] = VisibilityChange{
			Granted: append([]Scope(nil), change.Granted...),
			Revoked: append([]Scope(nil), change.Revoked...),
		}
	}
	return cloned
}

// clonePublicationResult copies collection fields that callers may retain or
// mutate. StateVersion is immutable by contract and is therefore shared.
func clonePublicationResult(result PublicationResult) PublicationResult {
	return PublicationResult{
		Version:           result.Version,
		Checkpoint:        result.Checkpoint,
		Events:            cloneStateEvents(result.Events),
		VisibilityChanges: cloneVisibilityChanges(result.VisibilityChanges),
	}
}
