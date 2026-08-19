package realtime

import (
	"errors"
	"sort"
	"sync"
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

// PublicationRequest supplies the complete unpublished state and event work
// for one linearized state command. VisibilityUserIDs must contain every user
// whose visible-scope set may change for this mutation.
type PublicationRequest struct {
	Candidate         *StateCandidate
	Events            []StateEventTemplate
	VisibilityUserIDs []int64
}

// PublicationResult describes the immutable state and replayable events made
// visible by one successful StatePublication commit.
type PublicationResult struct {
	Version           *StateVersion
	Checkpoint        Checkpoint
	Events            []StateEvent
	VisibilityChanges map[int64]VisibilityChange
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
	now        func() int64

	mu   sync.RWMutex
	hook PublicationHook
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

// Commit publishes request as the immediate successor to StateStore's current
// version. It allocates contiguous GEIDs, advances visibility epochs only for
// real visible-scope transitions, appends the ring, and swaps the state pointer
// without exposing a forward version that lacks its replayable events.
func (p *StatePublication) Commit(request PublicationRequest) (PublicationResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

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
	events, err := p.materializeEvents(request.Events, before.checkpoint.GEID)
	if err != nil {
		return PublicationResult{}, err
	}
	// Nothing outside this lock can observe after until the ring has accepted all
	// event refs. The candidate itself is unpublished, so updating its runtime
	// epochs and checkpoint here cannot leak a half-committed view.
	for userID, epoch := range epochs {
		after.runtime.visibilityEpochs[userID] = epoch
	}
	if len(events) != 0 {
		after.checkpoint.GEID = events[len(events)-1].GEID
	}
	p.callHook(PublicationBeforeRingAppend)
	if err := p.ring.Append(events); err != nil {
		return PublicationResult{}, err
	}
	p.callHook(PublicationAfterRingAppend)
	p.callHook(PublicationBeforeStateSwap)
	p.state.current.Store(after)
	p.callHook(PublicationAfterStateSwap)

	return PublicationResult{
		Version:           after,
		Checkpoint:        after.checkpoint,
		Events:            cloneStateEvents(events),
		VisibilityChanges: cloneVisibilityChanges(changes),
	}, nil
}

// Capture returns one version/ring pair while excluding a concurrent commit.
// Snapshot and replay callers must use it instead of separately reading
// StateStore.Current and StateRing.Snapshot.
func (p *StatePublication) Capture() PublicationSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
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
func (p *StatePublication) materializeEvents(templates []StateEventTemplate, baseGEID uint64) ([]StateEvent, error) {
	events := make([]StateEvent, len(templates))
	serverTime := p.now()
	for i, template := range templates {
		event, err := stateEventFromTemplate(template, baseGEID+uint64(i)+1, serverTime)
		if err != nil {
			return nil, err
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
