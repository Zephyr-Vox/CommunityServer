package realtime

import (
	"bytes"
	"errors"
	"sort"
	"sync"
)

var (
	// ErrInvalidEventBus is returned when an EventBus or sync connection lacks
	// the process-local dependencies required for ordered state delivery.
	ErrInvalidEventBus = errors.New("realtime: invalid event bus")
	// ErrEventBusClosed is returned after EventBus shutdown has removed every
	// live subscription and rejected later sync attempts.
	ErrEventBusClosed = errors.New("realtime: event bus closed")
	// ErrSyncConnectionExists is returned when one exact connection generation
	// already has an in-progress or live state subscription.
	ErrSyncConnectionExists = errors.New("realtime: sync connection already registered")
	// ErrSyncAttemptClosed is returned when disconnect or shutdown invalidated a
	// sync attempt before its replay batch reached the connection queue.
	ErrSyncAttemptClosed = errors.New("realtime: sync attempt closed")
	// ErrEventConsumerSlow is returned after one connection cannot admit its
	// bounded replay/live handoff. The global publication remains committed.
	ErrEventConsumerSlow = errors.New("realtime: event consumer slow")
)

// StateDeliveryPolicy controls final queue handling for one state item.
type StateDeliveryPolicy uint8

const (
	// StateDeliveryControl identifies replay and sync control frames that are not
	// tied to one scope and must not be removed by a later visibility revoke.
	StateDeliveryControl StateDeliveryPolicy = iota + 1
	// StateDeliveryVisibleAfter identifies ordinary state events selected from
	// the publication's after-version visibility projection.
	StateDeliveryVisibleAfter
	// StateDeliveryDirectTransition identifies sanitized visibility transition
	// events addressed directly to one user rather than resolved by scope ACL.
	StateDeliveryDirectTransition
	// StateDeliveryUserTargeted identifies a non-transition event addressed to
	// exactly one user. It uses ordinary cursor semantics and is never pruned as
	// a visibility replacement control item.
	StateDeliveryUserTargeted
)

// StateQueueItem is one immutable connection-local delivery unit. Scope and
// policy let a visibility revoke prune unclaimed private payload atomically;
// recipient, generation and cursor epoch retain the final-delivery proof needed
// by direct transitions in the next visibility layer.
type StateQueueItem struct {
	Frame                 []byte
	Scope                 Scope
	GEID                  uint64
	Policy                StateDeliveryPolicy
	RecipientUserID       int64
	ConnectionGeneration  uint64
	CursorVisibilityEpoch uint64
}

// StateSyncConnection is one exact control-connection generation's bounded
// state delivery sink. ApplyStateBatch must prune revoked scopes and append the
// full item batch under one non-blocking queue gate; DisconnectSlowConsumer must
// converge on ConnectionCoordinator.BeginDisconnect rather than writing a
// socket directly.
type StateSyncConnection interface {
	// ControlRef returns the immutable connection identity for this sink.
	ControlRef() ControlConnectionRef
	// ApplyStateBatch prunes unclaimed visible-after items for revoked scopes,
	// then atomically admits items in slice order. A false result may retain the
	// privacy-preserving prune but must not retain a partial append.
	ApplyStateBatch(revoked []Scope, items []StateQueueItem) bool
	// DisconnectSlowConsumer requests this connection's terminal 4006 close.
	DisconnectSlowConsumer()
}

type eventSubscriptionPhase uint8

const (
	eventSubscriptionSyncing eventSubscriptionPhase = iota + 1
	eventSubscriptionLive
)

// EventBus owns process-local state subscriptions and their replay-to-live
// delivery gates. StatePublication calls fanout while holding its publication
// lock; EventBus never blocks waiting for queue capacity or socket I/O.
type EventBus struct {
	signer     *CursorSigner
	visibility *VisibilityResolver

	mu            sync.Mutex
	closed        bool
	subscriptions map[ControlConnectionRef]*eventSubscription
}

type eventSubscription struct {
	connection StateSyncConnection
	ref        ControlConnectionRef

	gate            sync.Mutex
	active          bool
	phase           eventSubscriptionPhase
	pending         []StateQueueItem
	pendingBytes    int
	visibilityEpoch uint64
	visibleScopes   map[Scope]struct{}
}

type eventSyncAttempt struct {
	bus          *EventBus
	subscription *eventSubscription
}

// NewEventBus creates an empty process-local state delivery registry. signer
// and visibility must belong to the same stream epoch and immutable projection
// used by the StatePublication that later binds this bus.
func NewEventBus(signer *CursorSigner, visibility *VisibilityResolver) (*EventBus, error) {
	if signer == nil || visibility == nil {
		return nil, ErrInvalidEventBus
	}
	return &EventBus{
		signer:        signer,
		visibility:    visibility,
		subscriptions: make(map[ControlConnectionRef]*eventSubscription),
	}, nil
}

// Close rejects later sync attempts and invalidates every current subscription.
// It is idempotent and performs no socket I/O; process shutdown closes control
// connections through ConnectionCoordinator before stopping the EventBus.
func (b *EventBus) Close() {
	if b == nil {
		return
	}
	subscriptions := b.snapshotAndClose()
	lockSubscriptions(subscriptions)
	for _, subscription := range subscriptions {
		subscription.active = false
		subscription.pending = nil
		subscription.pendingBytes = 0
	}
	unlockSubscriptions(subscriptions)
}

// beginSync registers connection in syncing state before StatePublication
// releases the capture lock. Later publications therefore append to pending
// delivery instead of escaping between replay capture and live registration.
func (b *EventBus) beginSync(connection StateSyncConnection, version *StateVersion) (*eventSyncAttempt, error) {
	if b == nil || connection == nil || version == nil {
		return nil, ErrInvalidEventBus
	}
	ref := connection.ControlRef()
	if !validConnectionRef(ref) {
		return nil, ErrInvalidConnection
	}
	subscription := &eventSubscription{
		connection:      connection,
		ref:             ref,
		active:          true,
		phase:           eventSubscriptionSyncing,
		visibilityEpoch: version.VisibilityEpoch(ref.UserID),
		visibleScopes:   scopesToSet(b.visibility.VisibleScopeIDs(ref.UserID, version)),
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrEventBusClosed
	}
	if _, exists := b.subscriptions[ref]; exists {
		return nil, ErrSyncConnectionExists
	}
	b.subscriptions[ref] = subscription
	return &eventSyncAttempt{bus: b, subscription: subscription}, nil
}

// completeSync atomically places replay frames and sync.complete before every
// state event published after the captured high-water mark, then changes the
// subscription to live. Any capacity failure removes only this connection.
func (b *EventBus) completeSync(attempt *eventSyncAttempt, handoff [][]byte) error {
	if b == nil || attempt == nil || attempt.bus != b || attempt.subscription == nil {
		return ErrInvalidEventBus
	}
	subscription := attempt.subscription
	subscription.gate.Lock()
	if !subscription.active || subscription.phase != eventSubscriptionSyncing {
		subscription.gate.Unlock()
		return ErrSyncAttemptClosed
	}
	combined := controlQueueItems(handoff, subscription.ref, subscription.visibilityEpoch)
	combined = append(combined, cloneStateQueueItems(subscription.pending)...)
	if !stateItemBatchWithinLimits(combined) || !subscription.connection.ApplyStateBatch(nil, combined) {
		subscription.active = false
		subscription.pending = nil
		subscription.pendingBytes = 0
		subscription.gate.Unlock()
		b.remove(subscription)
		subscription.connection.DisconnectSlowConsumer()
		return ErrEventConsumerSlow
	}
	subscription.phase = eventSubscriptionLive
	subscription.pending = nil
	subscription.pendingBytes = 0
	subscription.gate.Unlock()
	return nil
}

// abortSync removes an unfinished attempt. It cannot remove a later connection
// generation or a subscription that already completed its live handoff.
func (b *EventBus) abortSync(attempt *eventSyncAttempt) {
	if b == nil || attempt == nil || attempt.bus != b || attempt.subscription == nil {
		return
	}
	subscription := attempt.subscription
	subscription.gate.Lock()
	if subscription.phase == eventSubscriptionSyncing {
		subscription.active = false
		subscription.pending = nil
		subscription.pendingBytes = 0
	}
	subscription.gate.Unlock()
	b.remove(subscription)
}

// unsubscribe removes exactly ref's syncing or live subscription. Frames
// already claimed by the sole writer remain ordered before terminal close;
// later publications cannot enqueue more work for this generation.
func (b *EventBus) unsubscribe(ref ControlConnectionRef) {
	if b == nil || !validConnectionRef(ref) {
		return
	}
	b.mu.Lock()
	subscription := b.subscriptions[ref]
	if subscription != nil {
		delete(b.subscriptions, ref)
	}
	b.mu.Unlock()
	if subscription == nil {
		return
	}
	subscription.gate.Lock()
	subscription.active = false
	subscription.pending = nil
	subscription.pendingBytes = 0
	subscription.gate.Unlock()
}

// fanout materializes one committed publication for every registered
// connection. The caller holds StatePublication's write lock. It returns slow
// consumers for teardown after that lock is released; ordinary backpressure
// never rolls back the globally committed version or ring.
func (b *EventBus) fanout(version *StateVersion, events []StateEvent, visibilityChanges map[int64]VisibilityChange) ([]StateSyncConnection, error) {
	if b == nil || version == nil {
		return nil, ErrInvalidEventBus
	}
	subscriptions := b.snapshotSubscriptions()
	lockSubscriptions(subscriptions)
	var slowSubscriptions []*eventSubscription
	for _, subscription := range subscriptions {
		if !subscription.active {
			continue
		}
		visibilityChange := visibilityChanges[subscription.ref.UserID]
		items, oversized, err := b.liveItems(subscription.ref, version, events, visibilityChange)
		if err != nil {
			unlockSubscriptions(subscriptions)
			return nil, err
		}
		revoked := visibilityChange.Revoked
		if visibilityChange.Changed() {
			subscription.visibilityEpoch = version.VisibilityEpoch(subscription.ref.UserID)
			subscription.visibleScopes = scopesToSet(b.visibility.VisibleScopeIDs(subscription.ref.UserID, version))
		}
		if oversized {
			if len(revoked) != 0 {
				_ = subscription.connection.ApplyStateBatch(revoked, nil)
			}
			subscription.active = false
			slowSubscriptions = append(slowSubscriptions, subscription)
			continue
		}
		if len(items) == 0 && len(revoked) == 0 {
			continue
		}
		switch subscription.phase {
		case eventSubscriptionSyncing:
			if !subscription.appendPending(revoked, items) {
				subscription.active = false
				slowSubscriptions = append(slowSubscriptions, subscription)
			}
		case eventSubscriptionLive:
			if !subscription.connection.ApplyStateBatch(revoked, items) {
				subscription.active = false
				slowSubscriptions = append(slowSubscriptions, subscription)
			}
		default:
			unlockSubscriptions(subscriptions)
			return nil, ErrInvalidEventBus
		}
	}
	unlockSubscriptions(subscriptions)

	slow := make([]StateSyncConnection, 0, len(slowSubscriptions))
	for _, subscription := range slowSubscriptions {
		b.remove(subscription)
		slow = append(slow, subscription.connection)
	}
	return slow, nil
}

// liveItems creates bounded recipient queue items and filters normal state
// events against the same immutable visibility resolver used by snapshots and
// replay. oversized reports connection backpressure without allocating beyond
// the fixed state queue budget.
func (b *EventBus) liveItems(ref ControlConnectionRef, version *StateVersion, events []StateEvent, visibilityChange VisibilityChange) ([]StateQueueItem, bool, error) {
	items := make([]StateQueueItem, 0, min(len(events), MaxWebSocketStateItems))
	bytes := 0
	checkpoint := version.Checkpoint()
	for _, event := range events {
		if !eventVisibleTo(ref.UserID, event, version, b.visibility) {
			continue
		}
		cursorEpoch := cursorEpochForEvent(event, ref.UserID, version)
		cursor, err := b.signer.Issue(ref.UserID, Checkpoint{StreamEpoch: checkpoint.StreamEpoch, GEID: event.GEID}, cursorEpoch)
		if err != nil {
			return nil, false, err
		}
		frame, err := encodeEventForRecipient(event, ref.UserID, version, cursor)
		if err != nil {
			return nil, false, err
		}
		if len(items)+1 > MaxWebSocketStateItems || bytes+len(frame) > MaxWebSocketStateBytes {
			return nil, true, nil
		}
		policy := StateDeliveryVisibleAfter
		if event.DeliveryPolicy == StateDeliveryDirectTransition {
			policy = StateDeliveryDirectTransition
		} else if event.DeliveryPolicy == StateDeliveryUserTargeted {
			policy = StateDeliveryUserTargeted
		}
		items = append(items, StateQueueItem{
			Frame:                 frame,
			Scope:                 event.Scope,
			GEID:                  event.GEID,
			Policy:                policy,
			RecipientUserID:       ref.UserID,
			ConnectionGeneration:  ref.Generation,
			CursorVisibilityEpoch: cursorEpoch,
		})
		bytes += len(frame)
	}
	return items, false, nil
}

// cursorEpochForEvent returns the persisted proof epoch for one recipient. A
// direct visibility transition carries its explicit old/new epoch. Ordinary
// events produced by that same visibility-changing publication retain the
// recipient's old epoch, so an interrupted replay cannot skip transition parts.
func cursorEpochForEvent(event StateEvent, userID int64, version *StateVersion) uint64 {
	if event.HasCursorVisibilityEpoch {
		return event.CursorVisibilityEpoch
	}
	index := sort.Search(len(event.cursorVisibilityEpochs), func(index int) bool {
		return event.cursorVisibilityEpochs[index].userID >= userID
	})
	if index < len(event.cursorVisibilityEpochs) && event.cursorVisibilityEpochs[index].userID == userID {
		return event.cursorVisibilityEpochs[index].epoch
	}
	return version.VisibilityEpoch(userID)
}

// isVisibilityTransitionEvent reports whether eventType is permitted on the
// visibility-only direct-transition delivery policy.
func isVisibilityTransitionEvent(eventType string) bool {
	switch eventType {
	case "visibility.tombstone", "visibility.revoked", "visibility.grant.begin", "visibility.fragment", "visibility.granted", "visibility.transition.complete":
		return true
	default:
		return false
	}
}

// appendPending prunes revoked private scopes and retains live items published
// while replay is being encoded.
// The same item/byte hard limits apply before and after the connection becomes
// live, preventing a sync attempt from allocating an unbounded side buffer.
func (s *eventSubscription) appendPending(revoked []Scope, items []StateQueueItem) bool {
	if s == nil || !s.active || s.phase != eventSubscriptionSyncing {
		return false
	}
	s.pending = pruneStateQueueItems(s.pending, revoked)
	s.pendingBytes = stateQueueItemBytes(s.pending)
	itemCount := len(s.pending)
	bytes := s.pendingBytes
	for _, item := range items {
		if len(item.Frame) == 0 {
			return false
		}
		itemCount++
		bytes += len(item.Frame)
		if itemCount > MaxWebSocketStateItems || bytes > MaxWebSocketStateBytes {
			return false
		}
	}
	s.pending = append(s.pending, cloneStateQueueItems(items)...)
	s.pendingBytes = bytes
	return true
}

// snapshotSubscriptions returns a stable, byte-sorted set without retaining
// the registry mutex while publication acquires connection delivery gates.
func (b *EventBus) snapshotSubscriptions() []*eventSubscription {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	subscriptions := make([]*eventSubscription, 0, len(b.subscriptions))
	for _, subscription := range b.subscriptions {
		subscriptions = append(subscriptions, subscription)
	}
	sortSubscriptions(subscriptions)
	return subscriptions
}

// snapshotAndClose atomically closes admission and detaches the registry.
func (b *EventBus) snapshotAndClose() []*eventSubscription {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	subscriptions := make([]*eventSubscription, 0, len(b.subscriptions))
	for _, subscription := range b.subscriptions {
		subscriptions = append(subscriptions, subscription)
	}
	b.subscriptions = make(map[ControlConnectionRef]*eventSubscription)
	sortSubscriptions(subscriptions)
	return subscriptions
}

// remove deletes subscription only when the registry still holds that exact
// attempt, so stale abort and slow-consumer work cannot remove a replacement.
func (b *EventBus) remove(subscription *eventSubscription) {
	if b == nil || subscription == nil {
		return
	}
	b.mu.Lock()
	if b.subscriptions[subscription.ref] == subscription {
		delete(b.subscriptions, subscription.ref)
	}
	b.mu.Unlock()
}

// sortSubscriptions establishes the global connection-gate acquisition order.
func sortSubscriptions(subscriptions []*eventSubscription) {
	sort.Slice(subscriptions, func(i, j int) bool {
		left := subscriptions[i].ref
		right := subscriptions[j].ref
		if order := bytes.Compare(left.ControlConnectionID[:], right.ControlConnectionID[:]); order != 0 {
			return order < 0
		}
		if left.Generation != right.Generation {
			return left.Generation < right.Generation
		}
		return left.UserID < right.UserID
	})
}

// lockSubscriptions acquires connection delivery gates in canonical order.
func lockSubscriptions(subscriptions []*eventSubscription) {
	for _, subscription := range subscriptions {
		subscription.gate.Lock()
	}
}

// unlockSubscriptions releases connection delivery gates in reverse order.
func unlockSubscriptions(subscriptions []*eventSubscription) {
	for index := len(subscriptions) - 1; index >= 0; index-- {
		subscriptions[index].gate.Unlock()
	}
}

// stateItemBatchWithinLimits validates one all-or-nothing state queue append.
func stateItemBatchWithinLimits(items []StateQueueItem) bool {
	if len(items) == 0 || len(items) > MaxWebSocketStateItems {
		return false
	}
	bytes := 0
	for _, item := range items {
		if len(item.Frame) == 0 || len(item.Frame) > MaxWebSocketStateBytes {
			return false
		}
		bytes += len(item.Frame)
		if bytes > MaxWebSocketStateBytes {
			return false
		}
	}
	return true
}

// controlQueueItems converts replay and sync.complete frames into unscoped
// control items that a later scope revoke must not prune.
func controlQueueItems(frames [][]byte, ref ControlConnectionRef, visibilityEpoch uint64) []StateQueueItem {
	items := make([]StateQueueItem, len(frames))
	for index, frame := range frames {
		items[index] = StateQueueItem{
			Frame:                 frame,
			Policy:                StateDeliveryControl,
			RecipientUserID:       ref.UserID,
			ConnectionGeneration:  ref.Generation,
			CursorVisibilityEpoch: visibilityEpoch,
		}
	}
	return items
}

// cloneStateQueueItems gives queue owners independent frame storage.
func cloneStateQueueItems(items []StateQueueItem) []StateQueueItem {
	cloned := make([]StateQueueItem, len(items))
	for index, item := range items {
		cloned[index] = item
		cloned[index].Frame = append([]byte(nil), item.Frame...)
	}
	return cloned
}

// pruneStateQueueItems removes unclaimed ordinary payload for revoked scopes.
// Direct transitions and replay/control frames survive the prune.
func pruneStateQueueItems(items []StateQueueItem, revoked []Scope) []StateQueueItem {
	if len(items) == 0 || len(revoked) == 0 {
		return items
	}
	revokedSet := scopesToSet(revoked)
	kept := items[:0]
	for _, item := range items {
		if item.Policy == StateDeliveryVisibleAfter {
			if _, remove := revokedSet[item.Scope]; remove {
				continue
			}
		}
		kept = append(kept, item)
	}
	return kept
}

// stateQueueItemBytes totals the retained wire bytes in items.
func stateQueueItemBytes(items []StateQueueItem) int {
	bytes := 0
	for _, item := range items {
		bytes += len(item.Frame)
	}
	return bytes
}
