package realtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
)

const (
	// MaxStateRingEntries is the fixed maximum number of replayable state events
	// retained by one process.
	MaxStateRingEntries = 1024
	// MaxStateRingBytes is the fixed total encoded size of retained state events.
	MaxStateRingBytes = 16 << 20
	// MaxStateEventBytes is the fixed encoded size limit for one state event.
	MaxStateEventBytes = 192 << 10
	// MaxStateEventCursorBytes bounds an opaque cursor issued by CursorSigner.
	// Ring entries omit that recipient-specific field, so this space is reserved
	// before an event enters the ring.
	MaxStateEventCursorBytes      = 256
	stateEventCursorEnvelopeBytes = len(`,"cursor":""`)
	maxStateEventRingBytes        = MaxStateEventBytes - MaxStateEventCursorBytes - stateEventCursorEnvelopeBytes
)

var (
	// ErrInvalidStateRingLimits is returned when a ring has no usable entry or
	// byte capacity.
	ErrInvalidStateRingLimits = errors.New("realtime: invalid state ring limits")
	// ErrInvalidStateEvent is returned when an event lacks a valid replayable
	// envelope shape.
	ErrInvalidStateEvent = errors.New("realtime: invalid state event")
	// ErrStateEventTooLarge is returned when an event exceeds the protocol's
	// fixed hard limit or cannot fit in the configured ring byte capacity.
	ErrStateEventTooLarge = errors.New("realtime: state event too large")
	// ErrStateRingSequence is returned when an append does not continue the
	// ring's strictly increasing GEID sequence.
	ErrStateRingSequence = errors.New("realtime: invalid state ring sequence")
)

// StateEventTemplate is the recipient-independent data from which
// StatePublication creates one replayable event. Data must be a valid JSON
// value; it intentionally excludes the per-recipient cursor.
type StateEventTemplate struct {
	EventType                string
	Scope                    Scope
	CausationID              int64
	Data                     json.RawMessage
	DeliveryPolicy           StateDeliveryPolicy
	RecipientUserID          int64
	SubjectUserID            int64
	CursorVisibilityEpoch    uint64
	HasCursorVisibilityEpoch bool
}

// StateEvent is one immutable replayable event retained in the process-local
// state ring. Accessors return copies so callers cannot alter retained data.
type StateEvent struct {
	GEID                     uint64
	EventType                string
	Scope                    Scope
	CausationID              int64
	ServerTime               int64
	Data                     json.RawMessage
	DeliveryPolicy           StateDeliveryPolicy
	RecipientUserID          int64
	SubjectUserID            int64
	CursorVisibilityEpoch    uint64
	HasCursorVisibilityEpoch bool
	cursorVisibilityEpochs   []cursorVisibilityEpoch
	subjectState             *eventSubjectState
	encoded                  []byte
}

type cursorVisibilityEpoch struct {
	userID int64
	epoch  uint64
}

type eventSubjectState struct {
	user     User
	presence Presence
}

// Encoded returns the canonical recipient-independent JSON event body. The
// returned bytes do not include a cursor and are safe for the caller to retain.
func (e StateEvent) Encoded() []byte {
	return append([]byte(nil), e.encoded...)
}

// EncodedWithCursor returns the final recipient event envelope for cursor. It
// checks the wire size again after adding the required cursor field, preventing
// an otherwise valid ring entry from exceeding the protocol event limit.
func (e StateEvent) EncodedWithCursor(cursor string) ([]byte, error) {
	if !validStateEventCursor(cursor) {
		return nil, ErrInvalidStateEvent
	}
	return e.EncodedWithDataAndCursor(e.Data, cursor)
}

// EncodedWithDataAndCursor serializes e for one recipient using a
// privacy-projected data value. Ring entries retain canonical source DTOs while
// EventBus and replay use this method for user/presence projection.
func (e StateEvent) EncodedWithDataAndCursor(data json.RawMessage, cursor string) ([]byte, error) {
	if !validStateEventCursor(cursor) || !json.Valid(data) {
		return nil, ErrInvalidStateEvent
	}
	encoded, err := json.Marshal(stateEventEnvelopeFromEventWithData(e, data, cursor))
	if err != nil {
		return nil, fmt.Errorf("realtime: encode state event: %w", err)
	}
	if len(encoded) > MaxStateEventBytes {
		return nil, ErrStateEventTooLarge
	}
	return encoded, nil
}

// Size returns the byte count used by e in the state ring.
func (e StateEvent) Size() int {
	return len(e.encoded)
}

// retainedSize returns the complete bounded ring footprint attributable to e,
// including compact recipient materialization metadata that is not serialized
// in the recipient-independent event envelope.
func (e StateEvent) retainedSize() int {
	size := len(e.encoded) + len(e.cursorVisibilityEpochs)*16
	if e.subjectState != nil {
		size += 64 + len(e.subjectState.user.Username) + len(e.subjectState.user.Nickname)
		if e.subjectState.user.Avatar != nil {
			size += len(*e.subjectState.user.Avatar)
		}
		if activity := e.subjectState.presence.Activity; activity != nil {
			size += len(activity.Type) + len(activity.Name) + len(activity.Privacy)
		}
	}
	return size
}

// StateRing retains the newest contiguous replayable events within fixed entry
// and byte limits. Its methods are safe for concurrent use, although normal
// mutation flows append only through StatePublication.
type StateRing struct {
	mu sync.RWMutex

	events    []StateEvent
	bytes     int
	highWater uint64
	maxEvents int
	maxBytes  int
}

// NewStateRing creates a state ring with the v1 fixed limits.
func NewStateRing() *StateRing {
	ring, err := NewStateRingWithLimits(MaxStateRingEntries, MaxStateRingBytes)
	if err != nil {
		panic(err)
	}
	return ring
}

// NewStateRingWithLimits creates a ring with explicit limits for deterministic
// tests. Production callers use NewStateRing and therefore retain v1 limits.
func NewStateRingWithLimits(maxEvents, maxBytes int) (*StateRing, error) {
	if maxEvents <= 0 || maxBytes <= 0 {
		return nil, ErrInvalidStateRingLimits
	}
	return &StateRing{maxEvents: maxEvents, maxBytes: maxBytes}, nil
}

// Append validates and atomically appends one contiguous event batch. Events
// are evicted from the oldest end until both fixed limits hold.
func (r *StateRing) Append(events []StateEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.appendLocked(events)
}

// ValidateAppend reports whether events could be appended to r at its current
// high-water mark without changing retention. StatePublication uses it while
// reserving a final checkpoint before the associated database transaction
// commits; Append repeats the validation at the actual commit boundary.
func (r *StateRing) ValidateAppend(events []StateEvent) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, err := r.validateAppendLocked(events)
	return err
}

// EventsAfter returns every retained event with GEID greater than geid and
// whether the complete interval from geid is still replayable. A false result
// means the caller must require a full snapshot rather than replay a suffix.
func (r *StateRing) EventsAfter(geid uint64) ([]StateEvent, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if geid > r.highWater {
		return nil, false
	}
	if len(r.events) == 0 {
		return nil, geid == r.highWater
	}
	oldest := r.events[0].GEID
	if geid < oldest-1 {
		return nil, false
	}
	start := len(r.events)
	for i := range r.events {
		if r.events[i].GEID > geid {
			start = i
			break
		}
	}
	return cloneStateEvents(r.events[start:]), true
}

// Snapshot returns an immutable-copy view of all retained events and their
// high-water mark. StatePublication.Capture should be used when the snapshot
// must be paired with one StateVersion.
func (r *StateRing) Snapshot() ([]StateEvent, uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneStateEvents(r.events), r.highWater
}

// snapshotRefs returns shallow immutable event references for a caller already
// operating inside StatePublication's capture boundary. Ring entries and their
// byte slices are never mutated after append; retaining these refs across
// eviction is safe, but callers must not expose or modify their slices.
func (r *StateRing) snapshotRefs() ([]StateEvent, uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]StateEvent(nil), r.events...), r.highWater
}

// HighWater returns the greatest GEID ever appended to r, including events
// that have since been evicted by its retention limits.
func (r *StateRing) HighWater() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.highWater
}

// Len returns the number of retained replayable events.
func (r *StateRing) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.events)
}

// Bytes returns the total retained encoded event size.
func (r *StateRing) Bytes() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bytes
}

// appendLocked validates a whole batch before mutating the ring. Callers hold
// r.mu so a failed validation can never leave a partially appended sequence.
func (r *StateRing) appendLocked(events []StateEvent) error {
	prepared, err := r.validateAppendLocked(events)
	if err != nil {
		return err
	}
	for _, event := range prepared {
		r.events = append(r.events, event)
		r.bytes += event.retainedSize()
		r.highWater = event.GEID
		for len(r.events) > r.maxEvents || r.bytes > r.maxBytes {
			r.bytes -= r.events[0].retainedSize()
			r.events = r.events[1:]
		}
	}
	return nil
}

// validateAppendLocked normalizes a complete contiguous batch without
// modifying r. Callers hold either r.mu or r.mu.RLock.
func (r *StateRing) validateAppendLocked(events []StateEvent) ([]StateEvent, error) {
	prepared := make([]StateEvent, len(events))
	expected := r.highWater + 1
	for i, event := range events {
		if event.GEID != expected {
			return nil, ErrStateRingSequence
		}
		normalized, err := normalizeStateEvent(event)
		if err != nil {
			return nil, err
		}
		if len(normalized.encoded) > maxStateEventRingBytes || len(normalized.encoded) > r.maxBytes {
			return nil, ErrStateEventTooLarge
		}
		if normalized.retainedSize() > r.maxBytes {
			return nil, ErrStateEventTooLarge
		}
		prepared[i] = normalized
		expected++
	}
	return prepared, nil
}

// stateEventFromTemplate assigns the publication-owned GEID and timestamp to a
// validated event template.
func stateEventFromTemplate(template StateEventTemplate, geid uint64, serverTime int64) (StateEvent, error) {
	return normalizeStateEvent(StateEvent{
		GEID:                     geid,
		EventType:                template.EventType,
		Scope:                    template.Scope,
		CausationID:              template.CausationID,
		ServerTime:               serverTime,
		Data:                     append(json.RawMessage(nil), template.Data...),
		DeliveryPolicy:           template.DeliveryPolicy,
		RecipientUserID:          template.RecipientUserID,
		SubjectUserID:            template.SubjectUserID,
		CursorVisibilityEpoch:    template.CursorVisibilityEpoch,
		HasCursorVisibilityEpoch: template.HasCursorVisibilityEpoch,
	})
}

// normalizeStateEvent copies one event and encodes the exact body retained in
// the ring. It accepts no caller-provided encoded cache because callers must
// not be able to bypass the size and structural validation rules.
func normalizeStateEvent(event StateEvent) (StateEvent, error) {
	if event.GEID == 0 || event.EventType == "" || !event.Scope.Valid() || event.CausationID < 0 {
		return StateEvent{}, ErrInvalidStateEvent
	}
	if event.DeliveryPolicy != 0 && event.DeliveryPolicy != StateDeliveryVisibleAfter && event.DeliveryPolicy != StateDeliveryDirectTransition && event.DeliveryPolicy != StateDeliveryUserTargeted {
		return StateEvent{}, ErrInvalidStateEvent
	}
	if (event.DeliveryPolicy == StateDeliveryDirectTransition || event.DeliveryPolicy == StateDeliveryUserTargeted) && event.RecipientUserID <= 0 {
		return StateEvent{}, ErrInvalidStateEvent
	}
	if event.DeliveryPolicy == StateDeliveryDirectTransition && !isVisibilityTransitionEvent(event.EventType) {
		return StateEvent{}, ErrInvalidStateEvent
	}
	if event.SubjectUserID < 0 {
		return StateEvent{}, ErrInvalidStateEvent
	}
	if event.Data == nil {
		event.Data = json.RawMessage("null")
	}
	if !json.Valid(event.Data) {
		return StateEvent{}, ErrInvalidStateEvent
	}
	event.Data = append(json.RawMessage(nil), event.Data...)
	encoded, err := json.Marshal(stateEventEnvelopeFromEvent(event, ""))
	if err != nil {
		return StateEvent{}, fmt.Errorf("realtime: encode state event: %w", err)
	}
	event.encoded = encoded
	return event, nil
}

// stateEventEnvelope is the event form retained in the ring without Cursor and
// serialized for a recipient with Cursor.
type stateEventEnvelope struct {
	Type        string          `json:"type"`
	GEID        string          `json:"geid"`
	Cursor      string          `json:"cursor,omitempty"`
	Class       string          `json:"class"`
	Scope       eventScope      `json:"scope"`
	EventType   string          `json:"event_type"`
	CausationID string          `json:"causation_id,omitempty"`
	ServerTime  int64           `json:"server_time"`
	Data        json.RawMessage `json:"data"`
}

// stateEventEnvelopeFromEvent creates the canonical event envelope for event.
func stateEventEnvelopeFromEvent(event StateEvent, cursor string) stateEventEnvelope {
	return stateEventEnvelopeFromEventWithData(event, event.Data, cursor)
}

// stateEventEnvelopeFromEventWithData creates one wire event with the supplied
// recipient-specific data projection.
func stateEventEnvelopeFromEventWithData(event StateEvent, data json.RawMessage, cursor string) stateEventEnvelope {
	return stateEventEnvelope{
		Type:        "state.event",
		GEID:        strconv.FormatUint(event.GEID, 10),
		Cursor:      cursor,
		Class:       "state",
		Scope:       stateEventScope(event.Scope),
		EventType:   event.EventType,
		CausationID: commandIDText(event.CausationID),
		ServerTime:  event.ServerTime,
		Data:        data,
	}
}

// validStateEventCursor accepts the base64url cursor grammar whose bounded
// encoded length was reserved when the cursor-free event entered the ring.
func validStateEventCursor(cursor string) bool {
	if cursor == "" || len(cursor) > MaxStateEventCursorBytes {
		return false
	}
	for _, character := range cursor {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

// eventScope keeps IDs in the protocol's decimal-string representation.
type eventScope struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// stateEventScope converts one validated in-memory scope to its event form.
func stateEventScope(scope Scope) eventScope {
	eventScope := eventScope{Type: scope.Type}
	if scope.ID != 0 {
		eventScope.ID = strconv.FormatInt(scope.ID, 10)
	}
	return eventScope
}

// commandIDText omits causation for non-command runtime events.
func commandIDText(commandID int64) string {
	if commandID == 0 {
		return ""
	}
	return strconv.FormatInt(commandID, 10)
}

// cloneStateEvents copies event slices and their mutable JSON payloads.
func cloneStateEvents(events []StateEvent) []StateEvent {
	cloned := make([]StateEvent, len(events))
	for i, event := range events {
		cloned[i] = event
		cloned[i].Data = append(json.RawMessage(nil), event.Data...)
		cloned[i].cursorVisibilityEpochs = append([]cursorVisibilityEpoch(nil), event.cursorVisibilityEpochs...)
		if event.subjectState != nil {
			state := *event.subjectState
			state.user = cloneUser(state.user)
			state.presence = clonePresence(state.presence)
			cloned[i].subjectState = &state
		}
		cloned[i].encoded = append([]byte(nil), event.encoded...)
	}
	return cloned
}
