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
	EventType   string
	Scope       Scope
	CausationID int64
	Data        json.RawMessage
}

// StateEvent is one immutable replayable event retained in the process-local
// state ring. Accessors return copies so callers cannot alter retained data.
type StateEvent struct {
	GEID        uint64
	EventType   string
	Scope       Scope
	CausationID int64
	ServerTime  int64
	Data        json.RawMessage
	encoded     []byte
}

// Encoded returns the canonical recipient-independent JSON event body. The
// returned bytes do not include a cursor and are safe for the caller to retain.
func (e StateEvent) Encoded() []byte {
	return append([]byte(nil), e.encoded...)
}

// Size returns the byte count used by e in the state ring.
func (e StateEvent) Size() int {
	return len(e.encoded)
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
	prepared := make([]StateEvent, len(events))
	expected := r.highWater + 1
	for i, event := range events {
		if event.GEID != expected {
			return ErrStateRingSequence
		}
		normalized, err := normalizeStateEvent(event)
		if err != nil {
			return err
		}
		if len(normalized.encoded) > MaxStateEventBytes || len(normalized.encoded) > r.maxBytes {
			return ErrStateEventTooLarge
		}
		prepared[i] = normalized
		expected++
	}
	for _, event := range prepared {
		r.events = append(r.events, event)
		r.bytes += len(event.encoded)
		r.highWater = event.GEID
		for len(r.events) > r.maxEvents || r.bytes > r.maxBytes {
			r.bytes -= len(r.events[0].encoded)
			r.events = r.events[1:]
		}
	}
	return nil
}

// stateEventFromTemplate assigns the publication-owned GEID and timestamp to a
// validated event template.
func stateEventFromTemplate(template StateEventTemplate, geid uint64, serverTime int64) (StateEvent, error) {
	return normalizeStateEvent(StateEvent{
		GEID:        geid,
		EventType:   template.EventType,
		Scope:       template.Scope,
		CausationID: template.CausationID,
		ServerTime:  serverTime,
		Data:        append(json.RawMessage(nil), template.Data...),
	})
}

// normalizeStateEvent copies one event and encodes the exact body retained in
// the ring. It accepts no caller-provided encoded cache because callers must
// not be able to bypass the size and structural validation rules.
func normalizeStateEvent(event StateEvent) (StateEvent, error) {
	if event.GEID == 0 || event.EventType == "" || !event.Scope.Valid() || event.CausationID < 0 {
		return StateEvent{}, ErrInvalidStateEvent
	}
	if event.Data == nil {
		event.Data = json.RawMessage("null")
	}
	if !json.Valid(event.Data) {
		return StateEvent{}, ErrInvalidStateEvent
	}
	event.Data = append(json.RawMessage(nil), event.Data...)
	encoded, err := json.Marshal(stateEventEnvelope{
		Type:        "state.event",
		GEID:        strconv.FormatUint(event.GEID, 10),
		Class:       "state",
		Scope:       stateEventScope(event.Scope),
		EventType:   event.EventType,
		CausationID: commandIDText(event.CausationID),
		ServerTime:  event.ServerTime,
		Data:        event.Data,
	})
	if err != nil {
		return StateEvent{}, fmt.Errorf("realtime: encode state event: %w", err)
	}
	event.encoded = encoded
	return event, nil
}

// stateEventEnvelope is the cursor-free JSON form retained in the ring.
type stateEventEnvelope struct {
	Type        string          `json:"type"`
	GEID        string          `json:"geid"`
	Class       string          `json:"class"`
	Scope       eventScope      `json:"scope"`
	EventType   string          `json:"event_type"`
	CausationID string          `json:"causation_id,omitempty"`
	ServerTime  int64           `json:"server_time"`
	Data        json.RawMessage `json:"data"`
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
		cloned[i].encoded = append([]byte(nil), event.encoded...)
	}
	return cloned
}
