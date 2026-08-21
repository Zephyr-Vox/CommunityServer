package protocol

import (
	"errors"
	"sync"
)

var (
	// ErrChannelTypeReserved is returned when a caller tries to register
	// channel_type 0. The protocol fixes type 0 as heartbeat / NAT keepalive
	// and it must never become a business stream.
	ErrChannelTypeReserved = errors.New("protocol: channel_type 0 is reserved for heartbeats")
	// ErrChannelAlreadyRegistered is returned on duplicate registration.
	ErrChannelAlreadyRegistered = errors.New("protocol: channel already registered")
	// ErrChannelRegistrySealed is returned when Register runs after the UDP
	// server started. Registrations must complete before Start; runtime
	// stream-type discovery is a future capability-table feature.
	ErrChannelRegistrySealed = errors.New("protocol: channel registry is sealed")
)

// Capabilities declares transport-visible properties of one registered
// stream type. Fragmentable is only a future capability declaration for the
// video batch: v1 parsing never interprets fragment flags, and packets with
// any channel flag set are dropped regardless of this field.
type Capabilities struct {
	Name         string
	MuteKind     string
	Fragmentable bool
}

// ChannelTypeRegistry is the caller-owned table of business stream types. The
// protocol itself fixes only channel_type 0 = heartbeat; 1..255 are
// registered by server assembly / the future voice business layer.
//
// The registry is concurrency-safe. The application or future voice business
// layer registers its stream types before Start; Start seals the table,
// after which registration is rejected.
type ChannelTypeRegistry struct {
	mu       sync.RWMutex
	channels map[uint8]Capabilities
	sealed   bool
}

// NewChannelTypeRegistry returns an empty, unsealed registry.
func NewChannelTypeRegistry() *ChannelTypeRegistry {
	return &ChannelTypeRegistry{channels: make(map[uint8]Capabilities)}
}

// Register adds a business stream type. It rejects type 0, duplicates, and
// registration after the registry was sealed by Start.
func (r *ChannelTypeRegistry) Register(channelType uint8, caps Capabilities) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if channelType == HeartbeatChannelType {
		return ErrChannelTypeReserved
	}
	if r.sealed {
		return ErrChannelRegistrySealed
	}
	if _, exists := r.channels[channelType]; exists {
		return ErrChannelAlreadyRegistered
	}
	r.channels[channelType] = caps
	return nil
}

// Registered reports whether channelType is a registered business stream.
// Heartbeat type 0 always reports false: it is protocol-owned, not a
// registered stream.
func (r *ChannelTypeRegistry) Registered(channelType uint8) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.channels[channelType]
	return ok
}

// Lookup returns the capabilities of a registered stream.
func (r *ChannelTypeRegistry) Lookup(channelType uint8) (Capabilities, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	caps, ok := r.channels[channelType]
	return caps, ok
}

// Snapshot returns every registered business stream in ascending channel-type
// order. The returned map is independent from the registry and remains stable
// after Seal, allowing application metadata to share the transport authority.
func (r *ChannelTypeRegistry) Snapshot() map[uint8]Capabilities {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[uint8]Capabilities, len(r.channels))
	for channelType, capabilities := range r.channels {
		result[channelType] = capabilities
	}
	return result
}

// Seal makes the registry read-only. The UDP server calls it exactly once
// when Start begins serving; registration after Seal fails with
// ErrChannelRegistrySealed.
func (r *ChannelTypeRegistry) Seal() {
	r.mu.Lock()
	r.sealed = true
	r.mu.Unlock()
}
