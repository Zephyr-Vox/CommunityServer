package realtime

import (
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/protocol"
)

// ErrInvalidMetadata reports invalid advertised endpoint or capability input.
var ErrInvalidMetadata = errors.New("realtime: invalid metadata")

// Metadata is the public process-level protocol discovery document returned by
// GET /api/v0/metadata. The one protocol_version covers HTTP, WebSocket and
// UDP so clients never negotiate independent control-plane versions.
type Metadata struct {
	ProtocolVersion  int               `json:"protocol_version"`
	VoiceEndpoint    VoiceEndpoint     `json:"voice_endpoint"`
	Codecs           []VoiceCodec      `json:"codecs"`
	VoiceStreamTypes []VoiceStreamType `json:"voice_stream_types"`
	Features         []string          `json:"features"`
}

// VoiceEndpoint identifies the public UDP endpoint clients use after an HTTP
// voice join. Host is always a validated advertised address, never a wildcard
// listen value or an HTTP Host header.
type VoiceEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// VoiceCodec describes one media codec capability supported by the current
// protocol implementation.
type VoiceCodec struct {
	Name      string `json:"name"`
	ClockRate int    `json:"clock_rate"`
	Channels  int    `json:"channels"`
	PTime     []int  `json:"ptime"`
}

// VoiceStreamType describes one registered non-heartbeat voice stream type.
type VoiceStreamType struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	MuteKind string `json:"mute_kind"`
}

// NewMetadata creates the immutable v1 discovery response. advertisedHost is
// validated here as a final boundary because callers must not derive it from an
// untrusted request header.
func NewMetadata(advertisedHost string, voicePort int) (Metadata, error) {
	registry := protocol.NewChannelTypeRegistry()
	if err := registry.Register(1, protocol.Capabilities{Name: "mic", MuteKind: "voice"}); err != nil {
		return Metadata{}, err
	}
	if err := registry.Register(2, protocol.Capabilities{Name: "desktop_audio", MuteKind: "desktop_audio"}); err != nil {
		return Metadata{}, err
	}
	return NewMetadataFromRegistry(advertisedHost, voicePort, registry)
}

// NewMetadataFromRegistry creates discovery data from the exact immutable
// stream registry used by UDP packet validation and relay mute enforcement.
func NewMetadataFromRegistry(advertisedHost string, voicePort int, registry *protocol.ChannelTypeRegistry) (Metadata, error) {
	host := strings.TrimSpace(advertisedHost)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" || voicePort < 1 || voicePort > 65535 || registry == nil {
		return Metadata{}, ErrInvalidMetadata
	}
	if net.ParseIP(host) == nil && !validMetadataDNSName(host) {
		return Metadata{}, ErrInvalidMetadata
	}
	streams := registry.Snapshot()
	streamTypes := make([]VoiceStreamType, 0, len(streams))
	for id, capabilities := range streams {
		if capabilities.Name == "" || capabilities.MuteKind == "" {
			return Metadata{}, ErrInvalidMetadata
		}
		streamTypes = append(streamTypes, VoiceStreamType{ID: int(id), Name: capabilities.Name, MuteKind: capabilities.MuteKind})
	}
	sort.Slice(streamTypes, func(i, j int) bool { return streamTypes[i].ID < streamTypes[j].ID })
	return Metadata{
		ProtocolVersion: 1,
		VoiceEndpoint:   VoiceEndpoint{Host: host, Port: voicePort},
		Codecs: []VoiceCodec{{
			Name:      "opus",
			ClockRate: 48000,
			Channels:  2,
			PTime:     []int{10, 20, 40, 60},
		}},
		VoiceStreamTypes: streamTypes,
		// Channel join/leave and relay advertise their feature names when that
		// application surface is mounted. A live UDP transport alone is not a
		// client-usable voice feature.
		Features: []string{},
	}, nil
}

// MetadataHandler handles public GET /api/v0/metadata.
//
// Errors:
//   - 1009 internal: metadata serialization failed
func MetadataHandler(metadata Metadata) echo.HandlerFunc {
	return func(c *echo.Context) error {
		return api.OK(c, 200, metadata)
	}
}

// validMetadataDNSName accepts the ASCII DNS form used by the configuration
// layer without importing config into realtime.
func validMetadataDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}
