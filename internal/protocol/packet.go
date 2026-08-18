package protocol

import "encoding/binary"

// Packet layout (identical in both directions):
//
// offset  size  field
// 0       4     magic "ZVX1"
// 4       1     version = 1
// 5       1     flags = 0 (reserved)
// 6       16    session_id (raw 16 bytes, not hex)
// 22      8     sequence (uint64 big endian)
// 30      12    channel subheader (channel_type + channel_seq + flags + speaker_id)
// 42      n     audio data (or type 0 heartbeat/revocation payload)
//
// In encrypted mode bytes 30..n are one AES-256-GCM ciphertext
// (channel subheader + audio + 16-byte tag). In plaintext mode they are the
// raw channel subheader + audio.
const (
	// Magic identifies a ZephyrVox v1 voice datagram.
	Magic = "ZVX1"

	// ProtocolVersion is the fixed outer protocol version carried in every
	// datagram. The version byte is the last-resort escape hatch: preferred
	// evolution goes through capability tables and reserved flag bits.
	ProtocolVersion = 1

	// HeaderSize is the fixed outer header: magic + version + flags +
	// session id + sequence.
	HeaderSize = 30
	// ChannelHeaderSize is the payload channel subheader: channel_type(1) +
	// channel_seq(2) + flags(1) + speaker_id(8).
	ChannelHeaderSize = 12
	// TagSize is the AES-GCM authentication tag size.
	TagSize = 16

	// MaxPacketSize is the hard datagram limit. 1200 stays below the IPv6
	// minimum MTU of 1280 including the UDP/IP headers, so packets never
	// fragment on a healthy path.
	MaxPacketSize = 1200

	// MaxPayloadEncrypted / MaxPayloadPlaintext are the largest audio payload
	// sizes for one datagram in each mode. The negotiation response reports
	// the applicable value to clients.
	MaxPayloadEncrypted = MaxPacketSize - HeaderSize - ChannelHeaderSize - TagSize // 1142
	MaxPayloadPlaintext = MaxPacketSize - HeaderSize - ChannelHeaderSize           // 1158

	// HeartbeatChannelType is fixed by the protocol: type 0 is the heartbeat
	// / NAT keepalive channel and must never be registered as a business
	// stream. 1..255 are caller-registered stream types; the protocol package
	// deliberately defines no application stream constants.
	HeartbeatChannelType uint8 = 0
)

// MaxPayload returns the maximum audio payload size for one datagram in the
// given mode. Clients must never hard-code these numbers; they come from the
// session negotiation response.
func MaxPayload(encrypted bool) int {
	if encrypted {
		return MaxPayloadEncrypted
	}
	return MaxPayloadPlaintext
}

// MinPacketSize returns the smallest structurally valid datagram for the
// mode: an empty audio payload still carries the full outer header and
// channel subheader, plus the GCM tag in encrypted mode.
func MinPacketSize(encrypted bool) int {
	if encrypted {
		return HeaderSize + ChannelHeaderSize + TagSize
	}
	return HeaderSize + ChannelHeaderSize
}

// ChannelHeader is the 12-byte payload subheader that demultiplexes audio
// streams inside one session. ChannelSeq is a per-channel uint16 modular
// counter kept by the source; relays pass it through unchanged.
type ChannelHeader struct {
	ChannelType uint8
	ChannelSeq  uint16
	Flags       uint8
	SpeakerID   int64
}

// putOuterHeader writes the fixed 30-byte outer header to dst. dst must have
// at least HeaderSize bytes of space.
func putOuterHeader(dst []byte, sessionID [16]byte, seq uint64) {
	copy(dst[0:4], Magic)
	dst[4] = ProtocolVersion
	dst[5] = 0
	copy(dst[6:22], sessionID[:])
	binary.BigEndian.PutUint64(dst[22:30], seq)
}

// parseOuterHeader validates the outer header and returns the session id and
// sequence. Any invalid packet is reported as ok=false: unknown magic,
// version, reserved flags, sequence zero, truncation and oversize datagrams
// are all dropped silently by the UDP layer, never answered.
func parseOuterHeader(p []byte) (sessionID [16]byte, seq uint64, ok bool) {
	if len(p) < HeaderSize || len(p) > MaxPacketSize {
		return sessionID, 0, false
	}
	if string(p[0:4]) != Magic || p[4] != ProtocolVersion || p[5] != 0 {
		return sessionID, 0, false
	}
	copy(sessionID[:], p[6:22])
	seq = binary.BigEndian.Uint64(p[22:30])
	if seq == 0 {
		return sessionID, 0, false
	}
	return sessionID, seq, true
}

// putChannelHeader writes the 12-byte channel subheader to dst. dst must have
// at least ChannelHeaderSize bytes of space.
func putChannelHeader(dst []byte, ch ChannelHeader) {
	dst[0] = ch.ChannelType
	binary.BigEndian.PutUint16(dst[1:3], ch.ChannelSeq)
	dst[3] = ch.Flags
	binary.BigEndian.PutUint64(dst[4:12], uint64(ch.SpeakerID))
}

// parseChannelHeader reads and validates the 12-byte channel subheader. It
// only checks shape; c2s/s2c direction rules (speaker_id, heartbeat payload)
// are enforced by the UDP server because they differ per direction.
func parseChannelHeader(p []byte) (ChannelHeader, bool) {
	var ch ChannelHeader
	if len(p) < ChannelHeaderSize {
		return ch, false
	}
	ch.ChannelType = p[0]
	ch.ChannelSeq = binary.BigEndian.Uint16(p[1:3])
	ch.Flags = p[3]
	ch.SpeakerID = int64(binary.BigEndian.Uint64(p[4:12]))
	return ch, true
}

// EncodePacket assembles one complete voice datagram with the given session
// key and sequence. It is shared by tests and clients: the wire format is
// identical in both directions, with direction separation enforced by the
// derived c2s/s2c keys and independent sequence counters.
//
// This convenience API constructs the GCM instance on every call; the UDP
// server hot path keeps a per-session cipher.AEAD and bypasses this function.
func EncodePacket(sessionID [16]byte, seq uint64, encrypted bool, key []byte, ch ChannelHeader, payload []byte) ([]byte, error) {
	if seq == 0 {
		return nil, ErrSequenceZero
	}
	if encrypted {
		gcm, err := newGCM(key)
		if err != nil {
			return nil, err
		}
		return buildPacket(sessionID, seq, true, gcm, ch, payload)
	}
	return buildPacket(sessionID, seq, false, nil, ch, payload)
}

// DecodePacket parses and (in encrypted mode) authenticates one datagram. It
// returns ok=false for every invalid packet, mirroring the server's silent
// drop policy; wire garbage never produces an error.
func DecodePacket(packet []byte, encrypted bool, key []byte) (sessionID [16]byte, seq uint64, ch ChannelHeader, payload []byte, ok bool) {
	sessionID, seq, ok = parseOuterHeader(packet)
	if !ok {
		return sessionID, seq, ch, nil, false
	}
	if encrypted {
		if key == nil || len(packet) < MinPacketSize(true) {
			return sessionID, seq, ch, nil, false
		}
		plaintext, err := Open(key, seq, packet[:HeaderSize], packet[HeaderSize:])
		if err != nil {
			return sessionID, seq, ch, nil, false
		}
		if ch, ok = parseChannelHeader(plaintext[:ChannelHeaderSize]); !ok {
			return sessionID, seq, ch, nil, false
		}
		payload = plaintext[ChannelHeaderSize:]
	} else {
		if len(packet) < MinPacketSize(false) {
			return sessionID, seq, ch, nil, false
		}
		body := packet[HeaderSize:]
		if ch, ok = parseChannelHeader(body[:ChannelHeaderSize]); !ok {
			return sessionID, seq, ch, nil, false
		}
		payload = body[ChannelHeaderSize:]
	}
	return sessionID, seq, ch, payload, true
}
