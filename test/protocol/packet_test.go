package protocol_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"zephyr.vox/server/ce/internal/protocol"
)

func TestPacketConstants(t *testing.T) {
	if protocol.MaxPayloadEncrypted != 1142 {
		t.Fatalf("MaxPayloadEncrypted = %d, want 1142", protocol.MaxPayloadEncrypted)
	}
	if protocol.MaxPayloadPlaintext != 1158 {
		t.Fatalf("MaxPayloadPlaintext = %d, want 1158", protocol.MaxPayloadPlaintext)
	}
	if protocol.MaxPayload(true) != protocol.MaxPayloadEncrypted || protocol.MaxPayload(false) != protocol.MaxPayloadPlaintext {
		t.Fatal("MaxPayload must match the fixed constants")
	}
	if protocol.MinPacketSize(true) != 58 || protocol.MinPacketSize(false) != 42 {
		t.Fatalf("MinPacketSize = (%d, %d), want (58, 42)", protocol.MinPacketSize(true), protocol.MinPacketSize(false))
	}
}

func TestEncodeDecodePlaintextRoundTrip(t *testing.T) {
	wantID := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	wantCh := protocol.ChannelHeader{ChannelType: 2, ChannelSeq: 0x4242, Flags: 0, SpeakerID: 42}
	payload := []byte("opus audio")
	packet, err := protocol.EncodePacket(wantID, 7, false, nil, wantCh, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != protocol.HeaderSize+protocol.ChannelHeaderSize+len(payload) {
		t.Fatalf("packet len = %d", len(packet))
	}
	gotID, seq, gotCh, gotPayload, ok := protocol.DecodePacket(packet, false, nil)
	if !ok {
		t.Fatal("valid packet rejected")
	}
	if gotID != wantID || seq != 7 || gotCh != wantCh || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("decode = (%x, %d, %+v, %q), want full round trip", gotID, seq, gotCh, gotPayload)
	}
}

func TestDecodePacketRejectsMalformedPackets(t *testing.T) {
	id := [16]byte{1}
	ch := protocol.ChannelHeader{ChannelType: 1}
	packet, err := protocol.EncodePacket(id, 1, false, nil, ch, nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"truncated header", func(b []byte) []byte { return b[:protocol.HeaderSize-1] }},
		{"magic", func(b []byte) []byte { b[0] = 'X'; return b }},
		{"version", func(b []byte) []byte { b[4] = 2; return b }},
		{"outer flags", func(b []byte) []byte { b[5] = 1; return b }},
		{"truncated channel", func(b []byte) []byte { return b[:protocol.HeaderSize+protocol.ChannelHeaderSize-1] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, _, _, ok := protocol.DecodePacket(tt.mutate(append([]byte(nil), packet...)), false, nil); ok {
				t.Fatal("invalid packet accepted")
			}
		})
	}

	oversize := make([]byte, protocol.MaxPacketSize+1)
	copy(oversize, packet)
	if _, _, _, _, ok := protocol.DecodePacket(oversize, false, nil); ok {
		t.Fatal("oversize datagram accepted")
	}
}

func TestDecodePacketRejectsSequenceZero(t *testing.T) {
	raw := make([]byte, protocol.HeaderSize+protocol.ChannelHeaderSize)
	copy(raw[:4], protocol.Magic)
	raw[4] = protocol.ProtocolVersion
	// Sequence bytes stay zero.
	if _, seq, _, _, ok := protocol.DecodePacket(raw, false, nil); ok {
		t.Fatalf("plaintext seq=%d packet accepted, want rejection", seq)
	}
}

func TestEncodePacketRejectsSequenceZeroAndOversize(t *testing.T) {
	if _, err := protocol.EncodePacket([16]byte{1}, 0, false, nil, protocol.ChannelHeader{ChannelType: 1}, nil); err != protocol.ErrSequenceZero {
		t.Fatalf("err = %v, want ErrSequenceZero", err)
	}
	big := make([]byte, protocol.MaxPayloadPlaintext+1)
	if _, err := protocol.EncodePacket([16]byte{1}, 1, false, nil, protocol.ChannelHeader{ChannelType: 1}, big); err != protocol.ErrPayloadTooLarge {
		t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
	}
}

func TestChannelSpeakerIDUsesBigEndian(t *testing.T) {
	// Encode/decode through a full packet so the wire bytes are exercised.
	want := int64(0x0102030405060708)
	packet, err := protocol.EncodePacket([16]byte{1}, 1, false, nil, protocol.ChannelHeader{ChannelType: 1, SpeakerID: want}, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := packet[protocol.HeaderSize:]
	if got := int64(binary.BigEndian.Uint64(body[4:12])); got != want {
		t.Fatalf("speaker bytes = %x, want big endian %x", uint64(got), uint64(want))
	}
}
