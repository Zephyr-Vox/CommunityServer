package protocol_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"zephyr.vox/server/ce/internal/protocol"
)

func TestDeriveDirectionKeys(t *testing.T) {
	id := [16]byte{1, 2, 3, 4}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	c2s, s2c, err := protocol.DeriveDirectionKeys(id, master)
	if err != nil {
		t.Fatal(err)
	}
	if len(c2s) != 32 || len(s2c) != 32 {
		t.Fatalf("derived key lengths = %d/%d, want 32", len(c2s), len(s2c))
	}
	if bytes.Equal(c2s, s2c) {
		t.Fatal("c2s and s2c keys must be direction-separated")
	}
	other, _, err := protocol.DeriveDirectionKeys([16]byte{9}, master)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c2s, other) {
		t.Fatal("different session salt must derive different keys")
	}
	if _, _, err := protocol.DeriveDirectionKeys(id, make([]byte, 16)); !errors.Is(err, protocol.ErrInvalidKey) {
		t.Fatalf("short master key err = %v, want ErrInvalidKey", err)
	}
}

func TestGenerateMasterKey(t *testing.T) {
	a, err := protocol.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := protocol.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 || bytes.Equal(a, b) {
		t.Fatalf("master keys not unique: len=%d", len(a))
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, protocol.HeaderSize)
	copy(header[:4], protocol.Magic)
	header[4] = protocol.ProtocolVersion
	plaintext := []byte("channel subheader plus opus audio")

	ct, err := protocol.Seal(key, 9, header, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.Open(key, 9, header, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted payload does not match")
	}
}

func TestEncryptedPacketRejectsTampering(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	id := [16]byte{5}
	payload := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	packet, err := protocol.EncodePacket(id, 9, true, key, protocol.ChannelHeader{ChannelType: 1}, payload)
	if err != nil {
		t.Fatal(err)
	}

	tamperCases := []struct {
		name string
		edit func([]byte)
	}{
		{"payload byte", func(p []byte) { p[protocol.HeaderSize] ^= 1 }},
		{"tag byte", func(p []byte) { p[len(p)-1] ^= 1 }},
		{"header magic", func(p []byte) { p[0] ^= 1 }},
		{"header seq", func(p []byte) { p[protocol.HeaderSize-1] ^= 1 }},
	}
	for _, tt := range tamperCases {
		t.Run(tt.name, func(t *testing.T) {
			p := append([]byte(nil), packet...)
			tt.edit(p)
			if _, _, _, _, ok := protocol.DecodePacket(p, true, key); ok {
				t.Fatal("tampered packet accepted")
			}
		})
	}
}

func TestEncryptedPacketRejectsWrongKeyAndSequence(t *testing.T) {
	key := make([]byte, 32)
	other := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(other); err != nil {
		t.Fatal(err)
	}
	packet, err := protocol.EncodePacket([16]byte{5}, 9, true, key, protocol.ChannelHeader{ChannelType: 1}, []byte("audio"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, ok := protocol.DecodePacket(packet, true, other); ok {
		t.Fatal("wrong key accepted")
	}
	// DecodePacket derives the nonce from the authenticated sequence field,
	// so changing the header sequence makes authentication fail.
	badSeq := append([]byte(nil), packet...)
	badSeq[protocol.HeaderSize-1] ^= 1
	if _, _, _, _, ok := protocol.DecodePacket(badSeq, true, key); ok {
		t.Fatal("wrong sequence accepted")
	}
}

func TestSealOpenRejectSequenceZero(t *testing.T) {
	key := make([]byte, 32)
	header := make([]byte, protocol.HeaderSize)
	if _, err := protocol.Seal(key, 0, header, nil); !errors.Is(err, protocol.ErrSequenceZero) {
		t.Fatalf("seal err = %v, want ErrSequenceZero", err)
	}
	if _, err := protocol.Open(key, 0, header, nil); !errors.Is(err, protocol.ErrSequenceZero) {
		t.Fatalf("open err = %v, want ErrSequenceZero", err)
	}
}

func TestNonceIsUniqueAndPrefixed(t *testing.T) {
	seen := make(map[[12]byte]struct{})
	for i := range 1024 {
		seq := uint64(i + 1)
		nonce := protocol.NonceFor(seq)
		if nonce[0] != 0 || nonce[1] != 0 || nonce[2] != 0 || nonce[3] != 0 {
			t.Fatalf("seq %d nonce prefix is not zero: %x", seq, nonce)
		}
		if _, dup := seen[nonce]; dup {
			t.Fatalf("seq %d reuses nonce %x", seq, nonce)
		}
		seen[nonce] = struct{}{}
	}
}

func TestEncryptedMaxPayloadRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, protocol.MaxPayloadEncrypted)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	id := [16]byte{1}
	packet, err := protocol.EncodePacket(id, 1, true, key, protocol.ChannelHeader{ChannelType: 1}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != protocol.MaxPacketSize {
		t.Fatalf("packet len = %d, want %d", len(packet), protocol.MaxPacketSize)
	}
	gotID, seq, ch, gotPayload, ok := protocol.DecodePacket(packet, true, key)
	if !ok || gotID != id || seq != 1 || ch.ChannelType != 1 || !bytes.Equal(gotPayload, payload) {
		t.Fatal("max payload round trip mismatch")
	}
	if _, err := protocol.EncodePacket(id, 2, true, key, protocol.ChannelHeader{ChannelType: 1}, make([]byte, protocol.MaxPayloadEncrypted+1)); !errors.Is(err, protocol.ErrPayloadTooLarge) {
		t.Fatalf("oversize err = %v, want ErrPayloadTooLarge", err)
	}
}
