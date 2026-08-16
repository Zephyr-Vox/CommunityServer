package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	masterKeySize = 32
	nonceSize     = 12
)

var (
	c2sKeyInfo = []byte("zephyrvox-voice-c2s-v1")
	s2cKeyInfo = []byte("zephyrvox-voice-s2c-v1")

	// ErrInvalidKey is returned when a key is not exactly 32 bytes.
	ErrInvalidKey = errors.New("protocol: key must be 32 bytes")
	// ErrSequenceZero is returned whenever a direction tries to encrypt with
	// sequence 0. Senders count from 1 and seq=0 is always rejected; this
	// removes the off-by-one ambiguity at the replay-window boundary.
	ErrSequenceZero = errors.New("protocol: sequence must start at 1")
	// ErrOpenFailed reports an AEAD authentication failure. Callers on the
	// UDP hot path normally discard it without logging.
	ErrOpenFailed = errors.New("protocol: aead open failed")
)

// GenerateMasterKey returns a fresh random 32-byte session master key. It is
// returned once over the caller's already-established authenticated control
// channel and is never stored server-side; only the HKDF-derived direction
// keys stay in memory.
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, masterKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// DeriveDirectionKeys derives the independent c2s and s2c AES-256 keys from
// one session master key. Direction separation prevents ciphertexts and
// replays from being swapped between directions.
//
// HKDF parameters:
//   - salt = the raw 16-byte session id;
//   - info = a fixed direction label.
//
// Every new session has a new random master key, so even if a sender ever
// reset its sequence the deterministic nonce would still never repeat with
// the same key. Any future "key rotation while reusing session/seq" feature
// must change the derivation salt or bump the protocol version.
func DeriveDirectionKeys(sessionID [16]byte, masterKey []byte) (c2s, s2c []byte, err error) {
	if len(masterKey) != masterKeySize {
		return nil, nil, ErrInvalidKey
	}
	c2s, err = deriveKey(sessionID, masterKey, c2sKeyInfo)
	if err != nil {
		return nil, nil, err
	}
	s2c, err = deriveKey(sessionID, masterKey, s2cKeyInfo)
	if err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

func deriveKey(sessionID [16]byte, masterKey, info []byte) ([]byte, error) {
	key := make([]byte, masterKeySize)
	r := hkdf.New(sha256.New, masterKey, sessionID[:], info)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// NonceFor builds the deterministic 12-byte GCM nonce for a sequence number:
// four zero bytes followed by the 64-bit big-endian sequence. Sequence
// numbers are strictly increasing per direction key, which makes the nonce
// unique; it is therefore never transmitted, saving 12 bytes per packet.
func NonceFor(seq uint64) [nonceSize]byte {
	var nonce [nonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:12], seq)
	return nonce
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != masterKeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext with AES-256-GCM under key and sequence seq. The
// complete 30-byte outer header is the AAD, so magic, version, reserved
// flags, session id and sequence are all authenticated. The nonce is derived
// deterministically from seq and is not included in the returned ciphertext;
// the caller puts ciphertext+tag at packet offset 30.
//
// Seal constructs the GCM instance every call. Callers that already hold a
// cipher.AEAD for the direction key can call gcm.Seal with NonceFor directly,
// which is what the UDP server hot path does.
func Seal(key []byte, seq uint64, header, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return sealWithAEAD(gcm, seq, header, plaintext)
}

// sealWithAEAD is Seal without the per-call AES/GCM setup. gcm must already
// be configured for the direction key; seq and header rules are identical to
// Seal.
func sealWithAEAD(gcm cipher.AEAD, seq uint64, header, plaintext []byte) ([]byte, error) {
	if gcm == nil {
		return nil, ErrNoKey
	}
	if seq == 0 {
		return nil, ErrSequenceZero
	}
	if len(header) != HeaderSize {
		return nil, errors.New("protocol: aad must be the 30-byte outer header")
	}
	nonce := NonceFor(seq)
	return gcm.Seal(nil, nonce[:], plaintext, header), nil
}

// Open authenticates and decrypts ciphertext+tag. It returns the plaintext
// (channel subheader + audio payload) only when every header byte and payload
// byte authenticates.
//
// Open constructs the GCM instance every call. Callers that already hold a
// cipher.AEAD for the direction key can call gcm.Open with NonceFor directly,
// which is what the UDP server hot path does.
func Open(key []byte, seq uint64, header, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return openWithAEAD(gcm, seq, header, ciphertext)
}

// openWithAEAD is Open without the per-call AES/GCM setup.
func openWithAEAD(gcm cipher.AEAD, seq uint64, header, ciphertext []byte) ([]byte, error) {
	if gcm == nil {
		return nil, ErrNoKey
	}
	if seq == 0 {
		return nil, ErrSequenceZero
	}
	if len(header) != HeaderSize {
		return nil, errors.New("protocol: aad must be the 30-byte outer header")
	}
	nonce := NonceFor(seq)
	plaintext, err := gcm.Open(nil, nonce[:], ciphertext, header)
	if err != nil {
		return nil, ErrOpenFailed
	}
	return plaintext, nil
}
