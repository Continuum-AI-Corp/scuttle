package scuttle

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// Key generation and parsing helpers, so an operator does not have to get the
// sizes, encodings and entropy source right by hand. Every Parse* accepts the
// hex that the matching Generate* output encodes to (and scuttle-keygen
// prints), with surrounding whitespace tolerated because these values usually
// arrive from an environment variable or a secrets file.

// GenerateCaptureSeed returns a fresh capture private key seed. Store it like
// any root secret: it opens every row sealed under its public key.
func GenerateCaptureSeed() ([]byte, error) {
	return randomBytes(CaptureSeedSize)
}

// GenerateAuthKey returns a fresh Envelope.AuthKey.
func GenerateAuthKey() ([]byte, error) {
	return randomBytes(AuthKeySize)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("scuttle: random: %w", err)
	}
	return b, nil
}

// ParseCaptureSeed decodes a hex capture seed and checks it is a valid key
// for the capture KEM.
func ParseCaptureSeed(s string) ([]byte, error) {
	seed, err := decodeHexKey("capture seed", s, CaptureSeedSize)
	if err != nil {
		return nil, err
	}
	if _, err := captureKEM().NewPrivateKey(seed); err != nil {
		return nil, fmt.Errorf("%w: capture seed: %v", ErrInvalidConfig, err)
	}
	return seed, nil
}

// ParsePublicKey decodes a hex capture public key, as a writer receives it.
func ParsePublicKey(s string) (PublicKeyBytes, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%w: capture public key is not hex: %v", ErrInvalidConfig, err)
	}
	if _, err := loadPublicKey(b); err != nil {
		return nil, err
	}
	return PublicKeyBytes(b), nil
}

// ParseAuthKey decodes a hex Envelope.AuthKey. An all-zero key is refused: it
// is a placeholder somebody forgot to replace, and it authenticates nothing.
func ParseAuthKey(s string) ([]byte, error) {
	k, err := decodeHexKey("auth key", s, AuthKeySize)
	if err != nil {
		return nil, err
	}
	if allZero(k) {
		return nil, fmt.Errorf("%w: auth key is all zeros", ErrInvalidConfig)
	}
	return k, nil
}

func decodeHexKey(what, s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not hex: %v", ErrInvalidConfig, what, err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%w: %s is %d bytes, want exactly %d", ErrInvalidConfig, what, len(b), size)
	}
	return b, nil
}
