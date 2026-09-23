// Package scuttle implements write-only payload encryption for captured
// request logs.
//
// The shape is deliberate and each part answers a named adversary (see
// README.md's threat model and SPEC.md for the wire format):
//
//   - A writer holds a PUBLIC key and a short-lived leaf key. It can seal a
//     body and can never open one it did not just write. Compromising the
//     whole fleet yields at most one leaf lifetime of traffic, never history.
//   - Content is AES-256-GCM over zstd, under a key DERIVED per (leaf,
//     document, field) rather than stored — so per-document key storage is
//     zero and one leaked field key opens exactly one field.
//   - The AEAD's associated data binds every ciphertext to the tenant,
//     document and field it was written for: a blob cannot be spliced between
//     workspaces, users, requests or fields without failing the tag check.
//   - Optionally (Envelope.AuthKey), the field key also depends on a symmetric
//     writer-authentication key that is never stored with the data, so someone
//     who can WRITE to storage cannot forge a row. Without it they can: the
//     capture key is public by design.
//
// Nothing here erases anything. Cryptographic erasure is out of scope.
package scuttle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/hkdf"
)

// LeafKeySize is the size of a leaf key: 32 bytes, the AES-256 key size and
// the output of the hybrid KEM's shared secret.
const LeafKeySize = 32

// Field tags. These are part of the AEAD associated data, so they are part of
// the ciphertext format: changing a value here makes existing blobs for that
// field permanently unreadable. Add, never rename.
const (
	FieldRequestBody     = "request_body"
	FieldResponseBody    = "response_body"
	FieldErrorMessage    = "error_message"
	FieldRequestHeaders  = "request_headers"
	FieldResponseHeaders = "response_headers"
)

// hkdfInfoPrefix is the domain separator for the per-field key derivation. It
// carries the format version: bumping it re-keys every field and is therefore
// a breaking change, not a tweak.
const hkdfInfoPrefix = "orca/rlog/v1"

// hkdfInfoPrefixAuth is the domain separator for the AUTHENTICATED mode. A
// distinct string rather than only a salt, so the two modes can never derive
// the same field key — not even for an auth key someone guessed.
const hkdfInfoPrefixAuth = "orca/rlog/v1/auth"

// AuthKeySize is the exact length of an Envelope.AuthKey.
const AuthKeySize = 32

// DefaultMaxPlaintext bounds what Open will decompress to. It exists so a
// corrupt or hostile blob cannot expand without limit; callers that capture
// larger bodies should raise it to their own cap rather than removing it.
const DefaultMaxPlaintext = 1 << 20 // 1 MiB

// nonceSize is AES-GCM's standard nonce. Stored as a prefix on every blob.
const nonceSize = 12

// ErrUndecryptable means the ciphertext did not open: a failed tag check
// (tampered, wrong key, or bound to a different tenant/document/field), a
// truncated blob, or an expansion past the plaintext cap.
//
// It is a VALUE the read path renders as a body state, not a failure to log
// and retry. It deliberately does not distinguish WHY: the AEAD cannot tell
// "wrong key" from "tampered", and a caller that branched on the difference
// would be branching on a guess.
var ErrUndecryptable = errors.New("scuttle: ciphertext will not open")

// ErrKeyUnavailable means the key material could not be reached right now —
// a remote keyring (KMS, HSM) is unreachable, or the caller's context ended.
// A row that is itself missing its sealed leaf is ErrUndecryptable: waiting
// will not give it one. Distinct from
// ErrUndecryptable because the remedies are opposite: this one is "retry in a
// moment", the other is "file a bug". Collapsing them is the defect the
// design's body_state enum exists to prevent.
var ErrKeyUnavailable = errors.New("scuttle: key material unavailable")

// ErrPlaintextTooLarge is returned by Seal for a body over the Envelope's cap.
// Seal refuses what Open would refuse, so a successful write is always a
// readable one.
var ErrPlaintextTooLarge = errors.New("scuttle: plaintext exceeds the envelope's cap")

// ErrInvalidConfig means the CALLER's configuration is wrong — an AuthKey of
// the wrong size, a MaxPlaintext above MaxPlaintextCeiling, a malformed key
// string. It is never returned because of a row's contents, so it is outside
// the ErrKeyUnavailable / ErrUndecryptable pair that describes rows: it is a
// deployment bug to fix, not a record state to render.
var ErrInvalidConfig = errors.New("scuttle: invalid configuration")

// Binding is the immutable metadata a ciphertext is bound to. Every field is
// mixed into the AEAD's associated data, so all of them must be
// WRITE-ONCE on the stored document: re-parenting a captured row to another
// workspace, or renumbering a user, makes its bodies permanently unreadable.
type Binding struct {
	SchemaVersion int
	EpochID       string
	LeafID        string
	WorkspaceID   int
	UserID        int
	RequestID     string
}

// aad builds the canonical associated data for one field.
//
// Every part is LENGTH-PREFIXED. Plain concatenation is ambiguous —
// (workspace 1, user 23) and (workspace 12, user 3) both render "123" — and
// the ambiguity is exactly a cross-tenant splice that would pass the tag
// check. The prefix makes the encoding injective.
//
// authed selects the domain separator of the authenticated mode, so the
// associated data itself also differs between the two modes.
func (b Binding) aad(authed bool, field string) []byte {
	prefix := hkdfInfoPrefix
	if authed {
		prefix = hkdfInfoPrefixAuth
	}
	parts := [][]byte{
		[]byte(prefix),
		[]byte(strconv.Itoa(b.SchemaVersion)),
		[]byte(b.EpochID),
		[]byte(b.LeafID),
		[]byte(strconv.Itoa(b.WorkspaceID)),
		[]byte(strconv.Itoa(b.UserID)),
		[]byte(b.RequestID),
		[]byte(field),
	}
	n := 0
	for _, p := range parts {
		n += 4 + len(p)
	}
	out := make([]byte, 0, n)
	var lp [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(lp[:], uint32(len(p)))
		out = append(out, lp[:]...)
		out = append(out, p...)
	}
	return out
}

// deriveFieldKey returns the AES-256 key for one (leaf, document, field).
//
// Derived, never stored: this is what makes per-document key storage zero. It
// also scopes a compromise — a field key opens one field of one document and
// says nothing about the leaf it came from, because HKDF is one-way.
//
// Unauthenticated mode (authKey empty): HKDF-Expand with the leaf key as the
// PRK. The leaf key is 32 uniformly random bytes, which is what Expand needs.
//
// Authenticated mode: full HKDF with authKey as the salt, so the PRK is
// HMAC(authKey, leafKey). A forger chooses their own leaf key and can wrap it
// to the public capture key, but without authKey cannot compute the field key
// and therefore cannot produce a tag the reader accepts.
func deriveFieldKey(leafKey, authKey []byte, b Binding, field string) ([]byte, error) {
	if len(leafKey) != LeafKeySize {
		return nil, fmt.Errorf("scuttle: leaf key must be %d bytes, got %d", LeafKeySize, len(leafKey))
	}
	var r io.Reader
	if len(authKey) == 0 {
		r = hkdf.Expand(sha256.New, leafKey, b.aad(false, field))
	} else {
		r = hkdf.New(sha256.New, leafKey, authKey, b.aad(true, field))
	}
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("scuttle: hkdf expand: %w", err)
	}
	return out, nil
}

// Envelope seals and opens individual fields. The zero value is usable.
//
// Writers and readers of the same rows must use the same configuration:
// MaxPlaintext because Seal refuses what Open would, and AuthKey because it
// changes the field key.
type Envelope struct {
	// MaxPlaintext caps the plaintext size: Seal refuses a larger body and
	// Open refuses to decompress past it. Zero means DefaultMaxPlaintext.
	// Never unbounded: an attacker who can write to the database could
	// otherwise trade a few hundred stored bytes for an out-of-memory kill on
	// the reader. Values above MaxPlaintextCeiling are ErrInvalidConfig.
	MaxPlaintext int

	// AuthKey, when set, authenticates rows against anyone who can write to
	// storage. Exactly AuthKeySize secret random bytes (GenerateAuthKey),
	// held by writers and readers and NEVER stored with the data.
	//
	// Without it, the public capture key is all a forger needs to plant a row
	// that opens cleanly as any tenant's. With it, a row opens only if it was
	// sealed by a holder of this key. Every writer holds it, so a compromised
	// writer can still forge — it could write false logs anyway.
	//
	// Turning it on is a cutover: a reader with an AuthKey refuses rows sealed
	// without one (otherwise a forger would simply write unauthenticated
	// rows). Keep a reader without it only for rows you know predate the
	// cutover, e.g. by Binding.SchemaVersion.
	AuthKey []byte
}

// config validates the envelope and returns its effective plaintext cap.
func (e Envelope) config() (int, error) {
	if n := len(e.AuthKey); n != 0 {
		if n != AuthKeySize {
			return 0, fmt.Errorf("%w: auth key must be %d bytes, got %d", ErrInvalidConfig, AuthKeySize, n)
		}
		if allZero(e.AuthKey) {
			return 0, fmt.Errorf("%w: auth key is all zeros", ErrInvalidConfig)
		}
	}
	switch {
	case e.MaxPlaintext > MaxPlaintextCeiling:
		return 0, fmt.Errorf("%w: MaxPlaintext %d exceeds MaxPlaintextCeiling %d",
			ErrInvalidConfig, e.MaxPlaintext, MaxPlaintextCeiling)
	case e.MaxPlaintext > 0:
		return e.MaxPlaintext, nil
	default:
		return DefaultMaxPlaintext, nil
	}
}

func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// MaxPlaintextCeiling bounds what the decoder will ALLOCATE, independently of
// any Envelope's policy cap. The two are not the same defence and both are
// needed: checking the length after DecodeAll returns is a policy check that
// has already paid for the memory, so a row engineered to expand to gigabytes
// would take the reader down before the check ran.
//
// Envelope.MaxPlaintext may not exceed it. It once could, and the ceiling
// silently won on read — so bodies between the two sealed fine and never
// opened again.
const MaxPlaintextCeiling = 16 << 20 // 16 MiB

// Encoders and decoders are safe for concurrent use and cheap to share; a
// per-call one would allocate a window on every body.
var (
	zstdEnc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
	zstdDec, _ = zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(MaxPlaintextCeiling),
	)
)

// Seal compresses then encrypts one field, returning nonce || ciphertext || tag.
//
// Compress-then-encrypt is deliberate. Ciphertext is incompressible, so
// sealing raw bodies would defeat a storage engine's block compression and inflate
// stored payloads several-fold. The usual objection (CRIME/BREACH) needs
// attacker-chosen plaintext compressed ALONGSIDE a secret in one context;
// every field of every document is compressed independently here, so no
// tenant's prompt ever shares a compression context with another tenant's
// anything. What remains observable is the compressed length; scuttle does not
// pad and does not claim to hide payload size.
//
// A body over the cap is refused with ErrPlaintextTooLarge: Open would refuse
// it, and a write that succeeds into an unreadable row is data loss.
func (e Envelope) Seal(leafKey []byte, b Binding, field string, plaintext []byte) ([]byte, error) {
	max, err := e.config()
	if err != nil {
		return nil, err
	}
	if len(plaintext) > max {
		return nil, fmt.Errorf("%w: %d bytes, cap %d", ErrPlaintextTooLarge, len(plaintext), max)
	}
	key, err := deriveFieldKey(leafKey, e.AuthKey, b, field)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	packed := zstdEnc.EncodeAll(plaintext, nil)

	// Random nonce rather than the all-zeros a once-only derived key would
	// permit. Twelve bytes is not worth the footgun if anything ever
	// re-encrypts a document in place under the same derived key.
	out := make([]byte, nonceSize, nonceSize+len(packed)+gcm.Overhead())
	if _, err := rand.Read(out[:nonceSize]); err != nil {
		return nil, fmt.Errorf("scuttle: nonce: %w", err)
	}
	return gcm.Seal(out, out[:nonceSize], packed, b.aad(len(e.AuthKey) > 0, field)), nil
}

// Open reverses Seal. Every failure caused by the row or the key is
// ErrUndecryptable — see its docs for why the cause is deliberately not
// distinguished. Only a misconfigured Envelope returns ErrInvalidConfig.
func (e Envelope) Open(leafKey []byte, b Binding, field string, blob []byte) ([]byte, error) {
	max, err := e.config()
	if err != nil {
		return nil, err
	}
	key, err := deriveFieldKey(leafKey, e.AuthKey, b, field)
	if err != nil {
		// A wrong-length key came from whatever keyring produced it; the row
		// will not open with it, and no retry changes that.
		return nil, fmt.Errorf("%w: %v", ErrUndecryptable, err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < nonceSize+gcm.Overhead() {
		return nil, ErrUndecryptable
	}
	packed, err := gcm.Open(nil, blob[:nonceSize], blob[nonceSize:], b.aad(len(e.AuthKey) > 0, field))
	if err != nil {
		return nil, ErrUndecryptable
	}
	// The tag has already proven this blob is ours, so the cap is not
	// defending against a forgery — it defends against a corrupt or
	// maliciously-written row expanding without bound on a reader.
	out, err := zstdDec.DecodeAll(packed, make([]byte, 0, min(len(packed)*4, max)))
	if err != nil || len(out) > max {
		return nil, ErrUndecryptable
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("scuttle: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("scuttle: gcm: %w", err)
	}
	return gcm, nil
}
