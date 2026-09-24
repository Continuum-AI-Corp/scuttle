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
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync"

	"github.com/klauspost/compress/zstd"
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
//
// The binding is only as specific as its values. Two stored records with the
// same Binding can have their field blobs swapped undetected, so RequestID
// must be unique per STORED RECORD — if one request writes several records
// (retries, fallbacks), include the attempt. Columns outside the Binding
// (model name, status, timestamps, KemKeyID) are not authenticated at all:
// put anything you rely on into one of these fields.
type Binding struct {
	// SchemaVersion is the application's record-format version.
	SchemaVersion int
	// EpochID is free-form application context, typically the retention or
	// key-rotation period the record belongs to. Empty is allowed.
	EpochID string
	// LeafID is the SealedLeaf.LeafID whose key sealed this record.
	LeafID string
	// WorkspaceID and UserID are the tenant the record belongs to.
	WorkspaceID int
	UserID      int
	// RequestID identifies the stored record; it must be unique per record.
	RequestID string
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
		return nil, fmt.Errorf("%w: leaf key must be %d bytes, got %d", ErrInvalidConfig, LeafKeySize, len(leafKey))
	}
	if allZero(leafKey) {
		// The exact shape of the historical bug in ATTACK.md claim 1: a
		// zeroed key has the right length and derives valid-looking keys.
		return nil, fmt.Errorf("%w: leaf key is all zeros", ErrInvalidConfig)
	}
	var out []byte
	var err error
	if len(authKey) == 0 {
		out, err = hkdf.Expand(sha256.New, leafKey, string(b.aad(false, field)), 32)
	} else {
		out, err = hkdf.Key(sha256.New, leafKey, authKey, string(b.aad(true, field)), 32)
	}
	if err != nil {
		return nil, fmt.Errorf("scuttle: hkdf: %w", err)
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
	// rows). Re-seal existing rows with Reseal, then read with the
	// authenticated Envelope ONLY. Never choose the Envelope per row from a
	// stored value such as Binding.SchemaVersion: a forger writes that value
	// too. Rotating the AuthKey is the same procedure.
	AuthKey []byte

	// DisableCompression stores fields uncompressed (still as a valid zstd
	// frame, so readers need no setting and existing readers open the rows).
	//
	// Compression makes the ciphertext's length depend on the plaintext's
	// redundancy. When one field holds a secret next to text an attacker can
	// influence — a system prompt or credential beside user or retrieved
	// content, an Authorization header beside client-chosen headers — an
	// attacker who can read stored lengths can confirm guesses about the
	// secret one request at a time (the CRIME attack). With compression off,
	// the length reveals only the plaintext length, which scuttle never hides.
	// The cost is storage: bodies are no longer shrunk.
	DisableCompression bool
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
	case e.MaxPlaintext < 0:
		return 0, fmt.Errorf("%w: MaxPlaintext %d is negative", ErrInvalidConfig, e.MaxPlaintext)
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

// The shared encoder. EncodeAll is safe for concurrent use; the concurrency
// option is how many EncodeAll calls may run AT ONCE, so it is sized to the
// machine rather than 1 — at 1 every Seal in the process ran single file.
var zstdEnc, _ = zstd.NewWriter(nil,
	zstd.WithEncoderLevel(zstd.SpeedDefault),
	zstd.WithEncoderConcurrency(runtime.GOMAXPROCS(0)),
)

// Decoders are bounded PER ENVELOPE CAP, not only by MaxPlaintextCeiling.
//
// A decoder bounded only by the ceiling let a row of a few hundred bytes make
// a reader with a 1 MiB cap allocate 16 MiB (and a frame without a content
// size, ~90 MiB of growth) before the cap was checked. zstd's memory option
// bounds both the decoded size and the window a frame may declare, so each cap
// is decoded under a limit just above what Seal can produce for it:
//
//	decoderLimit(cap) = next power of two ≥ max(2*cap, 64 KiB), at most MaxPlaintextCeiling
//
// Twice the cap because the encoder declares a window of up to twice the body
// for bodies under 64 KiB (the next power of two, at least 1 KiB); the floor
// covers the smallest bodies. Rounding to a power of two leaves at most nine
// distinct limits (64 KiB … 16 MiB), so every one gets a long-lived shared
// decoder and none is ever built per call. TestSealOpen_RoundTripsAtEveryCapBoundary
// pins that no row Seal wrote is refused by this bound.
func decoderLimit(capBytes int) int {
	limit := 64 << 10
	for limit < 2*capBytes && limit < MaxPlaintextCeiling {
		limit <<= 1
	}
	return min(limit, MaxPlaintextCeiling)
}

var sharedDecoders = struct {
	sync.Mutex
	byLimit map[int]*zstd.Decoder
}{byLimit: map[int]*zstd.Decoder{}}

// decoderFor returns the shared decoder for a limit. DecodeAll is safe for
// concurrent use, and the concurrency option is how many may run at once — at
// 1 (as it once was) every Open in the process queued behind the slowest.
// It is capped at 4 because each slot can keep up to a cap's worth of buffer
// alive between calls, and nine limits × GOMAXPROCS slots × 16 MiB is a lot of
// memory to hold for a throughput gain that stops mattering well before that.
//
// DecodeAllCapLimit makes DecodeAll decode into the capacity it is given and
// fail rather than grow. Without it, every frame that declares a content size
// reallocates the output and copies everything decoded so far, so a row of
// many small frames cost memory quadratic in the cap (2 GB for a 22 KB row
// under a 1 MiB cap).
func decoderFor(limit int) (*zstd.Decoder, error) {
	sharedDecoders.Lock()
	defer sharedDecoders.Unlock()
	if d, ok := sharedDecoders.byLimit[limit]; ok {
		return d, nil
	}
	d, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(min(runtime.GOMAXPROCS(0), 4)),
		zstd.WithDecoderMaxMemory(uint64(limit)),
		zstd.WithDecodeAllCapLimit(true),
	)
	if err != nil {
		return nil, err
	}
	sharedDecoders.byLimit[limit] = d
	return d, nil
}

// decodeCapped decompresses packed with allocation bounded by capBytes, and
// refuses output longer than capBytes.
func decodeCapped(packed []byte, capBytes int) ([]byte, error) {
	dec, err := decoderFor(decoderLimit(capBytes))
	if err != nil {
		return nil, err
	}
	// Decode into a fixed buffer; DecodeAllCapLimit refuses to grow it. The
	// first try is sized from the frame's declared content size when it has
	// one, so an honest row allocates about its own size, not the cap. If that
	// was too small (no declared size, or several frames), retry once at the
	// full cap. Any error retries, not only "size exceeded": the decoder
	// reports a too-small buffer in more than one way.
	full := capBytes + 1024 // slack the decoder wants beyond the content
	guess := min(len(packed)*4, full)
	var h zstd.Header
	if h.Decode(packed) == nil && h.HasFCS {
		guess = min(int(min(h.FrameContentSize, uint64(capBytes)))+1024, full)
	}
	out, err := dec.DecodeAll(packed, make([]byte, 0, guess))
	if err != nil && guess < full {
		out, err = dec.DecodeAll(packed, make([]byte, 0, full))
	}
	if err != nil {
		return nil, err
	}
	if len(out) > capBytes {
		return nil, errors.New("scuttle: plaintext exceeds the envelope's cap")
	}
	return out, nil
}

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
	if field == "" {
		return nil, fmt.Errorf("%w: field name is empty", ErrInvalidConfig)
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
	var packed []byte
	if e.DisableCompression {
		packed = storedFrame(plaintext)
	} else {
		packed = zstdEnc.EncodeAll(plaintext, nil)
	}

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
	if field == "" {
		return nil, ErrUndecryptable // Seal never writes one
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
	if len(blob) < nonceSize+gcm.Overhead() || len(blob) > maxBlobLen(max) {
		// Too long is refused before decrypting: decrypting allocates the
		// whole blob, and nothing Seal writes under this cap is that long.
		return nil, ErrUndecryptable
	}
	packed, err := gcm.Open(nil, blob[:nonceSize], blob[nonceSize:], b.aad(len(e.AuthKey) > 0, field))
	if err != nil {
		return nil, ErrUndecryptable
	}
	// The tag has already proven this blob is ours, so the cap is not
	// defending against a forgery — it defends against a corrupt or
	// maliciously-written row expanding without bound on a reader.
	out, err := decodeCapped(packed, max)
	if err != nil {
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

// storedFrame wraps p in a zstd frame of raw (uncompressed) blocks, so its
// size depends only on len(p): 9 bytes of frame header, and a 3-byte header
// per 128 KiB block. It is an ordinary zstd frame, so every reader decodes it.
//
//	magic 28 B5 2F FD | descriptor A0 (single segment, 4-byte content size)
//	| content size (u32 LE) | blocks: u24 LE (size<<3 | raw<<1 | last), bytes
func storedFrame(p []byte) []byte {
	const maxBlock = 128 << 10
	out := make([]byte, 0, 9+len(p)+3*(len(p)/maxBlock+1))
	out = append(out, 0x28, 0xB5, 0x2F, 0xFD, 0xA0)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(p)))
	for off := 0; ; {
		n := min(maxBlock, len(p)-off)
		last := off+n == len(p)
		hdr := uint32(n) << 3 // block type 0: raw
		if last {
			hdr |= 1
		}
		out = append(out, byte(hdr), byte(hdr>>8), byte(hdr>>16))
		out = append(out, p[off:off+n]...)
		off += n
		if last {
			return out
		}
	}
}

// Reseal moves one stored field from one Envelope configuration to another,
// keeping its leaf and binding: it opens blob with from and seals the result
// with to. The caller needs the leaf key, so this runs on the reader side.
//
// It is how the AuthKey cutover is done safely — re-seal every existing row
// from the unauthenticated Envelope to the authenticated one, then read ONLY
// with the authenticated one — and how an AuthKey is rotated. Never choose the
// Envelope per row from a stored value such as Binding.SchemaVersion: a forger
// writes that value too, and routes the forgery to the unauthenticated path.
//
// A row that does not open under from is ErrUndecryptable and is not written.
// Re-sealing authenticates whatever was stored at the time, including any row
// forged before the migration FINISHES: it cannot tell forged legacy rows from
// real ones. Run it once, keep readers on from until it ends, then switch
// them all to to; never let a reader fall back from one to the other.
//
// The result takes all of to's settings: set DisableCompression on to if the
// field should stay uncompressed. Reseal also permits the downgrade from an
// authenticated Envelope to an unauthenticated one; do not do that.
func Reseal(leafKey []byte, b Binding, field string, blob []byte, from, to Envelope) ([]byte, error) {
	pt, err := from.Open(leafKey, b, field, blob)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	return to.Seal(leafKey, b, field, pt)
}

// maxBlobLen is the longest field blob Seal can produce under a cap: nonce and
// tag, a zstd frame header (at most 18 bytes) and checksum (4), and at worst
// the body stored raw in 128 KiB blocks of 3-byte headers — compression never
// makes zstd output longer than that — plus slack.
func maxBlobLen(capBytes int) int {
	return nonceSize + 16 + 18 + 4 + capBytes + 3*(capBytes/(128<<10)+2) + 64
}
