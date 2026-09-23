package scuttle

import (
	"context"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
)

// captureKEM is the hybrid post-quantum KEM the capture key uses:
// ML-KEM-768 + X25519 (X-Wing).
//
// Hybrid rather than pure ML-KEM because ML-KEM is young: X-Wing is secure if
// EITHER component holds, so a cryptanalytic surprise in the lattice half
// degrades this to today's security rather than to none. The cost is 32 bytes
// per leaf.
//
// Post-quantum at all because the ciphertext outlives the policy: a body
// sealed today sits in a seven-year backup until 2033, and NIST's draft
// transition guidance disallows classical public-key after 2035. That is
// harvest-now-decrypt-later, and it applies to exactly this step — how the
// content key is wrapped. Symmetric crypto is already post-quantum, which is
// why ML-KEM appears here and nowhere else in this package.
//
// Changing this constant changes the wire format. kem_key_id on every sealed
// leaf is what makes a future change survivable; see SealedLeaf.
func captureKEM() hpke.KEM { return hpke.MLKEM768X25519() }

// hpkeInfo is the HPKE info string. Like the field tags it is part of the
// format: a change makes existing sealed leaves unopenable.
var hpkeInfo = []byte("orca/rlog/leaf/v1")

// CaptureSeedSize is the exact byte length of a capture private key seed for
// this KEM. Exported because the operator generates it (openssl rand -hex 32)
// and the boot path validates it: hpke rejects any other length with
// "invalid hybrid KEM secret length", which is a correct but unhelpful thing
// to find out at start-up.
const CaptureSeedSize = 32

// PublicKeyBytes is a serialized capture public key. It is public by design:
// every relay holds one and it grants only the ability to SEAL.
//
// It authenticates nothing — HPKE base mode has no sender authentication, so
// anyone holding this key can produce a well-formed SealedLeaf. That matters
// only where sealed leaves are ACCEPTED from somewhere; carrying the blob on
// the document removes that surface, because a forged leaf can only key the
// forger's own row.
type PublicKeyBytes []byte

// SealedLeaf is a leaf key encapsulated to the capture public key. It is safe
// to queue, retry, and carry over any channel: only the keyring can open it.
type SealedLeaf struct {
	LeafID string
	// KemKeyID identifies the capture key generation that sealed this leaf,
	// so rotating the capture key does not strand blobs sealed under the
	// previous one. Rotation is not erasure: the keyring keeps retired
	// private keys until nothing sealed under them remains.
	KemKeyID string
	Blob     []byte
}

// LeafSealer is the relay-side half. It holds a public key and nothing else,
// which is the property that makes a whole-fleet compromise yield at most
// leaf_ttl of traffic and never history.
type LeafSealer struct {
	pub      hpke.PublicKey
	kemKeyID string
}

// NewLeafSealer builds a sealer from a serialized capture public key.
func NewLeafSealer(pub PublicKeyBytes) (*LeafSealer, error) {
	pk, err := loadPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return &LeafSealer{pub: pk, kemKeyID: KemKeyIDFor(pub)}, nil
}

// loadPublicKey parses a capture public key and proves it can be sealed to.
// Parsing alone accepts keys that fail on every encapsulation (an all-zero
// X25519 half is a low-order point); a writer configured with one would start
// cleanly and then lose every write. One trial seal at load costs about a
// millisecond once.
func loadPublicKey(pub PublicKeyBytes) (hpke.PublicKey, error) {
	pk, err := captureKEM().NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: capture public key: %v", ErrInvalidConfig, err)
	}
	if _, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("scuttle/load-check"), nil); err != nil {
		return nil, fmt.Errorf("%w: capture public key cannot be sealed to: %v", ErrInvalidConfig, err)
	}
	return pk, nil
}

// KemKeyID identifies the capture key generation this sealer seals to. It is
// stamped on every document so a later capture-key rotation can still find
// the right private key.
func (s *LeafSealer) KemKeyID() string { return s.kemKeyID }

// NewLeaf mints a fresh random leaf key and seals it to the capture key.
//
// The caller keeps the returned key in memory for at most leaf_ttl and then
// forgets it; the SealedLeaf goes to the keyring. The relay never learns any
// other leaf's key, so rooting one pod yields that pod's current window only.
func (s *LeafSealer) NewLeaf(leafID string) (leafKey []byte, sealed SealedLeaf, err error) {
	if leafID == "" || len(leafID) > MaxLeafIDLength {
		return nil, SealedLeaf{}, fmt.Errorf("%w: leaf id must be 1 to %d bytes, got %d", ErrInvalidConfig, MaxLeafIDLength, len(leafID))
	}
	leafKey = make([]byte, LeafKeySize)
	if _, err = rand.Read(leafKey); err != nil {
		return nil, SealedLeaf{}, fmt.Errorf("scuttle: leaf key: %w", err)
	}
	blob, err := hpke.Seal(s.pub, hpke.HKDFSHA256(), hpke.AES256GCM(), leafInfo(leafID), leafKey)
	if err != nil {
		return nil, SealedLeaf{}, fmt.Errorf("scuttle: seal leaf: %w", err)
	}
	return leafKey, SealedLeaf{LeafID: leafID, KemKeyID: s.kemKeyID, Blob: blob}, nil
}

// sealedLeafSize is the exact length of a sealed leaf: the 1120-byte X-Wing
// encapsulated key plus the 32-byte leaf key and 16-byte AEAD tag (SPEC.md §2).
const sealedLeafSize = 1168

// MaxLeafIDLength bounds a leaf id. The id goes into the HPKE info, the cache
// key and error messages, and a row is untrusted input: without a bound a
// hostile row picks how much work and log volume it costs.
const MaxLeafIDLength = 256

// leafInfo binds the envelope to its leaf id, so a blob cannot be re-filed
// under a different id even by whoever sealed it.
func leafInfo(leafID string) []byte {
	out := make([]byte, 0, len(hpkeInfo)+1+len(leafID))
	out = append(out, hpkeInfo...)
	out = append(out, '|')
	return append(out, leafID...)
}

// KemKeyIDFor derives a short, stable identifier for a capture key
// generation. A hash of the public key rather than a counter: it needs no
// coordination, and two deployments that share a key agree on its id.
func KemKeyIDFor(pub PublicKeyBytes) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Keyring is the privileged half. Only it can open a sealed leaf, and
// therefore only it can open a body.
//
// It is addressed by BLOB, not by id. An earlier shape had relays ship sealed
// leaves to the keyring over a channel and the keyring hold them in a map
// keyed by leaf id. That shape had four failure modes and this one has none
// of them:
//
//   - a restart lost every leaf, so all prior bodies became permanently
//     unreadable while reporting themselves as merely "unavailable";
//   - two pods derived the same leaf id and different keys, so with a shared
//     keyring the second pod's bodies were dropped and with per-pod keyrings
//     most reads missed;
//   - the map grew for the process lifetime with nothing tying it to
//     document retention;
//   - the ingest endpoint accepted anything well-formed, because the sealing
//     key is public by design and HPKE base mode authenticates no sender.
//
// Carrying the sealed blob on the document itself removes the channel, and
// with it all four. The row becomes self-contained: any process holding the
// capture private key can open it, and no process needs to have been running
// when it was written. The cost is the blob's 1168 bytes on every record that
// carries it; records that share a leaf window may store it once and refer to
// it instead.
type Keyring interface {
	// OpenLeaf opens a sealed leaf blob. Implementations may cache, subject to
	// two obligations that are easy to miss and silent to get wrong:
	//
	// The cache key must cover every input that determines the opened key —
	// the capture-key generation, the leaf id, AND the blob. Narrower keys
	// serve one row's key for another row; see leafCacheKey for the three that
	// were tried here.
	//
	// The RETURNED SLICE IS THE CALLER'S: the caller is entitled to zeroize
	// it, so an implementation that caches must return a copy. (The obvious
	// "return the cached slice" implementation is destroyed by its first
	// reader, silently — a zeroed key still has the right length and derives a
	// perfectly valid-looking field key.)
	OpenLeaf(ctx context.Context, sealed SealedLeaf) ([]byte, error)
	// CapturePublicKey returns what relays should seal to.
	CapturePublicKey() PublicKeyBytes
	// KemKeyID identifies this keyring's current capture key generation.
	KemKeyID() string
}

// LocalKeyring holds the capture private key in this process and caches
// opened leaf keys.
//
// The cache is an optimisation only: every leaf it can open is reconstructible
// from the document's own blob, so losing it costs a few microseconds rather
// than any data. A deployment that wants the private key somewhere the relay
// is not implements this interface against a KMS instead.
type LocalKeyring struct {
	// The ACTIVE generation: what NewLeaf seals under, and the only key this
	// keyring publishes.
	priv     hpke.PrivateKey
	pub      PublicKeyBytes
	kemKeyID string

	// Every generation this keyring can OPEN, active included, by kem key id.
	//
	// Rotation is the reason this is a map. A sealed row names the generation
	// that sealed it, and before this existed OpenLeaf ignored that name and
	// always used the single key it held — so changing the capture key made
	// every previously-sealed body permanently unreadable, with no error at
	// rotation time. Retiring a key means dropping it from this map, which is
	// a deliberate act with a visible consequence, not a side effect of
	// editing one environment variable.
	byKeyID map[string]hpke.PrivateKey

	// The same generations in configured order, active first: the order an
	// UNSTAMPED row tries them in. Written once at construction.
	ordered []hpke.PrivateKey

	// requireStamp refuses unstamped rows (RequireGenerationStamp).
	requireStamp bool

	mu    sync.RWMutex
	cache map[string][]byte
}

var _ Keyring = (*LocalKeyring)(nil)

// maxCachedLeaves bounds the opened-key cache. Unbounded would grow one entry
// per (workspace, user, window) for the process lifetime with nothing tying it
// to document retention; when it fills, the cache is dropped wholesale
// because every entry is cheap to rebuild from a document blob.
const maxCachedLeaves = 4096

// NewLocalKeyring builds a keyring from one capture seed (the output of
// GenerateCaptureSeed, ParseCaptureSeed or PrivateKeyBytes).
//
// An empty seed is ErrInvalidConfig. It used to mean "generate a fresh key",
// so a reader whose seed variable was unset started successfully and then
// reported every row as undecryptable. Use NewEphemeralKeyring when a
// throwaway key is what you want.
func NewLocalKeyring(seed []byte) (*LocalKeyring, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("%w: capture seed is empty (use NewEphemeralKeyring for a throwaway key)", ErrInvalidConfig)
	}
	return NewLocalKeyringMulti([][]byte{seed})
}

// NewEphemeralKeyring builds a keyring around a freshly generated capture
// key that exists only in this process. Everything sealed to it becomes
// permanently unreadable when the process exits: it is for tests and demos.
func NewEphemeralKeyring() (*LocalKeyring, error) {
	priv, err := captureKEM().GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("scuttle: capture key: %w", err)
	}
	return newLocalKeyring([]hpke.PrivateKey{priv}), nil
}

// NewLocalKeyringMulti builds a keyring over several capture-key generations.
//
// seeds[0] is ACTIVE — the one whose public key relays seal under. The rest
// are RETIRED: still openable, never sealed with. That ordering is the whole
// operator contract for rotation, so it is checked by a test rather than left
// to a comment: prepend the new key, keep the old one, restart. Old rows go on
// opening; new rows use the new key; and when nothing sealed under the old
// generation remains, drop it from the list.
//
// Every seed must be exactly CaptureSeedSize bytes and distinct. A repeated
// seed is refused because it is a paste error with a silent outcome — the
// "rotation" would rotate nothing while appearing to succeed.
func NewLocalKeyringMulti(seeds [][]byte, opts ...KeyringOption) (*LocalKeyring, error) {
	if len(seeds) == 0 {
		return nil, fmt.Errorf("%w: at least one capture key is required", ErrInvalidConfig)
	}
	kem := captureKEM()
	privs := make([]hpke.PrivateKey, 0, len(seeds))
	seen := make(map[string]bool, len(seeds))
	for i, seed := range seeds {
		if len(seed) != CaptureSeedSize {
			return nil, fmt.Errorf(
				"%w: capture key %d is %d bytes, want exactly %d",
				ErrInvalidConfig, i, len(seed), CaptureSeedSize)
		}
		priv, err := kem.NewPrivateKey(seed)
		if err != nil {
			return nil, fmt.Errorf("%w: capture key %d: %v", ErrInvalidConfig, i, err)
		}
		id := KemKeyIDFor(PublicKeyBytes(priv.PublicKey().Bytes()))
		if seen[id] {
			return nil, fmt.Errorf(
				"%w: capture key %d repeats an earlier one; a rotation that "+
					"lists the same key twice rotates nothing", ErrInvalidConfig, i)
		}
		seen[id] = true
		privs = append(privs, priv)
	}
	k := newLocalKeyring(privs)
	for _, o := range opts {
		if o != nil {
			o(k)
		}
	}
	return k, nil
}

// KeyringOption configures a LocalKeyring at construction.
type KeyringOption func(*LocalKeyring)

// RequireGenerationStamp refuses rows whose KemKeyID is empty instead of trying
// every generation for them.
//
// The fallback exists for rows written before rows carried a generation. Once
// none of those remain, it only serves rows nobody honest writes, and each one
// costs a key decapsulation per generation held. Turn this on then.
func RequireGenerationStamp() KeyringOption {
	return func(k *LocalKeyring) { k.requireStamp = true }
}

// newLocalKeyring assembles the struct. privs[0] is active.
func newLocalKeyring(privs []hpke.PrivateKey) *LocalKeyring {
	byID := make(map[string]hpke.PrivateKey, len(privs))
	for _, priv := range privs {
		byID[KemKeyIDFor(PublicKeyBytes(priv.PublicKey().Bytes()))] = priv
	}
	active := privs[0]
	pub := PublicKeyBytes(active.PublicKey().Bytes())
	return &LocalKeyring{
		priv:     active,
		pub:      pub,
		kemKeyID: KemKeyIDFor(pub),
		byKeyID:  byID,
		ordered:  privs,
		cache:    make(map[string][]byte),
	}
}

// CapturePublicKey returns the ACTIVE generation's public key: what writers
// seal to. Retired generations are never published.
func (k *LocalKeyring) CapturePublicKey() PublicKeyBytes { return k.pub }

// KemKeyID identifies the active generation; rows sealed to
// CapturePublicKey are stamped with it.
func (k *LocalKeyring) KemKeyID() string { return k.kemKeyID }

// PrivateKeyBytes serializes the capture private key so an operator can
// persist it deliberately. Whatever writes this value must never reach an
// application log or a SQL log.
func (k *LocalKeyring) PrivateKeyBytes() ([]byte, error) { return k.priv.Bytes() }

// OpenLeaf opens a sealed leaf, caching the result.
//
// Always returns a COPY: the caller zeroizes what it gets back, and handing
// out the cached slice would let the first reader destroy the entry for
// everyone after it — silently, since a zeroed key still has the right length
// and derives a perfectly valid-looking field key.
func (k *LocalKeyring) OpenLeaf(ctx context.Context, sealed SealedLeaf) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		// The one condition a retry does fix. Wraps both, so callers that
		// check for context.Canceled still see it.
		return nil, fmt.Errorf("%w: %w", ErrKeyUnavailable, err)
	}
	if sealed.LeafID == "" || len(sealed.Blob) == 0 {
		// Every record carries its own sealed leaf, so a row without one will
		// not acquire one by waiting. "Unavailable" here once sent readers
		// into an endless retry.
		return nil, fmt.Errorf("%w: leaf %s has no sealed key", ErrUndecryptable, rowText(sealed.LeafID))
	}
	if len(sealed.Blob) != sealedLeafSize {
		// Every blob this KEM produces is exactly this long; anything else
		// is refused before it is hashed into a cache key or decapsulated.
		return nil, fmt.Errorf("%w: leaf %s: sealed key is %d bytes, not %d",
			ErrUndecryptable, rowText(sealed.LeafID), len(sealed.Blob), sealedLeafSize)
	}
	if len(sealed.LeafID) > MaxLeafIDLength {
		return nil, fmt.Errorf("%w: leaf id is %d bytes, over %d", ErrUndecryptable, len(sealed.LeafID), MaxLeafIDLength)
	}
	if sealed.KemKeyID == "" && k.requireStamp {
		return nil, fmt.Errorf("%w: leaf %s carries no generation stamp", ErrUndecryptable, rowText(sealed.LeafID))
	}

	// Which generation sealed this row? The row says so, and until this
	// existed nothing read it — OpenLeaf always used the active key, so
	// rotating the capture key silently orphaned every older row.
	//
	// An UNSTAMPED row (KemKeyID empty) predates the field. It was sealed by
	// whichever generation was active at the time, which after a rotation is
	// no longer the active one — so it tries every generation, active first.
	// That is safe because the HPKE open is authenticated: a wrong generation
	// fails its tag rather than yielding a wrong key.
	//
	// Resolved BEFORE the cache is consulted, for two reasons: the resolved
	// generation is one of the three inputs the cache key covers, and a row
	// naming a generation this keyring does not hold has to fail on its own
	// terms rather than be answered out of a cache it was never entitled to.
	//
	// byKeyID is written once, during construction, and never again — so
	// reading it here needs no lock.
	candidates := k.ordered
	privID := "" // cache namespace for unstamped rows: the whole keyring
	if sealed.KemKeyID != "" {
		found, ok := k.byKeyID[sealed.KemKeyID]
		if !ok {
			// A generation this deployment does not hold: retired and dropped,
			// or a row from another deployment entirely. Undecryptable, not
			// unavailable — no retry will produce the key, and telling the
			// reader to try again sends them into a loop instead of to the
			// runbook.
			return nil, fmt.Errorf(
				"%w: leaf %s was sealed under capture key %s, which this keyring does not hold",
				ErrUndecryptable, rowText(sealed.LeafID), rowText(sealed.KemKeyID))
		}
		candidates = []hpke.PrivateKey{found}
		privID = sealed.KemKeyID
	}

	cacheKey := leafCacheKey(privID, sealed.LeafID, sealed.Blob)

	k.mu.RLock()
	cached, ok := k.cache[cacheKey]
	k.mu.RUnlock()
	if ok {
		return append([]byte(nil), cached...), nil
	}

	var leafKey []byte
	var err error
	for _, priv := range candidates {
		leafKey, err = hpke.Open(priv, hpke.HKDFSHA256(), hpke.AES256GCM(), leafInfo(sealed.LeafID), sealed.Blob)
		if err == nil {
			break
		}
	}
	if err != nil {
		// Damaged or tampered with. (A named-but-unknown generation is caught
		// above, so this does not conflate the two.) Not retryable — the
		// caller maps it to "will not open" rather than "try again".
		return nil, fmt.Errorf("%w: leaf %s: %v", ErrUndecryptable, rowText(sealed.LeafID), err)
	}
	if len(leafKey) != LeafKeySize || allZero(leafKey) {
		// The public key lets anyone wrap a "leaf key" of any length. Handing
		// that on would make the error surface somewhere else, outside the
		// declared pair.
		// An all-zero key is the historical bug's exact shape (ATTACK.md
		// claim 1); nothing honest produces one.
		return nil, fmt.Errorf("%w: leaf %s does not wrap a usable %d-byte key",
			ErrUndecryptable, rowText(sealed.LeafID), LeafKeySize)
	}

	k.mu.Lock()
	if len(k.cache) >= maxCachedLeaves {
		// Shed a quarter, chosen by map iteration order, rather than
		// everything: anyone with the public key can mint valid leaves, and a
		// wholesale drop let one sweep of them empty the cache.
		drop := maxCachedLeaves / 4
		for key := range k.cache {
			if drop == 0 {
				break
			}
			delete(k.cache, key)
			drop--
		}
	}
	k.cache[cacheKey] = append([]byte(nil), leafKey...)
	k.mu.Unlock()
	return leafKey, nil
}

// leafCacheKey names a cached leaf key by EVERY input that determines its
// value: the generation whose private key opens the blob, the leaf id that
// leafInfo binds into the HPKE open, and the blob itself.
//
// Anything narrower lets one lookup be answered with another lookup's key, and
// all three narrower spellings have been live in this cache in turn:
//
//   - Keyed on the LEAF ID alone, a rotation part-way through a window serves
//     generation 1's key for a generation 2 row. Every field then fails its tag
//     and reads as corruption rather than the key mix-up it is.
//   - Keyed on (GENERATION, LEAF ID), that pair is assumed to identify one
//     blob, and nothing enforces it: two NewLeaf calls with the same id under
//     the same generation mint two different random leaf keys, so the second
//     row is handed the first row's key. A fuzz target found this one.
//   - Keyed on the BLOB alone, the leaf id drops out — and the leaf id is
//     exactly what the HPKE open binds. A row presenting a valid blob under a
//     DIFFERENT leaf id is then served from cache with that binding never
//     checked. The envelope's own AAD still refuses such a row downstream, so
//     this eroded defence in depth rather than breaking confidentiality; a
//     cache still must not be the thing that skips a binding.
//
// For an UNSTAMPED row the generation slot is empty: such a row is opened by
// trying every generation this keyring holds, and that set is fixed for the
// keyring's lifetime, so (leaf id, blob) alone determine the answer.
//
// Length-prefixed for the reason Binding.aad is: plain concatenation is
// ambiguous, and an ambiguity here is one entry colliding with another.
// SHA-256 over a ~1 KiB blob costs nothing beside the HPKE open it avoids.
func leafCacheKey(kemKeyID, leafID string, blob []byte) string {
	h := sha256.New()
	var lp [4]byte
	for _, p := range [][]byte{[]byte(kemKeyID), []byte(leafID), blob} {
		binary.BigEndian.PutUint32(lp[:], uint32(len(p)))
		h.Write(lp[:])
		h.Write(p)
	}
	return string(h.Sum(nil))
}

// Generations reports how many capture-key generations this keyring can OPEN
// (the active one plus every retired one still listed).
//
// For the health surface. Right after a rotation this is the one number that
// distinguishes "the retired key loaded" from "the retired key was a typo and
// every older row is about to read as undecryptable" — a distinction the
// operator otherwise makes by opening an old row and hoping.
//
// A COUNT, never the ids and never the material.
func (k *LocalKeyring) Generations() int { return len(k.byKeyID) }

// CachedLeaves reports the opened-key cache size, for the health surface.
func (k *LocalKeyring) CachedLeaves() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.cache)
}

// rowText renders an untrusted row value for an error message: quoted, so a
// newline cannot forge a log line, and cut short, so a hostile row cannot
// choose how large the error (and the log it lands in) is.
func rowText(s string) string {
	const limit = 64
	if len(s) <= limit {
		return strconv.Quote(s)
	}
	return fmt.Sprintf("%s…(%d bytes)", strconv.Quote(s[:limit]), len(s))
}
