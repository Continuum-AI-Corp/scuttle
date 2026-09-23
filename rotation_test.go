package scuttle

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Capture-key rotation.
//
// Every sealed row already carries a kem_key_id naming the capture key
// generation that sealed it, and SealedLeaf has the field — but OpenLeaf
// ignored it and always used the single key the keyring held. So changing the
// capture key made every previously-sealed body permanently unreadable, with
// no error at rotation time and no way back: the reader simply started
// reporting "undecryptable" forever.
//
// These tests define rotation as the thing it has to be — the old key stays
// openable while the new one seals — before the code can do it.

func freshSeed(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, CaptureSeedSize)
	if _, err := rand.Read(s); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s
}

// sealUnder produces a row exactly as a relay holding `pub` would.
func sealUnder(t *testing.T, kr Keyring, leafID string) (SealedLeaf, []byte) {
	t.Helper()
	s, err := NewLeafSealer(kr.CapturePublicKey())
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	key, sealed, err := s.NewLeaf(leafID)
	if err != nil {
		t.Fatalf("new leaf: %v", err)
	}
	return sealed, key
}

// TestRotation_RetiredKeyStillOpensOldRows is the whole point: after rotating,
// rows sealed under the previous generation must still open.
func TestRotation_RetiredKeyStillOpensOldRows(t *testing.T) {
	oldSeed, newSeed := freshSeed(t), freshSeed(t)

	// Generation 1 seals a row.
	gen1, err := NewLocalKeyring(oldSeed)
	if err != nil {
		t.Fatalf("gen1: %v", err)
	}
	sealed, wantKey := sealUnder(t, gen1, "ws:1|u:2|w:0")
	if sealed.KemKeyID == "" {
		t.Fatal("a sealed leaf must name the capture generation that sealed it")
	}

	// Rotate: the NEW seed is active, the OLD one retired but retained.
	rotated, err := NewLocalKeyringMulti([][]byte{newSeed, oldSeed})
	if err != nil {
		t.Fatalf("rotated keyring: %v", err)
	}

	got, err := rotated.OpenLeaf(context.Background(), sealed)
	if err != nil {
		t.Fatalf("a row sealed under the retired key would not open: %v", err)
	}
	if !bytes.Equal(got, wantKey) {
		t.Fatal("opened the retired row but recovered the wrong leaf key")
	}
}

// TestRotation_SealsUnderTheActiveKey: the FIRST seed is the one relays seal
// with. Getting this backwards would keep sealing under a key the operator is
// trying to retire.
func TestRotation_SealsUnderTheActiveKey(t *testing.T) {
	activeSeed, retiredSeed := freshSeed(t), freshSeed(t)

	activeOnly, err := NewLocalKeyring(activeSeed)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	rotated, err := NewLocalKeyringMulti([][]byte{activeSeed, retiredSeed})
	if err != nil {
		t.Fatalf("rotated: %v", err)
	}

	if !bytes.Equal(rotated.CapturePublicKey(), activeOnly.CapturePublicKey()) {
		t.Fatal("the keyring publishes a public key that is not the first (active) seed's")
	}
	if rotated.KemKeyID() != activeOnly.KemKeyID() {
		t.Fatalf("kem key id = %q, want the active key's %q",
			rotated.KemKeyID(), activeOnly.KemKeyID())
	}
}

// TestRotation_UnknownGenerationIsUndecryptableNotUnavailable.
//
// The two errors drive different reader states: ErrKeyUnavailable means "try
// again", ErrUndecryptable means "report this". A row sealed under a key the
// operator DROPPED is not going to open on a retry — saying otherwise sends
// someone into a loop instead of to the runbook.
func TestRotation_UnknownGenerationIsUndecryptable(t *testing.T) {
	strangerSeed := freshSeed(t)
	stranger, err := NewLocalKeyring(strangerSeed)
	if err != nil {
		t.Fatalf("stranger: %v", err)
	}
	sealed, _ := sealUnder(t, stranger, "ws:1|u:2|w:0")

	ours, err := NewLocalKeyringMulti([][]byte{freshSeed(t), freshSeed(t)})
	if err != nil {
		t.Fatalf("ours: %v", err)
	}
	_, err = ours.OpenLeaf(context.Background(), sealed)
	if err == nil {
		t.Fatal("opened a leaf sealed under a capture key we do not hold")
	}
	if !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable for a dropped generation, got %v", err)
	}
}

// TestRotation_CacheDoesNotCrossGenerations.
//
// The opened-key cache was keyed by leaf id ALONE. Two generations can carry
// the same leaf id — the id is derived from (workspace, user, window), so a
// rotation mid-window produces exactly that — and a leaf-id-only cache would
// then serve generation 1's key for a generation 2 row. Every field would
// decrypt to garbage or fail its tag, reported as corruption rather than as
// the key mix-up it is.
func TestRotation_CacheDoesNotCrossGenerations(t *testing.T) {
	seedA, seedB := freshSeed(t), freshSeed(t)
	const sharedLeafID = "ws:1|u:2|w:0" // deliberately identical

	genA, err := NewLocalKeyring(seedA)
	if err != nil {
		t.Fatalf("genA: %v", err)
	}
	genB, err := NewLocalKeyring(seedB)
	if err != nil {
		t.Fatalf("genB: %v", err)
	}
	sealedA, keyA := sealUnder(t, genA, sharedLeafID)
	sealedB, keyB := sealUnder(t, genB, sharedLeafID)
	if bytes.Equal(keyA, keyB) {
		t.Fatal("two generations produced the same leaf key; the test proves nothing")
	}

	both, err := NewLocalKeyringMulti([][]byte{seedA, seedB})
	if err != nil {
		t.Fatalf("both: %v", err)
	}
	ctx := context.Background()

	gotA, err := both.OpenLeaf(ctx, sealedA)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	if !bytes.Equal(gotA, keyA) {
		t.Fatal("A opened to the wrong key")
	}
	// Now B, same leaf id, different generation. A leaf-id-only cache returns
	// A's key here.
	gotB, err := both.OpenLeaf(ctx, sealedB)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	if bytes.Equal(gotB, keyA) {
		t.Fatal("the cache served generation A's key for a generation B row")
	}
	if !bytes.Equal(gotB, keyB) {
		t.Fatal("B opened to neither generation's key")
	}
}

// TestRotation_RejectsAnEmptyOrMalformedSet. Fail at boot, loudly, rather than
// come up with a keyring that cannot open anything.
func TestRotation_RejectsAnEmptyOrMalformedSet(t *testing.T) {
	for _, tc := range []struct {
		name  string
		seeds [][]byte
	}{
		{"no seeds", nil},
		{"empty slice", [][]byte{}},
		{"a short seed", [][]byte{freshSeed(t), make([]byte, 8)}},
		{"an empty seed among good ones", [][]byte{freshSeed(t), {}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewLocalKeyringMulti(tc.seeds); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}

// TestRotation_RejectsDuplicateSeeds. The same key twice is a config mistake
// (a paste error while rotating), and silently accepting it hides that the
// "rotation" rotated nothing.
func TestRotation_RejectsDuplicateSeeds(t *testing.T) {
	s := freshSeed(t)
	if _, err := NewLocalKeyringMulti([][]byte{s, s}); err == nil {
		t.Fatal("expected a refusal for a repeated capture key")
	}
}

// TestRotation_SingleSeedMatchesTheOldConstructor keeps NewLocalKeyring a
// special case of the new one rather than a second implementation.
func TestRotation_SingleSeedMatchesTheOldConstructor(t *testing.T) {
	seed := freshSeed(t)
	one, err := NewLocalKeyring(seed)
	if err != nil {
		t.Fatalf("one: %v", err)
	}
	multi, err := NewLocalKeyringMulti([][]byte{seed})
	if err != nil {
		t.Fatalf("multi: %v", err)
	}
	if !bytes.Equal(one.CapturePublicKey(), multi.CapturePublicKey()) {
		t.Fatal("the two constructors disagree on the public key")
	}
	if one.KemKeyID() != multi.KemKeyID() {
		t.Fatal("the two constructors disagree on the kem key id")
	}
}

// TestRotation_CacheNeverServesAKeyAcrossDistinctBlobs.
//
// Found by FuzzRotationNeverServesTheWrongGeneration, which failed on its
// first seed. The cache was keyed by (generation, leaf id), which ASSUMES that
// pair identifies one blob — and nothing here enforces that. Two NewLeaf calls
// with the same id under the same generation mint two different random leaf
// keys, and the second row was handed the first row's key, surfacing later as
// "corruption" rather than as a cache mix-up.
//
// The application using this library makes leaf ids process-unique, so it
// never hit this. A library must not rely on an obligation it never states.
// The cache is keyed by a hash of the BLOB now: two lookups share an entry
// only when they would decapsulate to the same key.
func TestRotation_CacheNeverServesAKeyAcrossDistinctBlobs(t *testing.T) {
	seed := freshSeed(t)
	kr, err := NewLocalKeyring(seed)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	sealer, err := NewLeafSealer(kr.CapturePublicKey())
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	const sameID = "ws:1|u:2|w:0" // deliberately identical
	key1, sealed1, err := sealer.NewLeaf(sameID)
	if err != nil {
		t.Fatalf("leaf 1: %v", err)
	}
	key2, sealed2, err := sealer.NewLeaf(sameID)
	if err != nil {
		t.Fatalf("leaf 2: %v", err)
	}
	if bytes.Equal(key1, key2) {
		t.Fatal("two NewLeaf calls produced the same key; the test proves nothing")
	}

	ctx := context.Background()
	got1, err := kr.OpenLeaf(ctx, sealed1)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	if !bytes.Equal(got1, key1) {
		t.Fatal("first leaf opened to the wrong key")
	}
	got2, err := kr.OpenLeaf(ctx, sealed2)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	if bytes.Equal(got2, key1) {
		t.Fatal("the cache served the FIRST blob's key for a different blob " +
			"sharing its leaf id")
	}
	if !bytes.Equal(got2, key2) {
		t.Fatal("second leaf opened to neither key")
	}
}

// TestCache_KeyCoversEveryInputThatDeterminesTheValue is an invariant over the
// CLASS, not over the three bugs that produced it.
//
// The cached value is hpke.Open(priv_for(KemKeyID), leafInfo(LeafID), Blob).
// Three inputs — and all three are read off a stored row, which this library
// treats as untrusted. Each narrower cache key that has shipped here dropped
// one of them and served one row's key for another row's lookup:
//
//	leaf id only          -> crossed generations
//	(generation, leaf id) -> crossed blobs        (found by a fuzz target)
//	blob only             -> crossed leaf ids     (found by a review pass)
//
// So the test varies each input ALONE against a PRIMED cache. Priming is the
// part the older single-purpose tests missed: on a cold keyring every lookup
// reaches hpke.Open, which enforces all three bindings itself, and the cache
// is never asked the question.
func TestCache_KeyCoversEveryInputThatDeterminesTheValue(t *testing.T) {
	newSeed, oldSeed := freshSeed(t), freshSeed(t)
	kr, err := NewLocalKeyringMulti([][]byte{newSeed, oldSeed})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	retired, err := NewLocalKeyring(oldSeed)
	if err != nil {
		t.Fatalf("retired keyring: %v", err)
	}
	sealer, err := NewLeafSealer(kr.CapturePublicKey())
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	const leafID = "ws:1|u:2|w:0"
	primedKey, primed, err := sealer.NewLeaf(leafID)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	// A SECOND leaf under the SAME id and generation: different random key,
	// different blob. This is what makes the blob a genuinely free variable.
	otherKey, other, err := sealer.NewLeaf(leafID)
	if err != nil {
		t.Fatalf("second leaf: %v", err)
	}
	if bytes.Equal(primedKey, otherKey) {
		t.Fatal("two NewLeaf calls produced the same key; the blob case proves nothing")
	}

	ctx := context.Background()
	got, err := kr.OpenLeaf(ctx, primed) // prime
	if err != nil {
		t.Fatalf("priming open: %v", err)
	}
	if !bytes.Equal(got, primedKey) {
		t.Fatal("the priming open returned the wrong key")
	}

	cases := []struct {
		input  string // the cache-key input this case varies
		row    SealedLeaf
		expect func(t *testing.T, got []byte, err error)
	}{{
		input: "blob",
		row:   SealedLeaf{LeafID: leafID, KemKeyID: primed.KemKeyID, Blob: other.Blob},
		expect: func(t *testing.T, got []byte, err error) {
			// A legitimate second row: it must open, to ITS OWN key.
			if err != nil {
				t.Fatalf("a valid second leaf failed to open: %v", err)
			}
			if bytes.Equal(got, primedKey) {
				t.Fatal("served the primed blob's key for a different blob")
			}
			if !bytes.Equal(got, otherKey) {
				t.Fatal("opened to neither key")
			}
		},
	}, {
		input: "leaf id",
		row:   SealedLeaf{LeafID: leafID + "-other", KemKeyID: primed.KemKeyID, Blob: primed.Blob},
		expect: func(t *testing.T, got []byte, err error) {
			// leafInfo binds the id into the open, so a re-filed blob must be
			// refused — including when the cache holds its key already.
			if !errors.Is(err, ErrUndecryptable) {
				t.Fatalf("a blob re-filed under another leaf id was accepted "+
					"(primed key served: %v): %v", bytes.Equal(got, primedKey), err)
			}
		},
	}, {
		input: "generation",
		row:   SealedLeaf{LeafID: leafID, KemKeyID: retired.KemKeyID(), Blob: primed.Blob},
		expect: func(t *testing.T, got []byte, err error) {
			// A held-but-wrong generation: the keyring HAS this private key,
			// so the lookup gets as far as an open, and that open must fail.
			if !errors.Is(err, ErrUndecryptable) {
				t.Fatalf("a blob attributed to the wrong generation was accepted "+
					"(primed key served: %v): %v", bytes.Equal(got, primedKey), err)
			}
		},
	}}

	// The table is the point, so it must not silently fall behind the function
	// it describes: a fourth input added to leafCacheKey has to be registered
	// here the day it is added, not the day it crosses two rows in production.
	if want := leafCacheKeyInputs(t); len(cases) != want {
		t.Fatalf("leafCacheKey takes %d inputs but this table covers %d; "+
			"register the new input as a case", want, len(cases))
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := kr.OpenLeaf(ctx, tc.row)
			tc.expect(t, got, err)
		})
	}
}

// leafCacheKeyInputs counts leafCacheKey's parameters by reading the source,
// so the table above is checked against the function rather than against a
// number someone remembered to update.
func leafCacheKeyInputs(t *testing.T) int {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "keyring.go", nil, 0)
	if err != nil {
		t.Fatalf("parse keyring.go: %v", err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "leafCacheKey" || fn.Recv != nil {
			continue
		}
		n := 0
		for _, field := range fn.Type.Params.List {
			n += len(field.Names) // `a, b string` is one field, two inputs
		}
		return n
	}
	t.Fatal("leafCacheKey not found in keyring.go; if it was renamed, point " +
		"this test at the new name rather than deleting the check")
	return 0
}
