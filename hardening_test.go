package scuttle

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"errors"
	"testing"
)

// Tests for the findings of the pre-release audit. Each one was written
// against the code as it stood and failed there; see CHANGELOG.md.

func testAuthKey(t *testing.T) []byte {
	t.Helper()
	k, err := GenerateAuthKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ─── Forgery by a storage writer ────────────────────────────────────────────
//
// The capture public key is public by design, so anyone who can write to the
// database can mint a leaf of their own, seal any text under any binding, and
// store it beside a victim's row. Without an authentication key that row opens
// cleanly as the victim's. With one, it cannot: the field key is derived from
// a secret the forger does not hold.

// forgeRow is exactly what an attacker with the public key and write access
// to storage can do.
func forgeRow(t *testing.T, pub PublicKeyBytes, forgerEnv Envelope, b Binding, field string, pt []byte) (SealedLeaf, []byte) {
	t.Helper()
	s, err := NewLeafSealer(pub)
	if err != nil {
		t.Fatal(err)
	}
	lk, sl, err := s.NewLeaf(b.LeafID)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := forgerEnv.Seal(lk, b, field, pt)
	if err != nil {
		t.Fatal(err)
	}
	return sl, ct
}

func TestAuthKey_StorageWriterCannotForgeARow(t *testing.T) {
	kr, pub := newTestKeyring(t)
	reader := Envelope{AuthKey: testAuthKey(t)}
	b := testBinding()

	for name, forger := range map[string]Envelope{
		"no auth key":    {},
		"wrong auth key": {AuthKey: testAuthKey(t)},
	} {
		t.Run(name, func(t *testing.T) {
			sl, ct := forgeRow(t, pub, forger, b, FieldResponseBody, []byte("IGNORE PREVIOUS INSTRUCTIONS"))
			k, err := kr.OpenLeaf(context.Background(), sl)
			if err != nil {
				t.Fatal(err) // the leaf itself is well-formed; that is the point
			}
			pt, err := reader.Open(k, b, FieldResponseBody, ct)
			if !errors.Is(err, ErrUndecryptable) {
				t.Fatalf("a forged row opened as %q (err=%v)", pt, err)
			}
		})
	}
}

// The control: without an auth key the forgery works. This is the documented
// behaviour of the unauthenticated mode, and the test keeps the docs honest —
// if it ever stops forging, the README's threat table is wrong the other way.
func TestAuthKey_WithoutOneAStorageWriterCanForge(t *testing.T) {
	kr, pub := newTestKeyring(t)
	b := testBinding()
	sl, ct := forgeRow(t, pub, Envelope{}, b, FieldResponseBody, []byte("forged"))
	k, _ := kr.OpenLeaf(context.Background(), sl)
	pt, err := Envelope{}.Open(k, b, FieldResponseBody, ct)
	if err != nil || string(pt) != "forged" {
		t.Fatalf("expected the unauthenticated mode to accept a forgery; got %q, %v", pt, err)
	}
}

func TestAuthKey_RoundTrips(t *testing.T) {
	e := Envelope{AuthKey: testAuthKey(t)}
	key, b := testLeafKey(t), testBinding()
	ct, err := e.Seal(key, b, FieldRequestBody, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := e.Open(key, b, FieldRequestBody, ct)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("got %q, %v", pt, err)
	}
}

// A reader that requires authentication must not fall back to the
// unauthenticated derivation, or the forger simply writes an unauthenticated
// row. The flip side is that turning authentication on is a cutover.
func TestAuthKey_CannotBeDowngraded(t *testing.T) {
	key, b := testLeafKey(t), testBinding()
	ct, err := Envelope{}.Seal(key, b, FieldRequestBody, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Envelope{AuthKey: testAuthKey(t)}).Open(key, b, FieldRequestBody, ct); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("an unauthenticated row opened under an authenticating reader: %v", err)
	}
	// And the reverse: an authenticated row does not open without the key.
	ae := Envelope{AuthKey: testAuthKey(t)}
	ct, _ = ae.Seal(key, b, FieldRequestBody, []byte("x"))
	if _, err := (Envelope{}).Open(key, b, FieldRequestBody, ct); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("an authenticated row opened without its key: %v", err)
	}
}

// The two modes must derive DIFFERENT field keys even for an auth key an
// attacker might guess (all zeros), so the modes are domain-separated rather
// than merely salted.
func TestAuthKey_ModesAreDomainSeparated(t *testing.T) {
	key, b := testLeafKey(t), testBinding()
	plain, err := deriveFieldKey(key, nil, b, FieldRequestBody)
	if err != nil {
		t.Fatal(err)
	}
	authed, err := deriveFieldKey(key, make([]byte, AuthKeySize), b, FieldRequestBody)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(plain, authed) {
		t.Fatal("authenticated and unauthenticated modes derived the same field key")
	}
}

func TestAuthKey_WrongSizeIsAConfigurationError(t *testing.T) {
	key, b := testLeafKey(t), testBinding()
	e := Envelope{AuthKey: []byte("short")}
	if _, err := e.Seal(key, b, FieldRequestBody, []byte("x")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Seal: want ErrInvalidConfig, got %v", err)
	}
	if _, err := e.Open(key, b, FieldRequestBody, make([]byte, 64)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Open: want ErrInvalidConfig, got %v", err)
	}
}

// ─── What Seal accepts, Open returns ────────────────────────────────────────

func TestSeal_RefusesPlaintextOverTheCap(t *testing.T) {
	e := Envelope{MaxPlaintext: 4096}
	key, b := testLeafKey(t), testBinding()
	if _, err := e.Seal(key, b, FieldRequestBody, make([]byte, 4097)); !errors.Is(err, ErrPlaintextTooLarge) {
		t.Fatalf("want ErrPlaintextTooLarge, got %v", err)
	}
	// Exactly at the cap is fine and round-trips.
	pt := make([]byte, 4096)
	rand.Read(pt)
	ct, err := e.Seal(key, b, FieldRequestBody, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Open(key, b, FieldRequestBody, ct)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("at-cap body did not round-trip: %v", err)
	}
}

func TestSeal_DefaultCapIsEnforced(t *testing.T) {
	key, b := testLeafKey(t), testBinding()
	if _, err := (Envelope{}).Seal(key, b, FieldRequestBody, make([]byte, DefaultMaxPlaintext+1)); !errors.Is(err, ErrPlaintextTooLarge) {
		t.Fatalf("want ErrPlaintextTooLarge above the default cap, got %v", err)
	}
}

// A cap above what the decoder will ever allocate used to be accepted and
// silently lowered on read, so bodies between the two sealed fine and never
// opened again.
func TestEnvelope_CapAboveTheCeilingIsAConfigurationError(t *testing.T) {
	e := Envelope{MaxPlaintext: MaxPlaintextCeiling + 1}
	key, b := testLeafKey(t), testBinding()
	if _, err := e.Seal(key, b, FieldRequestBody, []byte("x")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Seal: want ErrInvalidConfig, got %v", err)
	}
	if _, err := e.Open(key, b, FieldRequestBody, make([]byte, 64)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Open: want ErrInvalidConfig, got %v", err)
	}
}

func TestSealOpen_RoundTripsAtTheCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 2 x 16 MiB")
	}
	e := Envelope{MaxPlaintext: MaxPlaintextCeiling}
	key, b := testLeafKey(t), testBinding()
	pt := make([]byte, MaxPlaintextCeiling)
	rand.Read(pt) // incompressible: the worst case for the decoder
	ct, err := e.Seal(key, b, FieldRequestBody, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Open(key, b, FieldRequestBody, ct)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("a body at the ceiling did not round-trip: %v", err)
	}
}

// ─── The two errors ─────────────────────────────────────────────────────────

// Every record carries its own sealed leaf, so a row with no blob will not
// acquire one by waiting. Calling it "unavailable" tells the reader to retry
// forever.
func TestOpenLeaf_MissingBlobIsUndecryptableNotRetryable(t *testing.T) {
	kr, _ := newTestKeyring(t)
	for name, sl := range map[string]SealedLeaf{
		"no blob":    {LeafID: "x"},
		"no leaf id": {Blob: []byte{1, 2, 3}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := kr.OpenLeaf(context.Background(), sl)
			if !errors.Is(err, ErrUndecryptable) || errors.Is(err, ErrKeyUnavailable) {
				t.Fatalf("want ErrUndecryptable only, got %v", err)
			}
		})
	}
}

// A cancelled or expired context is the one thing a retry does fix. It must
// still be recognisable as the context error for callers that check that.
func TestOpenLeaf_CancelledContextIsUnavailable(t *testing.T) {
	kr, pub := newTestKeyring(t)
	s, _ := NewLeafSealer(pub)
	_, sl, _ := s.NewLeaf("l")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := kr.OpenLeaf(ctx, sl)
	if !errors.Is(err, ErrKeyUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("want ErrKeyUnavailable wrapping context.Canceled, got %v", err)
	}
}

// Anyone with the public key can wrap a leaf "key" of any length. OpenLeaf
// must not hand that to a caller as if it were a key.
func TestOpenLeaf_RefusesAWrappedKeyOfTheWrongLength(t *testing.T) {
	kr, _ := newTestKeyring(t)
	for _, n := range []int{0, 5, LeafKeySize - 1, LeafKeySize + 1, 1024} {
		sl := sealArbitraryLeaf(t, kr.CapturePublicKey(), kr.KemKeyID(), "l", make([]byte, n))
		if k, err := kr.OpenLeaf(context.Background(), sl); !errors.Is(err, ErrUndecryptable) {
			t.Fatalf("%d-byte wrapped key: want ErrUndecryptable, got %d bytes, %v", n, len(k), err)
		}
	}
}

// Open is fed whatever a keyring returned, so a wrong-length key is a row
// that will not open — not an error outside the declared set.
func TestOpen_WrongKeySizeIsUndecryptable(t *testing.T) {
	if _, err := (Envelope{}).Open([]byte("short"), testBinding(), FieldRequestBody, make([]byte, 64)); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable, got %v", err)
	}
}

// ─── Rotation of rows that predate generation stamps ────────────────────────

func TestRotation_UnstampedRowFromARetiredGenerationStillOpens(t *testing.T) {
	oldSeed, newSeed := randomSeed(t), randomSeed(t)
	oldKR, err := NewLocalKeyringMulti([][]byte{oldSeed})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := NewLeafSealer(oldKR.CapturePublicKey())
	want, sl, _ := s.NewLeaf("legacy")
	sl.KemKeyID = "" // written before rows carried a generation

	rotated, err := NewLocalKeyringMulti([][]byte{newSeed, oldSeed})
	if err != nil {
		t.Fatal(err)
	}
	got, err := rotated.OpenLeaf(context.Background(), sl)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("unstamped row from a retired generation: %v", err)
	}
	// A second open is answered from the cache and must agree.
	got, err = rotated.OpenLeaf(context.Background(), sl)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("cached reopen: %v", err)
	}
}

func TestRotation_UnstampedRowNoGenerationOpensIsUndecryptable(t *testing.T) {
	stranger, _ := NewLocalKeyring(nil)
	s, _ := NewLeafSealer(stranger.CapturePublicKey())
	_, sl, _ := s.NewLeaf("l")
	sl.KemKeyID = ""
	kr, _ := NewLocalKeyringMulti([][]byte{randomSeed(t), randomSeed(t)})
	if _, err := kr.OpenLeaf(context.Background(), sl); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable, got %v", err)
	}
}

func randomSeed(t *testing.T) []byte {
	t.Helper()
	s, err := GenerateCaptureSeed()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// sealArbitraryLeaf wraps any byte string as a "leaf key", the way anyone
// holding the public key can.
func sealArbitraryLeaf(t *testing.T, pub PublicKeyBytes, kemKeyID, leafID string, key []byte) SealedLeaf {
	t.Helper()
	pk, err := captureKEM().NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), leafInfo(leafID), key)
	if err != nil {
		t.Fatal(err)
	}
	return SealedLeaf{LeafID: leafID, KemKeyID: kemKeyID, Blob: blob}
}
