package scuttle

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
)

func newTestKeyring(t *testing.T) (*LocalKeyring, PublicKeyBytes) {
	t.Helper()
	kr, err := NewLocalKeyring(nil)
	if err != nil {
		t.Fatal(err)
	}
	return kr, kr.CapturePublicKey()
}

func TestLeafEnvelope_RoundTripsThroughTheKeyring(t *testing.T) {
	kr, pub := newTestKeyring(t)
	sealer, err := NewLeafSealer(pub)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, sealed, err := sealer.NewLeaf("ws:42|u:7|2026-06-10")
	if err != nil {
		t.Fatal(err)
	}
	if len(leafKey) != LeafKeySize {
		t.Fatalf("leaf key is %d bytes", len(leafKey))
	}
	if bytes.Contains(sealed.Blob, leafKey) {
		t.Fatal("the leaf key is visible in its own sealed envelope")
	}
	got, err := kr.OpenLeaf(context.Background(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, leafKey) {
		t.Fatal("keyring returned a different leaf key than the relay sealed")
	}
}

// A2: the relay holds a public key. It must not be able to open anything.
func TestSealer_CannotOpenWhatItSealed(t *testing.T) {
	_, pub := newTestKeyring(t)
	sealer, err := NewLeafSealer(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, sealed, err := sealer.NewLeaf("leaf-1")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewLocalKeyring(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.OpenLeaf(context.Background(), sealed); err == nil {
		t.Fatal("a foreign keyring opened the envelope")
	}
}

// REGRESSION (review F3). The cache must hand back a COPY. The caller
// zeroizes what it receives, so returning the cached slice would let the
// first reader destroy the entry for everyone after it — silently, because a
// zeroed key still has the right length and derives a valid-looking field key.
func TestOpenLeaf_CacheSurvivesACallerThatZeroesItsKey(t *testing.T) {
	kr, pub := newTestKeyring(t)
	sealer, _ := NewLeafSealer(pub)
	want, sealed, _ := sealer.NewLeaf("leaf")
	ctx := context.Background()

	first, err := kr.OpenLeaf(ctx, sealed)
	if err != nil {
		t.Fatal(err)
	}
	for i := range first { // a caller doing exactly what the read path does
		first[i] = 0
	}
	second, err := kr.OpenLeaf(ctx, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, want) {
		t.Fatal("the cached leaf key was destroyed by the previous reader")
	}
}

// A restart, a second pod, and a cold cache are all the same thing now: the
// document carries its own sealed key, so any process with the capture
// private key can open it.
func TestOpenLeaf_WorksFromABlobAloneOnAFreshProcess(t *testing.T) {
	kr, _ := newTestKeyring(t)
	seed, err := kr.PrivateKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := NewLeafSealer(kr.CapturePublicKey())
	want, sealed, _ := sealer.NewLeaf("leaf")

	restarted, err := NewLocalKeyring(seed) // same capture key, no shared state
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.OpenLeaf(context.Background(), sealed)
	if err != nil {
		t.Fatalf("a restarted process could not open a stored leaf: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("wrong key after restart")
	}
}

func TestOpenLeaf_DamagedBlobIsUndecryptable(t *testing.T) {
	kr, pub := newTestKeyring(t)
	sealer, _ := NewLeafSealer(pub)
	_, sealed, _ := sealer.NewLeaf("leaf")
	sealed.Blob[len(sealed.Blob)-1] ^= 0xff
	_, err := kr.OpenLeaf(context.Background(), sealed)
	if !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable, got %v", err)
	}
}

// A blob cannot be re-filed under a different leaf id: the id is bound into
// the HPKE info, so the tag fails.
// The COLD-cache half of the re-filing check: nothing has been opened, so the
// refusal comes from hpke.Open itself. The warm half — the same row after its
// blob's key is already cached — lives in
// TestCache_KeyCoversEveryInputThatDeterminesTheValue, and is a separate test
// because a cache key that dropped the leaf id passed THIS one unchanged.
func TestOpenLeaf_RejectsARefiledBlob(t *testing.T) {
	kr, pub := newTestKeyring(t)
	sealer, _ := NewLeafSealer(pub)
	_, sealed, _ := sealer.NewLeaf("leaf-a")
	sealed.LeafID = "leaf-b"
	if _, err := kr.OpenLeaf(context.Background(), sealed); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("a blob was re-filed under another id: %v", err)
	}
}

// kem_key_id lets a deployment rotate the capture key without stranding
// blobs sealed under the previous one (R5).
func TestSealedLeaf_CarriesTheKeyGeneration(t *testing.T) {
	kr, pub := newTestKeyring(t)
	sealer, _ := NewLeafSealer(pub)
	_, sealed, _ := sealer.NewLeaf("leaf")
	if sealed.KemKeyID == "" {
		t.Fatal("sealed leaf carries no kem_key_id")
	}
	if sealed.KemKeyID != kr.KemKeyID() {
		t.Fatalf("kem_key_id mismatch: sealed %q, keyring %q", sealed.KemKeyID, kr.KemKeyID())
	}
}

// Two pods sealing for the same (workspace, user, window) must not collide:
// each mints its own leaf id, and each row carries the blob that opens it.
func TestTwoSealersDoNotCollide(t *testing.T) {
	kr, pub := newTestKeyring(t)
	a, _ := NewLeafSealer(pub)
	b, _ := NewLeafSealer(pub)
	keyA, sealedA, _ := a.NewLeaf("ws:42|u:7|w1|podA")
	keyB, sealedB, _ := b.NewLeaf("ws:42|u:7|w1|podB")
	ctx := context.Background()

	gotA, err := kr.OpenLeaf(ctx, sealedA)
	if err != nil {
		t.Fatal(err)
	}
	gotB, err := kr.OpenLeaf(ctx, sealedB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, keyA) || !bytes.Equal(gotB, keyB) {
		t.Fatal("two sealers interfered with each other")
	}
}

func TestKeyring_IsConcurrencySafe(t *testing.T) {
	kr, pub := newTestKeyring(t)
	sealer, _ := NewLeafSealer(pub)
	_, sealed, _ := sealer.NewLeaf("shared-id")
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, err := kr.OpenLeaf(ctx, sealed)
			if err == nil {
				for j := range k { // every caller zeroizes, as the read path does
					k[j] = 0
				}
			}
		}()
	}
	wg.Wait()
	if _, err := kr.OpenLeaf(ctx, sealed); err != nil {
		t.Fatalf("the leaf must still open after concurrent readers: %v", err)
	}
}

func TestCache_IsBounded(t *testing.T) {
	kr, pub := newTestKeyring(t)
	sealer, _ := NewLeafSealer(pub)
	ctx := context.Background()
	for i := 0; i < maxCachedLeaves+50; i++ {
		_, sealed, err := sealer.NewLeaf("leaf-" + string(rune('a'+i%26)) + "-" + itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := kr.OpenLeaf(ctx, sealed); err != nil {
			t.Fatal(err)
		}
	}
	if n := kr.CachedLeaves(); n > maxCachedLeaves {
		t.Fatalf("cache grew past its bound: %d", n)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
