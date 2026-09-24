package scuttle

import (
	"bytes"
	"context"
	"crypto/hkdf"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// Tests for the findings of the independent review. Each failed against the
// code as it stood.

// ─── F5: an all-zero leaf key is the historical bug's exact shape ───────────
//
// ATTACK.md claim 1 recounts fields sealed under a 32-byte all-zero key. The
// length check could not see it; this refuses it at every entry point.

func TestSeal_RefusesAnAllZeroLeafKey(t *testing.T) {
	_, err := (Envelope{}).Seal(make([]byte, LeafKeySize), testBinding(), FieldRequestBody, []byte("x"))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestSeal_WrongLengthKeyIsADeclaredError(t *testing.T) {
	_, err := (Envelope{}).Seal([]byte("short"), testBinding(), FieldRequestBody, []byte("x"))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestOpen_RefusesAnAllZeroLeafKey(t *testing.T) {
	b := testBinding()
	zero := make([]byte, LeafKeySize)
	// Built by hand: deriveFieldKey itself now refuses this key.
	fk, _ := hkdf.Expand(sha256.New, zero, string(b.aad(false, FieldRequestBody)), 32)
	gcm, _ := newGCM(fk)
	nonce := make([]byte, nonceSize)
	ct := gcm.Seal(nonce, nonce, zstdEnc.EncodeAll([]byte("x"), nil), b.aad(false, FieldRequestBody))
	if _, err := (Envelope{}).Open(make([]byte, LeafKeySize), b, FieldRequestBody, ct); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable, got %v", err)
	}
}

func TestOpenLeaf_RefusesAWrappedAllZeroKey(t *testing.T) {
	kr, _ := newTestKeyring(t)
	sl := sealArbitraryLeaf(t, kr.CapturePublicKey(), kr.KemKeyID(), "l", make([]byte, LeafKeySize))
	if _, err := kr.OpenLeaf(context.Background(), sl); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable, got %v", err)
	}
}

// ─── F2: Open's allocation is bounded by the envelope's cap ─────────────────
//
// The decoder used to be bounded only by MaxPlaintextCeiling (16 MiB), and the
// cap was checked after DecodeAll — so a tiny row cost the reader 16 MiB
// whatever cap it had asked for.

func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// streamedFrame compresses p without a frame content size, the shape a
// hostile writer would use to get past a header check.
func streamedFrame(t *testing.T, p []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(p); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sealPacked(t *testing.T, leafKey []byte, b Binding, field string, packed []byte) []byte {
	t.Helper()
	key, err := deriveFieldKey(leafKey, nil, b, field)
	if err != nil {
		t.Fatal(err)
	}
	gcm, _ := newGCM(key)
	nonce := make([]byte, nonceSize)
	return gcm.Seal(nonce, nonce, packed, b.aad(false, field))
}

func TestOpen_AllocationIsBoundedByTheEnvelopesCap(t *testing.T) {
	const capBytes = 64 << 10
	const budget = 4 << 20 // generous overhead, far below the 15 MiB bomb
	key, b := testLeafKey(t), testBinding()
	bomb := make([]byte, 15<<20)
	for name, packed := range map[string][]byte{
		"single frame with content size":  zstdEnc.EncodeAll(bomb, nil),
		"streamed frame, no content size": streamedFrame(t, bomb),
		"valid frame then a bomb frame":   append(zstdEnc.EncodeAll([]byte("ok"), nil), zstdEnc.EncodeAll(bomb, nil)...),
	} {
		t.Run(name, func(t *testing.T) {
			ct := sealPacked(t, key, b, FieldRequestBody, packed)
			env := Envelope{MaxPlaintext: capBytes}
			var err error
			n := allocatedBy(func() { _, err = env.Open(key, b, FieldRequestBody, ct) })
			if !errors.Is(err, ErrUndecryptable) {
				t.Fatalf("want ErrUndecryptable, got %v", err)
			}
			if n > budget {
				t.Fatalf("Open allocated %d bytes to refuse a row under a %d-byte cap", n, capBytes)
			}
		})
	}
}

// ─── CI fuzz commands target one package ────────────────────────────────────
//
// `go test -fuzz` refuses more than one package. Once cmd/scuttle-keygen made
// the module two packages, `-fuzz ... ./...` failed on every run, and the test
// that checked the target LISTS could not see it.
func TestCI_FuzzCommandsTargetTheRootPackageOnly(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	lines := 0
	for _, l := range strings.Split(ci, "\n") {
		if !strings.Contains(l, "-fuzz=") {
			continue
		}
		lines++
		if !strings.HasSuffix(strings.TrimSpace(l), " .") {
			t.Errorf("fuzz command must end with the single package \".\": %s", strings.TrimSpace(l))
		}
	}
	if lines < 2 {
		t.Fatalf("found %d fuzz commands in ci.yml; the scan is broken", lines)
	}
}

// ─── Configuration mistakes are ErrInvalidConfig, everywhere ────────────────

func TestConstructors_ReportConfigurationMistakesAsErrInvalidConfig(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, CaptureSeedSize)
	kr, _ := NewLocalKeyring(seed)
	s, _ := NewLeafSealer(kr.CapturePublicKey())
	cases := map[string]func() error{
		"keyring: no seeds":        func() error { _, err := NewLocalKeyringMulti(nil); return err },
		"keyring: short seed":      func() error { _, err := NewLocalKeyringMulti([][]byte{{1, 2, 3}}); return err },
		"keyring: duplicate seeds": func() error { _, err := NewLocalKeyringMulti([][]byte{seed, seed}); return err },
		"keyring: nil seed":        func() error { _, err := NewLocalKeyring(nil); return err },
		"sealer: bad public key":   func() error { _, err := NewLeafSealer(PublicKeyBytes{1, 2, 3}); return err },
		"sealer: empty leaf id":    func() error { _, _, err := s.NewLeaf(""); return err },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if err := f(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("want ErrInvalidConfig, got %v", err)
			}
		})
	}
}

// NewEphemeralKeyring() used to mint a fresh random key. A reader whose seed
// variable was unset therefore started "successfully" and reported every row
// as undecryptable. A throwaway key must be asked for by name.
func TestNewEphemeralKeyring_IsTheOnlyWayToGetARandomKey(t *testing.T) {
	a, err := NewEphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewEphemeralKeyring()
	if bytes.Equal(a.CapturePublicKey(), b.CapturePublicKey()) {
		t.Fatal("two ephemeral keyrings share a key")
	}
	if _, err := NewLocalKeyring([]byte{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty seed: want ErrInvalidConfig, got %v", err)
	}
}

// The per-cap decoder limit must never refuse a row Seal wrote. zstd frames
// declare a window up to twice the body size for small bodies, so every cap
// is checked at and just below its own size, compressible and not.
func TestSealOpen_RoundTripsAtEveryCapBoundary(t *testing.T) {
	caps := []int{1, 2, 100, 511, 512, 513, 1023, 1024, 1025, 4096, 65535, 65536, 65537, 1 << 20}
	if !testing.Short() {
		caps = append(caps, 8<<20-1, 8<<20, 8<<20+1, 12<<20, MaxPlaintextCeiling)
	}
	key, b := testLeafKey(t), testBinding()
	for _, c := range caps {
		for _, raw := range []bool{false, true} {
			env := Envelope{MaxPlaintext: c, DisableCompression: raw}
			for _, n := range []int{c, c - 1, c / 2} {
				if n < 0 {
					continue
				}
				random := make([]byte, n)
				crand.Read(random)
				for _, pt := range [][]byte{random, make([]byte, n)} {
					ct, err := env.Seal(key, b, FieldRequestBody, pt)
					if err != nil {
						t.Fatalf("cap %d, %d bytes: Seal: %v", c, n, err)
					}
					got, err := env.Open(key, b, FieldRequestBody, ct)
					if err != nil || !bytes.Equal(got, pt) {
						t.Fatalf("cap %d, %d bytes: sealed but did not open: %v", c, n, err)
					}
				}
			}
		}
	}
}

func TestDecoderLimit_IsAPowerOfTwoCoveringTwiceTheCap(t *testing.T) {
	seen := map[int]bool{}
	for c := 1; c <= MaxPlaintextCeiling; c = c*3/2 + 1 {
		l := decoderLimit(c)
		seen[l] = true
		if l&(l-1) != 0 || l > MaxPlaintextCeiling || (l < 2*c && l != MaxPlaintextCeiling) {
			t.Fatalf("decoderLimit(%d) = %d", c, l)
		}
	}
	if len(seen) > 9 {
		t.Fatalf("%d distinct decoder limits; the shared-decoder set must stay small", len(seen))
	}
}

// ─── Implementation review: smaller findings ────────────────────────────────

// The cache-HIT path must also hand out a copy. Only the miss path was tested,
// so `return cached, nil` passed the whole suite.
func TestOpenLeaf_CacheHitReturnsACopy(t *testing.T) {
	kr, pub := newTestKeyring(t)
	s, _ := NewLeafSealer(pub)
	want, sl, _ := s.NewLeaf("l")
	ctx := context.Background()
	if _, err := kr.OpenLeaf(ctx, sl); err != nil { // miss: primes the cache
		t.Fatal(err)
	}
	hit, err := kr.OpenLeaf(ctx, sl) // hit
	if err != nil {
		t.Fatal(err)
	}
	clear(hit) // the caller is entitled to zeroize what it gets
	again, err := kr.OpenLeaf(ctx, sl)
	if err != nil || !bytes.Equal(again, want) {
		t.Fatalf("a caller zeroing a cache hit destroyed the cached key: %x", again)
	}
}

func TestEnvelope_AllZeroAuthKeyIsAConfigurationError(t *testing.T) {
	e := Envelope{AuthKey: make([]byte, AuthKeySize)}
	if _, err := e.Seal(testLeafKey(t), testBinding(), FieldRequestBody, []byte("x")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestEnvelope_NegativeCapIsAConfigurationError(t *testing.T) {
	e := Envelope{MaxPlaintext: -1}
	if _, err := e.Seal(testLeafKey(t), testBinding(), FieldRequestBody, []byte("x")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

// A field name is part of the binding; an empty one is a caller bug.
func TestSeal_RefusesAnEmptyFieldName(t *testing.T) {
	if _, err := (Envelope{}).Seal(testLeafKey(t), testBinding(), "", []byte("x")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

// A public key that parses but cannot be sealed to (an all-zero X25519 half is
// a low-order point) must fail at load, not on every later write.
func TestPublicKey_ThatCannotBeSealedToIsRefusedAtLoad(t *testing.T) {
	bad := make([]byte, 1216)
	if _, err := NewLeafSealer(bad); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewLeafSealer: want ErrInvalidConfig, got %v", err)
	}
	if _, err := ParsePublicKey(strings.Repeat("00", 1216)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("ParsePublicKey: want ErrInvalidConfig, got %v", err)
	}
}

// Row contents are reflected into error strings; a hostile row must not be
// able to make them arbitrarily large (they end up in logs).
func TestOpenLeaf_ErrorsDoNotReflectUnboundedRowContents(t *testing.T) {
	kr, _ := newTestKeyring(t)
	huge := strings.Repeat("\x00", 1<<20)
	for name, sl := range map[string]SealedLeaf{
		"kem key id": {LeafID: "l", KemKeyID: huge, Blob: []byte{1}},
		"leaf id":    {LeafID: huge, Blob: []byte{1}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := kr.OpenLeaf(context.Background(), sl)
			if !errors.Is(err, ErrUndecryptable) {
				t.Fatalf("want ErrUndecryptable, got %v", err)
			}
			if len(err.Error()) > 512 {
				t.Fatalf("error message is %d bytes", len(err.Error()))
			}
		})
	}
}

// Leaf ids are bounded: they go into HPKE's info, the cache key and every
// error, and nothing honest needs a long one.
func TestLeafID_IsBounded(t *testing.T) {
	kr, pub := newTestKeyring(t)
	s, _ := NewLeafSealer(pub)
	if _, _, err := s.NewLeaf(strings.Repeat("x", MaxLeafIDLength)); err != nil {
		t.Fatalf("a %d-byte leaf id must be accepted: %v", MaxLeafIDLength, err)
	}
	if _, _, err := s.NewLeaf(strings.Repeat("x", MaxLeafIDLength+1)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewLeaf: want ErrInvalidConfig, got %v", err)
	}
	sl := SealedLeaf{LeafID: strings.Repeat("x", MaxLeafIDLength+1), KemKeyID: kr.KemKeyID(), Blob: []byte{1}}
	if _, err := kr.OpenLeaf(context.Background(), sl); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("OpenLeaf: want ErrUndecryptable, got %v", err)
	}
}

// Once every row carries its generation, the try-every-generation fallback
// only serves hostile rows (N decapsulations each). It can be switched off.
func TestKeyring_UnstampedFallbackCanBeDisabled(t *testing.T) {
	seed := randomSeed(t)
	old, _ := NewLocalKeyringMulti([][]byte{seed})
	s, _ := NewLeafSealer(old.CapturePublicKey())
	_, sl, _ := s.NewLeaf("l")
	sl.KemKeyID = ""
	strict, err := NewLocalKeyringMulti([][]byte{randomSeed(t), seed}, RequireGenerationStamp())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.OpenLeaf(context.Background(), sl); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("unstamped row under RequireGenerationStamp: want ErrUndecryptable, got %v", err)
	}
	sl.KemKeyID = old.KemKeyID()
	if _, err := strict.OpenLeaf(context.Background(), sl); err != nil {
		t.Fatalf("stamped row: %v", err)
	}
}

// A full cache sheds part of itself, not everything: an attacker who can mint
// valid leaves should not be able to empty it with one sweep.
func TestCache_EvictsPartiallyWhenFull(t *testing.T) {
	kr, pub := newTestKeyring(t)
	s, _ := NewLeafSealer(pub)
	for i := 0; i < maxCachedLeaves+1; i++ {
		_, sl, _ := s.NewLeaf("l")
		if _, err := kr.OpenLeaf(context.Background(), sl); err != nil {
			t.Fatal(err)
		}
	}
	if n := kr.CachedLeaves(); n < maxCachedLeaves/2 {
		t.Fatalf("cache dropped to %d entries when it filled; want at least %d kept", n, maxCachedLeaves/2)
	}
}

// ─── F1: the AuthKey cutover ────────────────────────────────────────────────
//
// The documented cutover — "choose the envelope from Binding.SchemaVersion" —
// re-opened the forgery AuthKey closes: schema_version is a column the forger
// writes too. The sound procedure re-seals every existing row once and then
// reads with ONE authenticated envelope. This is that procedure, end to end.

func TestCutover_ResealThenReadAuthenticatedOnly(t *testing.T) {
	kr, pub := newTestKeyring(t)
	ctx := context.Background()
	legacy, authed := Envelope{}, Envelope{AuthKey: testAuthKey(t)}
	s, _ := NewLeafSealer(pub)

	type row struct {
		sl   SealedLeaf
		b    Binding
		blob []byte
		pt   string
	}
	var rows []row
	for i, pt := range []string{"alpha", "beta", ""} {
		lk, sl, _ := s.NewLeaf("leaf")
		b := Binding{SchemaVersion: 1, LeafID: sl.LeafID, WorkspaceID: 42, UserID: 7, RequestID: string(rune('a' + i))}
		rows = append(rows, row{sl, b, mustSeal(t, legacy, lk, b, []byte(pt)), pt})
	}

	// Migration: open each row with the legacy envelope, re-seal it in place
	// (same leaf, same binding) with the authenticated one.
	for i := range rows {
		k, err := kr.OpenLeaf(ctx, rows[i].sl)
		if err != nil {
			t.Fatal(err)
		}
		rows[i].blob, err = Reseal(k, rows[i].b, FieldRequestBody, rows[i].blob, legacy, authed)
		if err != nil {
			t.Fatal(err)
		}
	}

	// After: one reader, authenticated only. Every migrated row opens...
	for _, r := range rows {
		k, _ := kr.OpenLeaf(ctx, r.sl)
		got, err := authed.Open(k, r.b, FieldRequestBody, r.blob)
		if err != nil || string(got) != r.pt {
			t.Fatalf("migrated row: %q, %v", got, err)
		}
	}
	// ...and a forgery in the legacy mode, even one claiming the old schema
	// version, does not.
	fb := Binding{SchemaVersion: 1, LeafID: "leaf", WorkspaceID: 42, UserID: 7, RequestID: "forged"}
	fsl, fct := forgeRow(t, pub, legacy, fb, FieldRequestBody, []byte("attacker text"))
	k, _ := kr.OpenLeaf(ctx, fsl)
	if pt, err := authed.Open(k, fb, FieldRequestBody, fct); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("a legacy-mode forgery opened after the cutover: %q, %v", pt, err)
	}
}

// Choosing the envelope per row from a stored value is the defect the cutover
// guidance used to recommend. Pinned so the docs can never recommend it again
// without this test being deleted first.
func TestCutover_ChoosingTheEnvelopeFromAStoredColumnAcceptsForgeries(t *testing.T) {
	kr, pub := newTestKeyring(t)
	authed := Envelope{AuthKey: testAuthKey(t)}
	readerFor := func(b Binding) Envelope {
		if b.SchemaVersion >= 2 {
			return authed
		}
		return Envelope{}
	}
	fb := Binding{SchemaVersion: 1, LeafID: "leaf", WorkspaceID: 42, UserID: 7, RequestID: "forged"}
	fsl, fct := forgeRow(t, pub, Envelope{}, fb, FieldRequestBody, []byte("attacker text"))
	k, _ := kr.OpenLeaf(context.Background(), fsl)
	if _, err := readerFor(fb).Open(k, fb, FieldRequestBody, fct); err != nil {
		t.Fatalf("expected the unsound per-row choice to accept the forgery (that is the point): %v", err)
	}
}

func TestReseal_RotatesTheAuthKey(t *testing.T) {
	key, b := testLeafKey(t), testBinding()
	oldEnv, newEnv := Envelope{AuthKey: testAuthKey(t)}, Envelope{AuthKey: testAuthKey(t)}
	ct := mustSeal(t, oldEnv, key, b, []byte("x"))
	ct2, err := Reseal(key, b, FieldRequestBody, ct, oldEnv, newEnv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldEnv.Open(key, b, FieldRequestBody, ct2); !errors.Is(err, ErrUndecryptable) {
		t.Fatal("the old auth key still opens a re-sealed row")
	}
	if got, err := newEnv.Open(key, b, FieldRequestBody, ct2); err != nil || string(got) != "x" {
		t.Fatalf("%q, %v", got, err)
	}
	if _, err := Reseal(key, b, FieldRequestBody, []byte("junk"), oldEnv, newEnv); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("resealing garbage: want ErrUndecryptable, got %v", err)
	}
}

// ─── F3: compression is a length oracle within one field ────────────────────
//
// When a field holds a secret next to text an attacker influences, the
// compressed length reveals whether the attacker's guess matches the secret
// (CRIME). Compression is on by default for storage; DisableCompression
// removes the oracle.

func crimePair() (right, wrong []byte) {
	return []byte(`{"system":"api_key=sk-live-7f3a9c2e1b","user":"api_key=sk-live-7f3a9c2e1b"}`),
		[]byte(`{"system":"api_key=sk-live-7f3a9c2e1b","user":"api_key=qz-bxnd-4k8w0p5r6t"}`)
}

func TestCompression_IsALengthOracleWithinAField(t *testing.T) {
	key, b := testLeafKey(t), testBinding()
	right, wrong := crimePair()
	a := mustSeal(t, Envelope{}, key, b, right)
	c := mustSeal(t, Envelope{}, key, b, wrong)
	if len(a) >= len(c) {
		t.Fatalf("expected the correct guess to compress smaller (%d vs %d); if this changed, update the docs", len(a), len(c))
	}
}

func TestDisableCompression_RemovesTheOracle(t *testing.T) {
	key, b := testLeafKey(t), testBinding()
	env := Envelope{DisableCompression: true}
	right, wrong := crimePair()
	if a, c := mustSeal(t, env, key, b, right), mustSeal(t, env, key, b, wrong); len(a) != len(c) {
		t.Fatalf("ciphertext length depends on content: %d vs %d", len(a), len(c))
	}
	random := make([]byte, 5000)
	crand.Read(random)
	if a, c := mustSeal(t, env, key, b, random), mustSeal(t, env, key, b, make([]byte, 5000)); len(a) != len(c) {
		t.Fatalf("ciphertext length depends on content: %d vs %d", len(a), len(c))
	}
}

// Readers need no setting: an uncompressed row is still a valid zstd frame.
func TestDisableCompression_RowsOpenWithAnyReader(t *testing.T) {
	key, b := testLeafKey(t), testBinding()
	for _, n := range []int{0, 1, 1000, 128 << 10, 128<<10 + 1, 300 << 10, DefaultMaxPlaintext} {
		pt := make([]byte, n)
		crand.Read(pt)
		ct := mustSeal(t, Envelope{DisableCompression: true}, key, b, pt)
		for _, reader := range []Envelope{{}, {DisableCompression: true}} {
			got, err := reader.Open(key, b, FieldRequestBody, ct)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("%d bytes: %v", n, err)
			}
		}
	}
}

// ─── Verification pass: frame floods and oversize blobs ─────────────────────
//
// zstd's DecodeAll reallocates the output for every frame that declares a
// content size, copying everything decoded so far. A row of many small frames
// therefore cost memory quadratic in the cap: 2 GB for a 22 KB row under a
// 1 MiB cap. The per-cap decoder limit bounded the RESULT, not the copying.

// rleFrame is a single-segment frame of n repeated bytes (256 <= n < 65792).
func rleFrame(n int) []byte {
	out := []byte{0x28, 0xB5, 0x2F, 0xFD, 0x60}
	out = binary.LittleEndian.AppendUint16(out, uint16(n-256))
	hdr := uint32(n)<<3 | 1<<1 | 1 // RLE, last block
	return append(out, byte(hdr), byte(hdr>>8), byte(hdr>>16), 'A')
}

func warmOpen(t *testing.T, env Envelope, key []byte, b Binding) {
	t.Helper()
	if _, err := env.Open(key, b, FieldRequestBody, mustSeal(t, env, key, b, []byte("warm"))); err != nil {
		t.Fatal(err)
	}
}

func TestOpen_FrameFloodIsBoundedByTheCap(t *testing.T) {
	const capBytes = 1 << 20
	key, b := testLeafKey(t), testBinding()
	env := Envelope{MaxPlaintext: capBytes}
	warmOpen(t, env, key, b)
	var toLimit, toCap []byte
	for i := 0; i*1024 < decoderLimit(capBytes); i++ {
		toLimit = append(toLimit, rleFrame(1024)...)
	}
	for i := 0; (i+1)*1024 <= capBytes; i++ {
		toCap = append(toCap, rleFrame(1024)...)
	}
	for name, tc := range map[string]struct {
		packed []byte
		opens  bool
	}{
		"frames past the cap":  {toLimit, false},
		"frames up to the cap": {toCap, true},
	} {
		t.Run(name, func(t *testing.T) {
			ct := sealPacked(t, key, b, FieldRequestBody, tc.packed)
			var err error
			n := allocatedBy(func() { _, err = env.Open(key, b, FieldRequestBody, ct) })
			if tc.opens != (err == nil) {
				t.Fatalf("opens=%v, err=%v", tc.opens, err)
			}
			if n > 4*capBytes {
				t.Fatalf("Open allocated %d bytes (%.0fx the cap)", n, float64(n)/capBytes)
			}
		})
	}
}

// A blob longer than any field Seal could write under this cap is refused
// before it is decrypted — decrypting it allocates its whole length.
func TestOpen_RefusesABlobLongerThanTheCapAllows(t *testing.T) {
	key, b := testLeafKey(t), testBinding()
	env := Envelope{MaxPlaintext: 1024}
	warmOpen(t, env, key, b)
	skippable := append([]byte{0x50, 0x2A, 0x4D, 0x18}, binary.LittleEndian.AppendUint32(nil, 1<<20)...)
	skippable = append(skippable, make([]byte, 1<<20)...)
	ct := sealPacked(t, key, b, FieldRequestBody, append(skippable, zstdEnc.EncodeAll([]byte("ok"), nil)...))
	var err error
	n := allocatedBy(func() { _, err = env.Open(key, b, FieldRequestBody, ct) })
	if !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable, got %v", err)
	}
	if n > 64<<10 {
		t.Fatalf("refusing an oversize blob allocated %d bytes", n)
	}
}

// The fix must not make honest rows expensive: a small, highly compressible
// body under a large cap decodes without allocating anything like the cap.
func TestOpen_HonestCompressibleRowIsCheap(t *testing.T) {
	key, b := testLeafKey(t), testBinding()
	env := Envelope{MaxPlaintext: 16 << 20}
	warmOpen(t, env, key, b)
	pt := bytes.Repeat([]byte("abcdefgh"), 10<<10) // 80 KiB, compresses ~1000x
	ct := mustSeal(t, env, key, b, pt)
	var got []byte
	var err error
	n := allocatedBy(func() { got, err = env.Open(key, b, FieldRequestBody, ct) })
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatal(err)
	}
	if n > 1<<20 {
		t.Fatalf("an 80 KiB row under a 16 MiB cap allocated %d bytes", n)
	}
}

// Sealed leaves have one size; anything else is refused before hashing or
// decapsulating it.
func TestOpenLeaf_RefusesABlobOfTheWrongSize(t *testing.T) {
	kr, pub := newTestKeyring(t)
	s, _ := NewLeafSealer(pub)
	_, sl, _ := s.NewLeaf("l")
	for _, blob := range [][]byte{append(sl.Blob, 0), sl.Blob[:len(sl.Blob)-1], make([]byte, 1<<20)} {
		bad := sl
		bad.Blob = blob
		if _, err := kr.OpenLeaf(context.Background(), bad); !errors.Is(err, ErrUndecryptable) {
			t.Fatalf("%d-byte blob: want ErrUndecryptable, got %v", len(blob), err)
		}
	}
}

func TestNewLocalKeyringMulti_IgnoresANilOption(t *testing.T) {
	if _, err := NewLocalKeyringMulti([][]byte{randomSeed(t)}, nil); err != nil {
		t.Fatal(err)
	}
}
