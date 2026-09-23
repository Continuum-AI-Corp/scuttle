package scuttle

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// Fuzz targets, written as a starting point for someone trying to break this.
//
// Each one asserts an INVARIANT rather than merely "does not panic". A crash
// is worth reporting, but the findings that matter here are the quiet ones: a
// blob that opens under a binding it was not sealed to, a decoder that
// allocates without bound, a tampered ciphertext that returns plaintext. Run
// them with:
//
//	go test -run=Fuzz -fuzz=FuzzOpenRejectsGarbage -fuzztime=10m
//
// and see ATTACK.md for the claims worth aiming at.

// fuzzLeafKey derives a deterministic 32-byte leaf key from fuzzer bytes, so
// the key is attacker-influenced without being attacker-length (Seal rejects
// a wrong-size key, which would make every case a trivial early return).
func fuzzLeafKey(b []byte) []byte {
	k := make([]byte, LeafKeySize)
	copy(k, b)
	if len(b) == 0 {
		k[0] = 1
	}
	return k
}

func fuzzBinding(schema, ws, uid int, epoch, leaf, req string) Binding {
	return Binding{
		SchemaVersion: schema,
		EpochID:       epoch,
		LeafID:        leaf,
		WorkspaceID:   ws,
		UserID:        uid,
		RequestID:     req,
	}
}

// FuzzOpenRejectsGarbage: Open must never return a plaintext for input it did
// not produce, and must never panic or allocate unboundedly on hostile bytes.
//
// This is the shape that matters because the database is untrusted: every
// byte Open sees can be chosen by whoever holds a database dump and can write it
// back.
func FuzzOpenRejectsGarbage(f *testing.F) {
	f.Add([]byte("k"), []byte("garbage"), "request_body")
	f.Add([]byte("k"), []byte{}, "request_body")
	f.Add([]byte("k"), bytes.Repeat([]byte{0xff}, 64), "response_body")

	env := Envelope{}
	f.Fuzz(func(t *testing.T, keyBytes, blob []byte, field string) {
		key := fuzzLeafKey(keyBytes)
		b := fuzzBinding(1, 7, 42, "e", "l", "r")

		pt, err := env.Open(key, b, field, blob)
		if err == nil {
			// Open succeeded on fuzzer-chosen bytes. That is only legitimate
			// if those bytes really are a valid sealing under this exact key,
			// binding and field — vanishingly unlikely, but re-sealing the
			// result must then reproduce something that opens identically.
			again, err2 := env.Open(key, b, field, blob)
			if err2 != nil || !bytes.Equal(pt, again) {
				t.Fatalf("Open is not deterministic on accepted input")
			}
			return
		}
		// Every rejection must be one of the two declared errors. An error
		// outside that set means a caller's errors.Is switch silently takes
		// no branch — which is how a decryption bug ends up reported to the
		// reader as "try again in a moment".
		if !errors.Is(err, ErrUndecryptable) && !errors.Is(err, ErrKeyUnavailable) {
			t.Fatalf("Open returned an unclassified error %v; callers switch on "+
				"ErrUndecryptable vs ErrKeyUnavailable and would take neither branch", err)
		}
		if pt != nil {
			t.Fatalf("Open returned %d plaintext bytes alongside an error", len(pt))
		}
	})
}

// FuzzRoundTripBindsEveryField: a blob sealed under one binding must not open
// under any DIFFERENT binding or field name.
//
// This is the anti-splice property, and it is the single most valuable thing
// to break. The AAD is length-prefixed precisely because plain concatenation
// lets (workspace 1, user 23) collide with (workspace 12, user 3) — if you
// find any two distinct bindings whose blobs are interchangeable, that is a
// cross-tenant read.
func FuzzRoundTripBindsEveryField(f *testing.F) {
	f.Add([]byte("seed"), []byte("payload"), 1, 1, 23, "e", "l", "r", "request_body")
	f.Add([]byte("seed"), []byte("payload"), 1, 12, 3, "e", "l", "r", "request_body")

	env := Envelope{}
	f.Fuzz(func(t *testing.T, keyBytes, payload []byte,
		schema, ws, uid int, epoch, leaf, req, field string) {
		if field == "" {
			return // Seal rejects an empty field name; not the property under test.
		}
		key := fuzzLeafKey(keyBytes)
		b := fuzzBinding(schema, ws, uid, epoch, leaf, req)

		blob, err := env.Seal(key, b, field, payload)
		if err != nil {
			return // oversize or otherwise refused; nothing sealed to attack
		}

		// It must open under its own binding.
		got, err := env.Open(key, b, field, blob)
		if err != nil {
			t.Fatalf("a blob this library just sealed will not open: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("round trip changed the payload")
		}

		// And must NOT open under any single-element mutation of it.
		for name, alt := range map[string]Binding{
			"schema":    fuzzBinding(schema+1, ws, uid, epoch, leaf, req),
			"workspace": fuzzBinding(schema, ws+1, uid, epoch, leaf, req),
			"user":      fuzzBinding(schema, ws, uid+1, epoch, leaf, req),
			"epoch":     fuzzBinding(schema, ws, uid, epoch+"x", leaf, req),
			"leaf":      fuzzBinding(schema, ws, uid, epoch, leaf+"x", req),
			"request":   fuzzBinding(schema, ws, uid, epoch, leaf, req+"x"),
		} {
			if _, err := env.Open(key, alt, field, blob); err == nil {
				t.Fatalf("blob opened under a different %s — the AAD does not bind it, "+
					"which is a cross-tenant splice", name)
			}
		}
		if _, err := env.Open(key, b, field+"x", blob); err == nil {
			t.Fatal("blob opened under a different field name")
		}

		// The classic ambiguity: (ws, uid) digits shifting across the
		// boundary. Only reachable when the decimal renderings concatenate
		// to the same string, which length-prefixing is meant to prevent.
		if ws >= 1 && uid >= 1 {
			shifted := fuzzBinding(schema, ws*10, uid, epoch, leaf, req)
			if _, err := env.Open(key, shifted, field, blob); err == nil {
				t.Fatal("blob opened under a digit-shifted workspace/user pair")
			}
		}
	})
}

// FuzzTamperIsAlwaysDetected: flipping any single byte of a valid blob must
// make it refuse to open. AES-GCM guarantees this; the target exists to catch
// a framing bug that lets a mutated byte fall outside the authenticated span.
func FuzzTamperIsAlwaysDetected(f *testing.F) {
	f.Add([]byte("seed"), []byte("some payload worth stealing"), 0)

	env := Envelope{}
	f.Fuzz(func(t *testing.T, keyBytes, payload []byte, pos int) {
		key := fuzzLeafKey(keyBytes)
		b := fuzzBinding(1, 7, 42, "e", "l", "r")
		blob, err := env.Seal(key, b, FieldRequestBody, payload)
		if err != nil || len(blob) == 0 {
			return
		}
		if pos < 0 {
			pos = -pos
		}
		i := pos % len(blob)

		tampered := append([]byte(nil), blob...)
		tampered[i] ^= 0x01

		if _, err := env.Open(key, b, FieldRequestBody, tampered); err == nil {
			t.Fatalf("a one-bit change at offset %d of %d still opened — that byte is "+
				"outside the authenticated span", i, len(blob))
		}
	})
}

// FuzzOpenLeafRejectsGarbage: the keyring's unwrap step on hostile bytes.
//
// SealedLeaf.Blob travels with the record, so it is attacker-controlled in
// exactly the same way. A panic here is a denial of service on the read path;
// a success is a forged leaf key.
func FuzzOpenLeafRejectsGarbage(f *testing.F) {
	f.Add([]byte("leaf-1"), []byte("garbage"), "kem-1")
	f.Add([]byte(""), []byte{}, "")

	kr, err := NewLocalKeyring(nil)
	if err != nil {
		f.Skipf("keyring unavailable: %v", err)
	}
	f.Fuzz(func(t *testing.T, leafID, blob []byte, kemKeyID string) {
		key, err := kr.OpenLeaf(context.Background(), SealedLeaf{
			LeafID:   string(leafID),
			KemKeyID: kemKeyID,
			Blob:     blob,
		})
		if err == nil {
			if len(key) != LeafKeySize {
				t.Fatalf("OpenLeaf accepted hostile bytes and returned a %d-byte key", len(key))
			}
			return
		}
		if !errors.Is(err, ErrUndecryptable) && !errors.Is(err, ErrKeyUnavailable) {
			t.Fatalf("OpenLeaf returned an unclassified error: %v", err)
		}
		if key != nil {
			t.Fatalf("OpenLeaf returned key material alongside an error")
		}
	})
}

// FuzzDecompressionIsBounded: a compression bomb must be REFUSED, not
// measured after the fact.
//
// The distinction is the whole point. A decoder that inflates first and
// checks the size afterwards has already allocated the memory an attacker
// asked for, so one crafted row is an OOM on the reader.
func FuzzDecompressionIsBounded(f *testing.F) {
	f.Add([]byte("seed"), 1024)

	f.Fuzz(func(t *testing.T, keyBytes []byte, limit int) {
		if limit < 1 || limit > 1<<20 {
			return
		}
		key := fuzzLeafKey(keyBytes)
		b := fuzzBinding(1, 7, 42, "e", "l", "r")

		// Seal a highly compressible payload larger than the OPEN side's cap.
		big := bytes.Repeat([]byte("A"), limit*4)
		sealer := Envelope{MaxPlaintext: limit * 8}
		blob, err := sealer.Seal(key, b, FieldRequestBody, big)
		if err != nil {
			return
		}

		// A reader with a smaller cap must refuse rather than inflate.
		reader := Envelope{MaxPlaintext: limit}
		pt, err := reader.Open(key, b, FieldRequestBody, blob)
		if err == nil {
			t.Fatalf("a %d-byte plaintext opened under a %d-byte cap", len(pt), limit)
		}
		if !errors.Is(err, ErrUndecryptable) {
			t.Fatalf("an over-cap payload must report ErrUndecryptable, got %v", err)
		}
	})
}

// FuzzRotationNeverServesTheWrongGeneration.
//
// The rotation code landed AFTER this harness was written, which only ever
// built a single-key keyring (NewLocalKeyring(nil)) — so the generation
// selector, the multi-key constructor and the cache key were the newest and
// least-attacked part of the library. This target aims at all three.
//
// The invariant: a leaf opened out of a keyring holding several generations
// must return the key that generation actually sealed — never another's, and
// never a cached entry belonging to a different (generation, leaf) pair.
func FuzzRotationNeverServesTheWrongGeneration(f *testing.F) {
	f.Add("leaf-1", "leaf-1", uint8(0), uint8(1))
	f.Add("ws:1|u:2|w:0", "ws:1|u:2|w:0", uint8(1), uint8(0)) // same id, both gens
	f.Add("a\x00b", "a", uint8(0), uint8(1))                  // separator games

	seedA := bytes.Repeat([]byte{0xA1}, CaptureSeedSize)
	seedB := bytes.Repeat([]byte{0xB2}, CaptureSeedSize)
	seedC := bytes.Repeat([]byte{0xC3}, CaptureSeedSize)
	seeds := [][]byte{seedA, seedB, seedC}

	kr, err := NewLocalKeyringMulti(seeds)
	if err != nil {
		f.Skipf("keyring: %v", err)
	}
	sealers := make([]*LeafSealer, len(seeds))
	for i, s := range seeds {
		one, err := NewLocalKeyring(s)
		if err != nil {
			f.Skipf("gen %d: %v", i, err)
		}
		sealers[i], err = NewLeafSealer(one.CapturePublicKey())
		if err != nil {
			f.Skipf("sealer %d: %v", i, err)
		}
	}

	f.Fuzz(func(t *testing.T, leafID1, leafID2 string, g1, g2 uint8) {
		if leafID1 == "" || leafID2 == "" {
			return // NewLeaf refuses an empty id; not the property under test
		}
		i1, i2 := int(g1)%len(sealers), int(g2)%len(sealers)

		key1, sealed1, err := sealers[i1].NewLeaf(leafID1)
		if err != nil {
			return
		}
		key2, sealed2, err := sealers[i2].NewLeaf(leafID2)
		if err != nil {
			return
		}

		ctx := context.Background()
		got1, err := kr.OpenLeaf(ctx, sealed1)
		if err != nil {
			t.Fatalf("a leaf this keyring's own generation sealed would not open: %v", err)
		}
		if !bytes.Equal(got1, key1) {
			t.Fatal("opened to the wrong leaf key")
		}
		got2, err := kr.OpenLeaf(ctx, sealed2)
		if err != nil {
			t.Fatalf("second leaf would not open: %v", err)
		}
		if !bytes.Equal(got2, key2) {
			t.Fatalf("leaf %q (gen %d) was served the wrong key after leaf %q (gen %d) — "+
				"a cache collision or a generation mix-up", leafID2, i2, leafID1, i1)
		}
	})
}

// FuzzMultiKeyringRejectsHostileSeedSets: the constructor on bad input. A
// keyring that comes up holding a key it should have refused is worse than a
// boot failure, because the failure is visible and this is not.
func FuzzMultiKeyringRejectsHostileSeedSets(f *testing.F) {
	f.Add([]byte{}, []byte{}, 0)
	f.Add(bytes.Repeat([]byte{1}, CaptureSeedSize), bytes.Repeat([]byte{1}, CaptureSeedSize), 2)

	f.Fuzz(func(t *testing.T, a, b []byte, n int) {
		if n < 0 {
			n = -n
		}
		n %= 4
		seeds := make([][]byte, 0, n)
		for i := 0; i < n; i++ {
			if i%2 == 0 {
				seeds = append(seeds, a)
			} else {
				seeds = append(seeds, b)
			}
		}
		kr, err := NewLocalKeyringMulti(seeds)
		if err != nil {
			if kr != nil {
				t.Fatal("returned a keyring alongside an error")
			}
			return
		}
		if len(seeds) == 0 {
			t.Fatal("accepted an empty seed set")
		}
		for i, s := range seeds {
			if len(s) != CaptureSeedSize {
				t.Fatalf("accepted seed %d of %d bytes", i, len(s))
			}
		}
		if len(seeds) > 1 && bytes.Equal(seeds[0], seeds[1]) {
			t.Fatal("accepted a repeated capture key; the rotation would rotate nothing")
		}
		if kr.Generations() != len(seeds) {
			t.Fatalf("holds %d generations for %d seeds", kr.Generations(), len(seeds))
		}
	})
}

// FuzzLeafCacheNeverCrossesRows: recombine the three fields of a stored row
// and demand the cache never answers a question it was not asked.
//
// The keyring reads SealedLeaf off a database row, so all three fields vary
// independently under an attacker who can write one — and the opened key is a
// function of all three (generation → private key, leaf id → HPKE info, blob →
// the ciphertext). Every cache key this package has shipped covered a strict
// subset, and each in turn served one row's key for another's:
//
//	leaf id only          → crossed generations
//	(generation, leaf id) → crossed blobs (FuzzRotationNeverServesTheWrongGeneration found it)
//	blob only             → crossed leaf ids
//
// The invariant, stated so it does not depend on which spelling is current:
// an OpenLeaf that succeeds returns the key that was sealed for exactly that
// (generation, leaf id, blob), and any recombination either opens to its own
// key or does not open at all. Priming matters — a cold keyring proves only
// that hpke.Open works.
func FuzzLeafCacheNeverCrossesRows(f *testing.F) {
	f.Add("leaf-1", "leaf-1", uint8(0), uint8(0), uint8(0), uint8(0))
	f.Add("ws:1|u:2|w:0", "ws:1|u:2|w:0", uint8(0), uint8(1), uint8(1), uint8(0))
	f.Add("a", "a\x00b", uint8(1), uint8(0), uint8(0), uint8(1))

	seeds := [][]byte{
		bytes.Repeat([]byte{0xA1}, CaptureSeedSize),
		bytes.Repeat([]byte{0xB2}, CaptureSeedSize),
	}
	kr, err := NewLocalKeyringMulti(seeds)
	if err != nil {
		f.Skipf("keyring: %v", err)
	}
	sealers := make([]*LeafSealer, len(seeds))
	for i, s := range seeds {
		one, err := NewLocalKeyring(s)
		if err != nil {
			f.Skipf("gen %d: %v", i, err)
		}
		if sealers[i], err = NewLeafSealer(one.CapturePublicKey()); err != nil {
			f.Skipf("sealer %d: %v", i, err)
		}
	}

	f.Fuzz(func(t *testing.T, idA, idB string, genA, genB, pickID, pickGen uint8) {
		if idA == "" || idB == "" {
			return // NewLeaf refuses an empty id
		}
		ia, ib := int(genA)%len(sealers), int(genB)%len(sealers)

		keyA, rowA, err := sealers[ia].NewLeaf(idA)
		if err != nil {
			return
		}
		keyB, rowB, err := sealers[ib].NewLeaf(idB)
		if err != nil {
			return
		}

		ctx := context.Background()
		// PRIME: both rows legitimately in the cache before anything is
		// recombined. Without this the cache is never consulted and the
		// property under test is never exercised.
		for _, row := range []struct {
			sealed SealedLeaf
			want   []byte
		}{{rowA, keyA}, {rowB, keyB}} {
			got, err := kr.OpenLeaf(ctx, row.sealed)
			if err != nil {
				t.Fatalf("a row this keyring sealed would not open: %v", err)
			}
			if !bytes.Equal(got, row.want) {
				t.Fatal("a legitimate row opened to the wrong key")
			}
		}

		// Now a row whose three fields come from wherever the fuzzer says.
		forged := SealedLeaf{
			LeafID:   []string{idA, idB}[int(pickID)%2],
			KemKeyID: []string{rowA.KemKeyID, rowB.KemKeyID}[int(pickGen)%2],
			Blob:     rowB.Blob,
		}
		got, err := kr.OpenLeaf(ctx, forged)
		if err != nil {
			return // refusing is always allowed
		}
		// It opened. Then it must be because the recombination happens to BE
		// rowB — same blob, and the leaf id and generation rowB was sealed
		// with — and the key must be rowB's.
		if forged.LeafID != rowB.LeafID || forged.KemKeyID != rowB.KemKeyID {
			t.Fatalf("row {id=%q gen=%q} opened using the blob sealed for "+
				"{id=%q gen=%q}: the cache answered without the HPKE bindings",
				forged.LeafID, forged.KemKeyID, rowB.LeafID, rowB.KemKeyID)
		}
		if !bytes.Equal(got, keyB) {
			t.Fatalf("rowB's own blob opened to a key that is not rowB's "+
				"(equals rowA's: %v)", bytes.Equal(got, keyA))
		}
	})
}

// FuzzWhatSealAcceptsOpens: anything Seal returns without error, Open under
// the same Envelope returns unchanged.
//
// Before this held, Seal did not check the cap Open enforces, so an over-cap
// body was written successfully and then read as permanently undecryptable —
// a write that reported success and was in fact data loss.
func FuzzWhatSealAcceptsOpens(f *testing.F) {
	f.Add([]byte("k"), []byte("hello"), 16, false)
	f.Add([]byte("k"), bytes.Repeat([]byte("A"), 100), 99, true)
	f.Add([]byte("k"), []byte{}, 1, false)

	f.Fuzz(func(t *testing.T, keyBytes, pt []byte, limit int, authed bool) {
		if limit < 1 || limit > 1<<16 {
			return
		}
		env := Envelope{MaxPlaintext: limit}
		if authed {
			env.AuthKey = bytes.Repeat([]byte{0x42}, AuthKeySize)
		}
		key := fuzzLeafKey(keyBytes)
		b := fuzzBinding(1, 7, 42, "e", "l", "r")
		ct, err := env.Seal(key, b, FieldRequestBody, pt)
		if err != nil {
			if len(pt) <= limit || !errors.Is(err, ErrPlaintextTooLarge) {
				t.Fatalf("Seal refused a %d-byte body under a %d-byte cap: %v", len(pt), limit, err)
			}
			return
		}
		got, err := env.Open(key, b, FieldRequestBody, ct)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("sealed %d bytes under cap %d; Open: %v", len(pt), limit, err)
		}
	})
}
