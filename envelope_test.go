package scuttle

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func testLeafKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, LeafKeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func testBinding() Binding {
	return Binding{
		SchemaVersion: 6,
		EpochID:       "ws:42|90d|2026-06-10",
		LeafID:        "ws:42|u:7|2026-06-10",
		WorkspaceID:   42,
		UserID:        7,
		RequestID:     "req_01JQ8F7YKX2M",
	}
}

// The AAD must be unambiguous: concatenating raw decimal fields lets
// (ws=1,uid=23) and (ws=12,uid=3) produce the same byte string, which would
// let a blob move between tenants without failing the tag check.
func TestBindingAAD_IsUnambiguousAcrossFieldBoundaries(t *testing.T) {
	a := Binding{WorkspaceID: 1, UserID: 23}
	b := Binding{WorkspaceID: 12, UserID: 3}
	if bytes.Equal(a.aad(false, FieldRequestBody), b.aad(false, FieldRequestBody)) {
		t.Fatal("AAD collided across the workspace/user boundary — length prefixing is missing")
	}
}

func TestBindingAAD_DiffersPerField(t *testing.T) {
	b := testBinding()
	if bytes.Equal(b.aad(false, FieldRequestBody), b.aad(false, FieldResponseBody)) {
		t.Fatal("request and response bodies share an AAD")
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	e := Envelope{}
	key, b := testLeafKey(t), testBinding()
	pt := []byte(`{"model":"claude-opus-5","messages":[{"role":"user","content":"hello"}]}`)

	ct, err := e.Seal(key, b, FieldRequestBody, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("claude-opus-5")) {
		t.Fatal("plaintext is visible in the ciphertext")
	}
	got, err := e.Open(key, b, FieldRequestBody, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", got, pt)
	}
}

func TestSeal_IsNonDeterministic(t *testing.T) {
	e := Envelope{}
	key, b := testLeafKey(t), testBinding()
	pt := []byte("same plaintext twice")
	c1, err := e.Seal(key, b, FieldRequestBody, pt)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := e.Seal(key, b, FieldRequestBody, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("two seals of the same plaintext are identical — the nonce is not random")
	}
}

// A5: the database is an untrusted store. None of these may open.
func TestOpen_RejectsEveryRebinding(t *testing.T) {
	e := Envelope{}
	key, b := testLeafKey(t), testBinding()
	pt := []byte("a prompt containing a policy number")
	ct, err := e.Seal(key, b, FieldRequestBody, pt)
	if err != nil {
		t.Fatal(err)
	}

	other := testBinding()
	other.WorkspaceID = 43
	otherUser := testBinding()
	otherUser.UserID = 8
	otherReq := testBinding()
	otherReq.RequestID = "req_someone_else"
	otherLeaf := testBinding()
	otherLeaf.LeafID = "ws:42|u:7|2026-06-11"
	otherEpoch := testBinding()
	otherEpoch.EpochID = "ws:42|90d|2026-06-11"
	otherSchema := testBinding()
	otherSchema.SchemaVersion = 7

	cases := []struct {
		name  string
		bind  Binding
		field string
	}{
		{"cross-workspace", other, FieldRequestBody},
		{"cross-user", otherUser, FieldRequestBody},
		{"cross-request", otherReq, FieldRequestBody},
		{"cross-leaf", otherLeaf, FieldRequestBody},
		{"cross-epoch", otherEpoch, FieldRequestBody},
		{"cross-schema", otherSchema, FieldRequestBody},
		{"request blob read as response", b, FieldResponseBody},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.Open(key, tc.bind, tc.field, ct); !errors.Is(err, ErrUndecryptable) {
				t.Fatalf("want ErrUndecryptable, got %v", err)
			}
		})
	}
}

func TestOpen_RejectsTamperedCiphertext(t *testing.T) {
	e := Envelope{}
	key, b := testLeafKey(t), testBinding()
	ct, err := e.Seal(key, b, FieldRequestBody, []byte("tamper target"))
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := e.Open(key, b, FieldRequestBody, ct); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable, got %v", err)
	}
}

func TestOpen_RejectsWrongLeafKey(t *testing.T) {
	e := Envelope{}
	b := testBinding()
	ct, err := e.Seal(testLeafKey(t), b, FieldRequestBody, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Open(testLeafKey(t), b, FieldRequestBody, ct); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable, got %v", err)
	}
}

func TestOpen_RejectsShortCiphertext(t *testing.T) {
	e := Envelope{}
	if _, err := e.Open(testLeafKey(t), testBinding(), FieldRequestBody, []byte{1, 2, 3}); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable, got %v", err)
	}
}

// Bodies are JSON and compress well; ciphertext does not. Compressing before
// sealing is what keeps a storage engine's block compression from being defeated.
func TestSeal_CompressesBeforeEncrypting(t *testing.T) {
	e := Envelope{}
	pt := []byte(strings.Repeat(`{"role":"user","content":"the same line over and over"},`, 400))
	ct, err := e.Seal(testLeafKey(t), testBinding(), FieldRequestBody, pt)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) >= len(pt)/2 {
		t.Fatalf("expected compression: plaintext %d bytes, ciphertext %d", len(pt), len(ct))
	}
}

// A hostile or corrupt blob must not be able to expand without bound.
func TestOpen_RefusesDecompressionBomb(t *testing.T) {
	e := Envelope{MaxPlaintext: 4096}
	key, b := testLeafKey(t), testBinding()
	big := bytes.Repeat([]byte("A"), 1<<20) // compresses tiny, expands past the cap
	ct := sealBypassingTheCap(t, key, nil, b, FieldRequestBody, big)
	if _, err := e.Open(key, b, FieldRequestBody, ct); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable for an over-cap expansion, got %v", err)
	}
}

func TestSeal_RejectsWrongKeySize(t *testing.T) {
	e := Envelope{}
	if _, err := e.Seal([]byte("too short"), testBinding(), FieldRequestBody, []byte("x")); err == nil {
		t.Fatal("expected an error for a short leaf key")
	}
}

func TestSeal_EmptyPlaintextRoundTrips(t *testing.T) {
	e := Envelope{}
	key, b := testLeafKey(t), testBinding()
	ct, err := e.Seal(key, b, FieldRequestBody, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Open(key, b, FieldRequestBody, ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %q", got)
	}
}

// The policy cap must not be the only bound: a blob engineered to expand to
// gigabytes must be refused by the DECODER, not merely measured afterwards.
func TestOpen_BombIsRefusedWithoutAllocatingIt(t *testing.T) {
	e := Envelope{MaxPlaintext: 1024}
	key, b := testLeafKey(t), testBinding()
	// ~64 MiB of zeros compresses to a few hundred bytes and is above the
	// decoder's hard allocation ceiling.
	huge := make([]byte, 64<<20)
	ct := sealBypassingTheCap(t, key, nil, b, FieldRequestBody, huge)
	if len(ct) > 1<<16 {
		t.Fatalf("fixture is not a bomb: %d bytes of ciphertext", len(ct))
	}
	if _, err := e.Open(key, b, FieldRequestBody, ct); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("want ErrUndecryptable, got %v", err)
	}
}

// sealBypassingTheCap builds a well-formed blob of any size, the way a hostile
// or misconfigured writer holding the leaf key could. Seal itself refuses
// bodies over the cap, so the bomb tests need this to construct their input.
func sealBypassingTheCap(t *testing.T, leafKey, authKey []byte, b Binding, field string, pt []byte) []byte {
	t.Helper()
	key, err := deriveFieldKey(leafKey, authKey, b, field)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, nonceSize)
	return gcm.Seal(nonce, nonce, zstdEnc.EncodeAll(pt, nil), b.aad(authKey != nil, field))
}
