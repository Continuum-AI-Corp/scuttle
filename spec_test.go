package scuttle

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"testing"
)

// SPEC.md §3–§4, re-implemented from the document rather than from the code,
// so a divergence between the two fails here.
func specAAD(prefix string, b Binding, field string) []byte {
	var out []byte
	for _, p := range []string{prefix, strconv.Itoa(b.SchemaVersion), b.EpochID, b.LeafID,
		strconv.Itoa(b.WorkspaceID), strconv.Itoa(b.UserID), b.RequestID, field} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out
}

// HKDF-Expand for L = 32 is a single block: HMAC(prk, info || 0x01).
func specExpand32(prk, info []byte) []byte {
	m := hmac.New(sha256.New, prk)
	m.Write(info)
	m.Write([]byte{1})
	return m.Sum(nil)
}

func TestSpec_FieldKeyMatchesTheDocumentedFormula(t *testing.T) {
	leaf := bytes.Repeat([]byte{3}, LeafKeySize)
	auth := bytes.Repeat([]byte{9}, AuthKeySize)
	b := Binding{SchemaVersion: -2, EpochID: "e", LeafID: "l", WorkspaceID: 12, UserID: 3, RequestID: "r"}

	gotPlain, _ := deriveFieldKey(leaf, nil, b, FieldRequestBody)
	wantPlain := specExpand32(leaf, specAAD("orca/rlog/v1", b, FieldRequestBody))
	if !bytes.Equal(gotPlain, wantPlain) {
		t.Fatal("unauthenticated field key differs from SPEC.md §4")
	}

	extract := hmac.New(sha256.New, auth)
	extract.Write(leaf)
	gotAuth, _ := deriveFieldKey(leaf, auth, b, FieldRequestBody)
	wantAuth := specExpand32(extract.Sum(nil), specAAD("orca/rlog/v1/auth", b, FieldRequestBody))
	if !bytes.Equal(gotAuth, wantAuth) {
		t.Fatal("authenticated field key differs from SPEC.md §4")
	}
	if !bytes.Equal(b.aad(true, FieldRequestBody), specAAD("orca/rlog/v1/auth", b, FieldRequestBody)) {
		t.Fatal("AAD differs from SPEC.md §3")
	}
}

func TestSpec_SealedLeafIs1168Bytes(t *testing.T) {
	kr, _ := NewEphemeralKeyring()
	if n := len(kr.CapturePublicKey()); n != 1216 {
		t.Fatalf("public key is %d bytes; SPEC.md says 1216", n)
	}
	s, _ := NewLeafSealer(kr.CapturePublicKey())
	_, sl, _ := s.NewLeaf("l")
	if len(sl.Blob) != 1168 {
		t.Fatalf("sealed leaf is %d bytes; SPEC.md says 1168", len(sl.Blob))
	}
	if len(sl.KemKeyID) != 16 {
		t.Fatalf("kem key id is %d chars; SPEC.md says 16", len(sl.KemKeyID))
	}
}

// SPEC.md §5: a stored frame's packed size is
// 9 + len + 3 × max(1, ceil(len / 131072)).
func TestSpec_StoredFrameSizeFormula(t *testing.T) {
	for _, n := range []int{0, 1, 131071, 131072, 131073, 3 * 131072, 1 << 20} {
		blocks := max(1, (n+131071)/131072)
		if got, want := len(storedFrame(make([]byte, n))), 9+n+3*blocks; got != want {
			t.Fatalf("%d bytes: stored frame is %d, SPEC.md says %d", n, got, want)
		}
	}
}

// SPEC.md §5: the decoder limit.
func TestSpec_DecoderLimitFormula(t *testing.T) {
	for _, c := range []int{1, 32 << 10, 32<<10 + 1, 1 << 20, 5 << 20, 16 << 20} {
		want := 1
		for want < max(2*c, 64<<10) {
			want <<= 1
		}
		want = min(want, 16<<20)
		if got := decoderLimit(c); got != want {
			t.Fatalf("decoderLimit(%d) = %d, SPEC.md says %d", c, got, want)
		}
	}
}
