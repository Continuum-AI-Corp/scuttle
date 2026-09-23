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
	kr, _ := NewLocalKeyring(nil)
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
