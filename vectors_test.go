package scuttle

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

// Known-answer vectors for the wire format (SPEC.md).
//
// Sealing is randomised (HPKE encapsulation and the GCM nonce), so the vectors
// fix the OUTPUT of one sealing and assert that every later version of this
// code — and any other implementation — opens it to the same bytes through
// every intermediate value: the opened leaf key, the associated data, the
// derived field key and the plaintext. A change that alters any of them is a
// wire-format change and fails here rather than in someone's backups.
//
// Regenerate (only for a deliberate, versioned format change):
//
//	go test -run TestVectors -update-vectors

var updateVectors = flag.Bool("update-vectors", false, "rewrite testdata/vectors.json")

const vectorsPath = "testdata/vectors.json"

type vectorFile struct {
	Comment          string       `json:"comment"`
	CaptureSeed      string       `json:"capture_seed"`
	CapturePublicKey string       `json:"capture_public_key"`
	KemKeyID         string       `json:"kem_key_id"`
	Cases            []vectorCase `json:"cases"`
}

type vectorCase struct {
	Name       string        `json:"name"`
	LeafID     string        `json:"leaf_id"`
	SealedLeaf string        `json:"sealed_leaf"`
	LeafKey    string        `json:"leaf_key"`
	AuthKey    string        `json:"auth_key"`
	Binding    vectorBinding `json:"binding"`
	Field      string        `json:"field"`
	AAD        string        `json:"aad"`
	FieldKey   string        `json:"field_key"`
	Ciphertext string        `json:"ciphertext"`
	Plaintext  string        `json:"plaintext"`
}

type vectorBinding struct {
	SchemaVersion int    `json:"schema_version"`
	EpochID       string `json:"epoch_id"`
	LeafID        string `json:"leaf_id"`
	WorkspaceID   int    `json:"workspace_id"`
	UserID        int    `json:"user_id"`
	RequestID     string `json:"request_id"`
}

func (v vectorBinding) binding() Binding {
	return Binding(v)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestVectors(t *testing.T) {
	if *updateVectors {
		writeVectors(t)
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v (generate with -update-vectors)", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Cases) < 3 {
		t.Fatalf("only %d vectors", len(vf.Cases))
	}
	kr, err := NewLocalKeyring(mustHex(t, vf.CaptureSeed))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(kr.CapturePublicKey()); got != vf.CapturePublicKey {
		t.Fatalf("seed -> public key changed:\n got %s\nwant %s", got, vf.CapturePublicKey)
	}
	if kr.KemKeyID() != vf.KemKeyID {
		t.Fatalf("kem key id: got %s want %s", kr.KemKeyID(), vf.KemKeyID)
	}
	var sawAuth, sawPlain bool
	for _, c := range vf.Cases {
		t.Run(c.Name, func(t *testing.T) {
			leafKey, err := kr.OpenLeaf(context.Background(), SealedLeaf{
				LeafID: c.LeafID, KemKeyID: vf.KemKeyID, Blob: mustHex(t, c.SealedLeaf),
			})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(leafKey, mustHex(t, c.LeafKey)) {
				t.Fatalf("leaf key: got %x", leafKey)
			}
			var auth []byte
			if c.AuthKey != "" {
				auth = mustHex(t, c.AuthKey)
				sawAuth = true
			} else {
				sawPlain = true
			}
			b := c.Binding.binding()
			if got := b.aad(auth != nil, c.Field); !bytes.Equal(got, mustHex(t, c.AAD)) {
				t.Fatalf("aad: got %x", got)
			}
			fk, err := deriveFieldKey(leafKey, auth, b, c.Field)
			if err != nil || !bytes.Equal(fk, mustHex(t, c.FieldKey)) {
				t.Fatalf("field key: got %x, %v", fk, err)
			}
			env := Envelope{AuthKey: auth}
			pt, err := env.Open(leafKey, b, c.Field, mustHex(t, c.Ciphertext))
			if err != nil || !bytes.Equal(pt, mustHex(t, c.Plaintext)) {
				t.Fatalf("plaintext: got %q, %v", pt, err)
			}
		})
	}
	if !sawAuth || !sawPlain {
		t.Fatal("vectors must cover both the authenticated and unauthenticated modes")
	}
}

func writeVectors(t *testing.T) {
	t.Helper()
	// A fixed, obviously-not-secret seed: vectors are public by definition.
	seed := bytes.Repeat([]byte{0x5c}, CaptureSeedSize)
	kr, err := NewLocalKeyring(seed)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := NewLeafSealer(kr.CapturePublicKey())
	auth := bytes.Repeat([]byte{0xa7}, AuthKeySize)

	type in struct {
		name  string
		auth  []byte
		b     vectorBinding
		field string
		pt    []byte
	}
	ins := []in{
		{"unauthenticated/request_body", nil, vectorBinding{1, "2026-09", "leaf-1", 42, 7, "req_01"}, FieldRequestBody, []byte(`{"prompt":"hello"}`)},
		{"unauthenticated/empty_response", nil, vectorBinding{1, "", "leaf-2", 0, 0, ""}, FieldResponseBody, []byte{}},
		{"unauthenticated/digit_shift", nil, vectorBinding{1, "e", "leaf-3", 12, 3, "r"}, FieldErrorMessage, []byte("ws 12 user 3")},
		{"authenticated/request_body", auth, vectorBinding{1, "2026-09", "leaf-4", 42, 7, "req_02"}, FieldRequestBody, []byte(`{"prompt":"hello"}`)},
		{"authenticated/headers", auth, vectorBinding{2, "2026-10", "leaf-5", 9, 1, "req_03"}, FieldResponseHeaders, bytes.Repeat([]byte("x-header: v\r\n"), 50)},
	}
	vf := vectorFile{
		Comment:          "scuttle wire-format known-answer vectors. See SPEC.md. All keys here are public test values.",
		CaptureSeed:      hex.EncodeToString(seed),
		CapturePublicKey: hex.EncodeToString(kr.CapturePublicKey()),
		KemKeyID:         kr.KemKeyID(),
	}
	for _, i := range ins {
		lk, sl, err := s.NewLeaf(i.b.LeafID)
		if err != nil {
			t.Fatal(err)
		}
		b := i.b.binding()
		fk, _ := deriveFieldKey(lk, i.auth, b, i.field)
		ct, err := Envelope{AuthKey: i.auth}.Seal(lk, b, i.field, i.pt)
		if err != nil {
			t.Fatal(err)
		}
		vf.Cases = append(vf.Cases, vectorCase{
			Name: i.name, LeafID: sl.LeafID, SealedLeaf: hex.EncodeToString(sl.Blob),
			LeafKey: hex.EncodeToString(lk), AuthKey: hex.EncodeToString(i.auth),
			Binding: i.b, Field: i.field, AAD: hex.EncodeToString(b.aad(i.auth != nil, i.field)),
			FieldKey: hex.EncodeToString(fk), Ciphertext: hex.EncodeToString(ct),
			Plaintext: hex.EncodeToString(i.pt),
		})
	}
	out, _ := json.MarshalIndent(vf, "", "  ")
	if err := os.WriteFile(vectorsPath, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
