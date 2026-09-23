package scuttle_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/Continuum-AI-Corp/scuttle"
)

// The full write-then-read path, with the two halves in the places they
// belong. In a real deployment the writer and the reader are different
// processes, and only the reader ever sees the capture seed.
func Example() {
	// Provisioning (once; see cmd/scuttle-keygen).
	seed, _ := scuttle.GenerateCaptureSeed()
	authKey, _ := scuttle.GenerateAuthKey()
	reader, _ := scuttle.NewLocalKeyring(seed)
	publicKey := reader.CapturePublicKey() // the ONLY key a writer receives

	env := scuttle.Envelope{MaxPlaintext: 256 << 10, AuthKey: authKey}

	// ── Writer: public key + auth key. Can seal, cannot open. ──
	sealer, _ := scuttle.NewLeafSealer(publicKey)
	leafKey, sealed, _ := sealer.NewLeaf("tenant:42|user:7|2026-09-12T10")
	bind := scuttle.Binding{
		SchemaVersion: 1,
		LeafID:        sealed.LeafID,
		WorkspaceID:   42,
		UserID:        7,
		RequestID:     "req_01JQ8F7YKX2M",
	}
	ct, err := env.Seal(leafKey, bind, scuttle.FieldRequestBody, []byte(`{"prompt":"hi"}`))
	if err != nil {
		panic(err)
	}
	// Store ct and sealed (LeafID, KemKeyID, Blob) with the record.

	// ── Reader: capture seed + auth key. ──
	key, err := reader.OpenLeaf(context.Background(), sealed)
	switch {
	case errors.Is(err, scuttle.ErrKeyUnavailable):
		return // retry later
	case err != nil:
		return // ErrUndecryptable: investigate, do not retry
	}
	pt, err := env.Open(key, bind, scuttle.FieldRequestBody, ct)
	fmt.Println(string(pt), err)

	// The same ciphertext presented as another tenant's does not open.
	other := bind
	other.WorkspaceID = 43
	_, err = env.Open(key, other, scuttle.FieldRequestBody, ct)
	fmt.Println(errors.Is(err, scuttle.ErrUndecryptable))

	// Output:
	// {"prompt":"hi"} <nil>
	// true
}
