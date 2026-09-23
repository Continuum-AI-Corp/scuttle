package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Continuum-AI-Corp/scuttle"
)

func parse(t *testing.T, out string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			m[k] = v
		}
	}
	return m
}

func TestKeygen_PrintsAConsistentKeySet(t *testing.T) {
	var buf bytes.Buffer
	if err := run(&buf); err != nil {
		t.Fatal(err)
	}
	m := parse(t, buf.String())

	seed, err := scuttle.ParseCaptureSeed(m["SCUTTLE_CAPTURE_SEED"])
	if err != nil {
		t.Fatal(err)
	}
	kr, err := scuttle.NewLocalKeyring(seed)
	if err != nil {
		t.Fatal(err)
	}
	if m["SCUTTLE_CAPTURE_PUBLIC_KEY"] != hex.EncodeToString(kr.CapturePublicKey()) {
		t.Fatal("printed public key does not belong to the printed seed")
	}
	if m["SCUTTLE_KEM_KEY_ID"] != kr.KemKeyID() {
		t.Fatal("printed kem key id does not match")
	}
	if _, err := scuttle.ParseAuthKey(m["SCUTTLE_AUTH_KEY"]); err != nil {
		t.Fatal(err)
	}
}

func TestKeygen_EveryRunIsFresh(t *testing.T) {
	var a, b bytes.Buffer
	_ = run(&a)
	_ = run(&b)
	if parse(t, a.String())["SCUTTLE_CAPTURE_SEED"] == parse(t, b.String())["SCUTTLE_CAPTURE_SEED"] {
		t.Fatal("two runs printed the same seed")
	}
}
