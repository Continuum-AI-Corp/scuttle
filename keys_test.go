package scuttle

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestGenerateCaptureSeed_BuildsAKeyring(t *testing.T) {
	a, err := GenerateCaptureSeed()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateCaptureSeed()
	if len(a) != CaptureSeedSize || bytes.Equal(a, b) {
		t.Fatalf("seed is %d bytes / repeated", len(a))
	}
	if _, err := NewLocalKeyring(a); err != nil {
		t.Fatal(err)
	}
}

func TestParseCaptureSeed(t *testing.T) {
	seed, _ := GenerateCaptureSeed()
	h := hex.EncodeToString(seed)
	for _, in := range []string{h, strings.ToUpper(h), "  " + h + "\n"} {
		got, err := ParseCaptureSeed(in)
		if err != nil || !bytes.Equal(got, seed) {
			t.Fatalf("ParseCaptureSeed(%q) = %x, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "zz", h[:62], h + "00", "0x" + h} {
		if _, err := ParseCaptureSeed(bad); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("ParseCaptureSeed(%q): want ErrInvalidConfig, got %v", bad, err)
		}
	}
}

func TestParsePublicKey_RoundTripsWhatAKeyringPublishes(t *testing.T) {
	kr, _ := NewEphemeralKeyring()
	got, err := ParsePublicKey(hex.EncodeToString(kr.CapturePublicKey()))
	if err != nil || !bytes.Equal(got, kr.CapturePublicKey()) {
		t.Fatalf("%v", err)
	}
	s, err := NewLeafSealer(got)
	if err != nil {
		t.Fatal(err)
	}
	_, sl, _ := s.NewLeaf("l")
	if _, err := kr.OpenLeaf(context.Background(), sl); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey("abcd"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("short public key: want ErrInvalidConfig, got %v", err)
	}
}

func TestAuthKeyHelpers(t *testing.T) {
	k, err := GenerateAuthKey()
	if err != nil || len(k) != AuthKeySize {
		t.Fatalf("%d bytes, %v", len(k), err)
	}
	got, err := ParseAuthKey(hex.EncodeToString(k))
	if err != nil || !bytes.Equal(got, k) {
		t.Fatalf("%v", err)
	}
	if _, err := ParseAuthKey("00"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
	// An all-zero key is a placeholder somebody forgot to replace, not a key.
	if _, err := ParseAuthKey(strings.Repeat("00", AuthKeySize)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("all-zero auth key: want ErrInvalidConfig, got %v", err)
	}
}
