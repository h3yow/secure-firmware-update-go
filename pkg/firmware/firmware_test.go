package firmware

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	sign := func(b []byte) ([]byte, error) {
		priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
		return ed25519.Sign(priv, b), nil
	}
	p, err := NewBuilder().Build("m1", "app", 7, []byte("payload"), "k9", time.Unix(1000, 0).UTC(), sign)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Meta.Version != 7 || p2.Meta.Model != "m1" || !bytes.Equal(p2.Payload, p.Payload) || !bytes.Equal(p2.Signature, p.Signature) {
		t.Fatalf("round trip mismatch: %+v", p2.Meta)
	}
}

func TestCanonicalEncodingStable(t *testing.T) {
	m := Metadata{Model: "m", TargetSlot: "app", Version: 1, PayloadHash: make([]byte, 32), PayloadSize: 0, KeyID: "k", IssuedAt: time.Unix(1, 0).UTC()}
	a, _ := CanonicalEncode(m)
	b, _ := CanonicalEncode(m)
	if !bytes.Equal(a, b) {
		t.Fatal("canonical encoding not stable")
	}
	// Different timezone normalization must not change encoding.
	m2 := m
	m2.IssuedAt = m.IssuedAt.In(time.FixedZone("X", 3600))
	c, _ := CanonicalEncode(m2)
	if !bytes.Equal(a, c) {
		t.Fatal("canonical encoding must normalize timezones to UTC")
	}
}
