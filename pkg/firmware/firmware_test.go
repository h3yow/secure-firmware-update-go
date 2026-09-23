package firmware

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseVersionCompare(t *testing.T) {
	cases := []struct {
		in   string
		want Version
		ok   bool
	}{
		{"1.2.3", Version{1, 2, 3}, true},
		{"0.0.1", Version{0, 0, 1}, true},
		{"1.2", Version{}, false},
		{"1.2.x", Version{}, false},
		{"1.2.3.4", Version{}, false},
		{"-1.0.0", Version{}, false},
	}
	for _, c := range cases {
		v, err := ParseVersion(c.in)
		if c.ok && err != nil {
			t.Fatalf("ParseVersion(%q) unexpected error: %v", c.in, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("ParseVersion(%q) expected error, got %v", c.in, v)
		}
		if c.ok && v != c.want {
			t.Fatalf("ParseVersion(%q)=%v want %v", c.in, v, c.want)
		}
	}
	if (Version{1, 10, 0}).Compare(Version{1, 9, 0}) != 1 {
		t.Fatal("1.10.0 must be greater than 1.9.0 (numeric, not lexicographic)")
	}
	if (Version{2, 0, 0}).Compare(Version{1, 99, 99}) != 1 {
		t.Fatal("2.0.0 must be greater than 1.99.99")
	}
	if (Version{1, 0, 0}).Compare(Version{1, 0, 0}) != 0 {
		t.Fatal("equal versions must compare 0")
	}
}

func sampleSignedBlob(t *testing.T) []byte {
	t.Helper()
	m := Manifest{
		Schema:        CurrentSchema,
		PackageID:     "p1",
		Model:         "m",
		TargetSlot:    "B",
		Version:       "1.0.0",
		PayloadSize:   5,
		PayloadSHA256: PayloadSHA256Hex([]byte("hello")),
		PayloadKey:    "k",
		IssuedAt:      1,
	}
	mb, err := CanonicalManifest(&m)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(mb, bytes.Repeat([]byte{1}, 64), "key-1", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseRoundtrip(t *testing.T) {
	b := sampleSignedBlob(t)
	p, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.KeyID != "key-1" || string(p.Payload) != "hello" || p.Manifest.Version != "1.0.0" {
		t.Fatalf("unexpected parsed package: %+v", p)
	}
	if len(p.Signature) != 64 {
		t.Fatalf("sig len %d", len(p.Signature))
	}
}

func TestParseTruncationAndMagic(t *testing.T) {
	good := sampleSignedBlob(t)
	for n := 0; n < len(good)-1; n += 7 {
		if _, err := Parse(good[:n]); err == nil {
			t.Fatalf("truncated at %d bytes parsed unexpectedly", n)
		}
	}
	bad := append([]byte(nil), good...)
	bad[0] = 'X'
	if _, err := Parse(bad); err == nil {
		t.Fatal("bad magic must fail")
	}
	extra := append(append([]byte(nil), good...), 0)
	if _, err := Parse(extra); err == nil {
		t.Fatal("trailing bytes must fail")
	}
}

func TestNonCanonicalManifestRejected(t *testing.T) {
	// Manifest JSON with reordered keys / extra whitespace is not canonical.
	nonCanon := []byte(`{"version":"1.0.0","schema":1}` + "\n")
	b, err := Encode(nonCanon, bytes.Repeat([]byte{1}, 64), "key-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(b)
	if err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("expected non-canonical error, got %v", err)
	}
}
