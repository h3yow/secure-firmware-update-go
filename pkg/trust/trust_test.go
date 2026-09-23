package trust

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T, id string) Key {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat(id+"\n", 20)))
	if err != nil {
		t.Fatal(err)
	}
	return Key{ID: id, Algorithm: AlgEd25519, Public: pub}
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestAcceptableKeyValidityBoundaries(t *testing.T) {
	k := testKey(t, "k1")
	k.NotBefore = at("2026-01-01T00:00:00Z").Unix()
	k.NotAfter = at("2026-12-31T00:00:00Z").Unix()
	k.Purposes = []Purpose{PurposeFirmware}
	r := &Root{Version: 1, Keys: []Key{k}}

	// Inclusive boundaries are acceptable.
	for _, s := range []string{"2026-01-01T00:00:00Z", "2026-06-01T12:00:00Z", "2026-12-31T00:00:00Z"} {
		got, amb, why := r.AcceptableKey("k1", PurposeFirmware, at(s))
		if amb || got == nil {
			t.Fatalf("%s: expected accept, got key=%v amb=%v why=%s", s, got, amb, why)
		}
	}
	// One second outside each side is rejected with precise reason.
	if got, _, _ := r.AcceptableKey("k1", PurposeFirmware, at("2025-12-31T23:59:59Z")); got != nil {
		t.Fatal("key one second before NotBefore must not be acceptable")
	}
	if got, _, _ := r.AcceptableKey("k1", PurposeFirmware, at("2027-01-01T00:00:01Z")); got != nil {
		t.Fatal("key one second after NotAfter must not be acceptable")
	}
}

func TestAcceptableKeyUnknownAndPurpose(t *testing.T) {
	k := testKey(t, "k1")
	k.NotBefore = at("2026-01-01T00:00:00Z").Unix()
	k.NotAfter = at("2026-12-31T00:00:00Z").Unix()
	k.Purposes = []Purpose{PurposeOther}
	r := &Root{Version: 1, Keys: []Key{k}}

	if got, _, _ := r.AcceptableKey("ghost", PurposeFirmware, at("2026-06-01T00:00:00Z")); got != nil {
		t.Fatal("unknown key id must not resolve")
	}
	if got, _, why := r.AcceptableKey("k1", PurposeFirmware, at("2026-06-01T00:00:00Z")); got != nil ||
		!strings.Contains(why, "do not include") {
		t.Fatalf("wrong-purpose key must be rejected with purpose basis, got=%v why=%s", got, why)
	}
	// Same key is fine for its own purpose.
	if got, _, _ := r.AcceptableKey("k1", PurposeOther, at("2026-06-01T00:00:00Z")); got == nil {
		t.Fatal("key must be acceptable for its listed purpose")
	}
}

func TestDuplicateKeyIDRejected(t *testing.T) {
	k1 := testKey(t, "dup")
	k2 := testKey(t, "dup")
	k1.NotBefore, k2.NotBefore = at("2026-01-01T00:00:00Z").Unix(), at("2026-01-01T00:00:00Z").Unix()
	k1.NotAfter, k2.NotAfter = at("2026-12-31T00:00:00Z").Unix(), at("2026-12-31T00:00:00Z").Unix()
	k1.Purposes, k2.Purposes = []Purpose{PurposeFirmware}, []Purpose{PurposeFirmware}
	r := &Root{Version: 1, Keys: []Key{k1, k2}}
	if err := r.validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate key ids must fail validation, got %v", err)
	}
}

func TestInvertedWindowRejected(t *testing.T) {
	k := testKey(t, "k1")
	k.NotBefore = at("2027-01-01T00:00:00Z").Unix()
	k.NotAfter = at("2026-01-01T00:00:00Z").Unix()
	k.Purposes = []Purpose{PurposeFirmware}
	r := &Root{Version: 1, Keys: []Key{k}}
	if err := r.validate(); err == nil {
		t.Fatal("inverted validity window must fail validation")
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	k := testKey(t, "k1")
	k.NotBefore = at("2026-01-01T00:00:00Z").Unix()
	k.NotAfter = at("2026-12-31T00:00:00Z").Unix()
	k.Purposes = []Purpose{PurposeFirmware}
	r := &Root{Version: 1, Keys: []Key{k}}
	path := dir + "/trust.json"
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	r2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Keys) != 1 || r2.Keys[0].ID != "k1" {
		t.Fatalf("roundtrip mismatch: %+v", r2)
	}
}
