package trust

import (
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
)

var t0 = time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)

func pubKey(id byte) []byte { return []byte{id} }

func TestEvaluateSelectsOnlyNamedKey(t *testing.T) {
	r := NewRoot()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// Two valid firmware keys during the rotation overlap window.
	must(r.AddKey(PublicKey{ID: "old", PublicKey: pubKey(1), Purpose: firmware.PurposeFirmware, NotBefore: t0.Add(-10 * 24 * time.Hour), NotAfter: t0.Add(2 * 24 * time.Hour)}))
	must(r.AddKey(PublicKey{ID: "new", PublicKey: pubKey(2), Purpose: firmware.PurposeFirmware, NotBefore: t0.Add(-1 * 24 * time.Hour), NotAfter: t0.Add(30 * 24 * time.Hour)}))

	for _, id := range []string{"old", "new"} {
		d := r.Evaluate(id, firmware.PurposeFirmware, t0)
		if !d.Accepted {
			t.Fatalf("key %q should be accepted during overlap: %s", id, d.Reason)
		}
	}
	// A recovery key never satisfies a firmware lookup.
	must(r.AddKey(PublicKey{ID: "rec", PublicKey: pubKey(3), Purpose: firmware.PurposeRecovery, NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour)}))
	if d := r.Evaluate("rec", firmware.PurposeFirmware, t0); d.Accepted {
		t.Fatal("recovery key must not be accepted for firmware purpose")
	}
}

func TestRejectOverlappingWindowSameKeyID(t *testing.T) {
	r := NewRoot()
	if err := r.AddKey(PublicKey{ID: "k", PublicKey: pubKey(1), Purpose: firmware.PurposeFirmware, NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// Same id+purpose with an overlapping window would make acceptance
	// ambiguous and must be rejected at registration time.
	err := r.AddKey(PublicKey{ID: "k", PublicKey: pubKey(2), Purpose: firmware.PurposeFirmware, NotBefore: t0.Add(-30 * time.Minute), NotAfter: t0.Add(2 * time.Hour)})
	if err == nil {
		t.Fatal("overlapping windows for same (id,purpose) must be rejected")
	}
	// Adjacent, non-overlapping re-registration (e.g. post-rotation renewal)
	// with a later window is allowed.
	if err := r.AddKey(PublicKey{ID: "k", PublicKey: pubKey(2), Purpose: firmware.PurposeFirmware, NotBefore: t0.Add(time.Hour), NotAfter: t0.Add(2 * time.Hour)}); err != nil {
		t.Fatalf("non-overlapping window should be allowed: %v", err)
	}
}

func TestDeterministicTestKeyDerivation(t *testing.T) {
	a, _ := GenerateTestKey("id", "seed", "firmware", t0.Add(-time.Hour), t0.Add(time.Hour))
	b, _ := GenerateTestKey("id", "seed", "firmware", t0.Add(-time.Hour), t0.Add(time.Hour))
	if string(a.Public) != string(b.Public) {
		t.Fatal("same seed must derive same key")
	}
	c, _ := GenerateTestKey("id", "other-seed", "firmware", t0.Add(-time.Hour), t0.Add(time.Hour))
	if string(a.Public) == string(c.Public) {
		t.Fatal("different seed must derive different key")
	}
	sig, err := a.Sign([]byte("msg"))
	if err != nil || len(sig) == 0 {
		t.Fatalf("sign failed: %v", err)
	}
}
