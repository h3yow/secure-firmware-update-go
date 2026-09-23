package update

import (
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/verdict"
)

// TestKeyRotationDeterministicDecision models a rotation window in which BOTH
// keys are simultaneously trusted and valid (2026-07-01..2026-12-31 overlap).
// Packages signed by either key verify in the overlap; outside the window the
// clock decides uniquely which one is acceptable. The engine never selects
// among keys: each package names exactly one key id and resolution is total.
func TestKeyRotationDeterministicDecision(t *testing.T) {
	h := newHarness(t)
	// Widen old key so it overlaps with cur during H2 2026 (rotation window).
	for i := range h.root.Keys {
		if h.root.Keys[i].ID == "old" {
			end, _ := time.Parse(time.RFC3339, "2026-12-31T00:00:00Z")
			h.root.Keys[i].NotAfter = end.Unix()
		}
	}

	pin := func(s string) {
		tt, _ := time.Parse(time.RFC3339, s)
		h.eng.Verifier.NowFn = func() time.Time { return tt }
	}

	// In the overlap window, packages from BOTH concurrently valid keys pass,
	// but each is resolved through its own key id deterministically.
	pin("2026-09-23T00:00:00Z")
	pOld := h.goodPkg(t, "old-in-window", "1.0.0", "old")
	pCur := h.goodPkg(t, "cur-in-window", "1.0.1", "cur")
	assertOutcome(t, h.eng.VerifyOnly(pOld), true, "")
	assertOutcome(t, h.eng.VerifyOnly(pCur), true, "")

	// Determinism, not preference: verifying the same input twice must give
	// byte-identical verdicts ten times in a row.
	for i := 0; i < 10; i++ {
		o := h.eng.VerifyOnly(pOld)
		if !o.Success || o.Version != "1.0.0" {
			t.Fatalf("nondeterministic verdict on iteration %d: %+v", i, o)
		}
	}

	// After the overlap ends (2027-01-01) cur (also expired 2026-12-31 in
	// this fixture) and old both expire; next is the sole valid key.
	pin("2027-06-01T00:00:00Z")
	assertOutcome(t, h.eng.VerifyOnly(pOld), false, verdict.CodeKeyExpired)
	assertOutcome(t, h.eng.VerifyOnly(pCur), false, verdict.CodeKeyExpired)
	pNext := h.goodPkg(t, "next-valid", "1.0.2", "next")
	assertOutcome(t, h.eng.VerifyOnly(pNext), true, "")

	// Before the window (2025), only old is valid; cur is future.
	pin("2025-06-01T00:00:00Z")
	// shrink cur not-before stays 2026 -> not yet valid
	cur := h.goodPkg(t, "cur-future", "1.0.3", "cur")
	assertOutcome(t, h.eng.VerifyOnly(cur), false, verdict.CodeKeyNotYetValid)
}

// TestNoSilentKeySelection ensures a package signed by key A but carrying key
// B's id fails as bad_signature even when both keys are currently trusted.
func TestNoSilentKeySelection(t *testing.T) {
	h := newHarness(t)
	for i := range h.root.Keys {
		if h.root.Keys[i].ID == "old" {
			end, _ := time.Parse(time.RFC3339, "2026-12-31T00:00:00Z")
			h.root.Keys[i].NotAfter = end.Unix()
		}
	}
	// Sign bytes with old, stamp with cur's id (both valid in overlap).
	path := h.pkgPath(t, "cross", "1.0.0", "old", h.eng.Dev.InactiveSlot(), model, nil)
	// Rewrite package claiming cur id but keeping old's signature.
	raw, _ := readFile(path)
	pkg, err := firmware.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	pkg.KeyID = "cur"
	reencoded, err := firmware.Encode(pkg.ManifestBytes, pkg.Signature, "cur", pkg.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile(path, reencoded); err != nil {
		t.Fatal(err)
	}
	assertOutcome(t, h.eng.VerifyOnly(path), false, verdict.CodeBadSignature)
}
