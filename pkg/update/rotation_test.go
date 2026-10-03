package update

import (
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/verify"
)

// TestContinuousUpgradeAcrossKeyRotation chains upgrades straight through a
// signing-key rotation window:
//
//	v1 factory (no signature)
//	v2 signed by old key "old" (still valid)
//	v3 signed by new key "new" (overlap window: both keys valid now)
//	v4 signed by new key after the old key expired
//
// Every package names exactly one KeyID; the decision only consults that key,
// so conclusions stay unique and deterministic — no "try every key" behavior,
// no stall at the handover.
func TestContinuousUpgradeAcrossKeyRotation(t *testing.T) {
	e := setup(t)
	defer e.close()
	// old: valid until now+12h. new: valid from now-12h for 2 days.
	e.addKey("old", now.Add(-30*day), now.Add(12*time.Hour))
	e.addKey("new", now.Add(-12*time.Hour), now.Add(2*day))

	step := func(name, key string, v uint64, want OutcomeCode) Outcome {
		t.Helper()
		o := e.eng.Install(e.pkgKey(key, v, nil))
		assertCode(t, name, o, want, "v"+itoa(v)+" signed by key "+key)
		if want == OutcomeInstalled {
			c := e.eng.ConfirmBoot()
			assertCode(t, name+"-confirm", c, OutcomeConfirmed, "confirm v"+itoa(v))
		}
		return o
	}

	// v2 still signed by the old key: accepted during the overlap window.
	step("v2-old-key", "old", 2, OutcomeInstalled)
	// v3 handed over to the new key: accepted while both keys coexist.
	step("v3-new-key", "new", 3, OutcomeInstalled)

	// Determinism across the rotation boundary: a package that still claims
	// the old key is rejected for a key-specific reason after expiry, never
	// silently re-verified with the new key. Simulate "later" by binding the
	// engine to an advanced clock; the package itself still says KeyID=old.
	later := now.Add(24 * time.Hour)
	e.eng.verifier = verify.New(e.root, func() time.Time { return later })
	expired := e.eng.Install(e.pkgKey("old", 4, nil))
	assertCode(t, "v4-old-key-after-expiry", expired, OutcomeRejected, "v4 claiming old key 24h later")
	if expired.Reason.Verification != verify.FailureKeyExpired {
		t.Fatalf("want key_expired for old key, got %+v", expired.Reason)
	}
	if e.curVersion() != 3 {
		t.Fatalf("rejected install must keep v3, got %d", e.curVersion())
	}

	// Same version v4 signed by the new key installs cleanly: chain continues.
	good := step("v4-new-key", "new", 4, OutcomeInstalled)
	if good.CurrentAfter != 4 {
		t.Fatalf("running=%d want 4", good.CurrentAfter)
	}
	st, _ := e.store.State()
	if st.Committed.Version != 4 || st.Retained.Version != 3 {
		t.Fatalf("after rotation chain: current=%d retained=%d", st.Committed.Version, st.Retained.Version)
	}
	if n := versionsOnDevice(st); n != 2 {
		t.Fatalf("device keeps %d versions, want 2", n)
	}
}
