package device

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// rewriteSlotMeta overwrites a slot's on-disk metadata file with arbitrary
// content, simulating a crash/partial write that left state.json and the
// slot file disagreeing.
func rewriteSlotMeta(t *testing.T, dir, name string, mutate func(SlotState) SlotState) {
	t.Helper()
	p := filepath.Join(dir, "slot-"+name+".json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m SlotState
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m = mutate(m)
	out, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestReconcileWithoutBootInterruptedCleanup reproduces the reported
// production failure: cleaning the old version is interrupted (slot
// metadata replaced, state.json not updated), and the operator queries
// status / rolls back WITHOUT ever running the boot recovery. The store
// must reconcile against disk truth on open: reported current version must
// match the payload the device really runs, and the broken old slot may
// never be re-enabled.
func TestReconcileWithoutBootInterruptedCleanup(t *testing.T) {
	s, dir := openStore(t)
	defer s.Close()
	if err := s.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	round(t, s, 2) // committed v2 on one slot, retained v1 on the other

	// Interrupt the staging of v3 exactly as the production failure did:
	// new slot files are already in place, state.json still claims the slot
	// holds retained v1.
	err := s.Stage(slot(3), []byte{3}, WithFaultHook(func(step string) error {
		if step == "stage.state" {
			return errors.New("power loss mid cleanup")
		}
		return nil
	}))
	if err == nil {
		t.Fatal("expected injected fault")
	}
	s.Close()

	// Fresh process, and deliberately DO NOT call RecoverOnBoot: a plain
	// status read must already be reconciled with disk truth.
	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatalf("device must still open after interrupted cleanup: %v", err)
	}
	defer s2.Close()
	st, err := s2.State()
	if err != nil {
		t.Fatalf("status must remain readable: %v", err)
	}
	if st.Committed.Version != 2 {
		t.Fatalf("reported current=%d must equal the really-running payload v2", st.Committed.Version)
	}
	if st.Staged.Present {
		t.Fatalf("broken old slot must be pruned, got retained=%+v", st.Staged)
	}
	t.Logf("scenario=reconcile-without-boot input=crash-after-slot-files basis=state.json(v1)!=disk(v3) result=committed=%d pruned=true", st.Committed.Version)

	// Rollback must not resurrect the broken old slot; with nothing retained
	// it is a stable no-op on the known-good version.
	if err := s2.Rollback(); err != ErrNotPending {
		t.Fatalf("rollback with no pending must be ErrNotPending, got %v", err)
	}
	if err := s2.Revert(); !errors.Is(err, ErrNothingToRevert) {
		t.Fatalf("revert to pruned slot must be refused, got %v", err)
	}
	// And later upgrades continue normally.
	round(t, s2, 4)
	st, _ = s2.State()
	if st.Committed.Version != 4 {
		t.Fatalf("upgrades must continue after reconciliation, got %d", st.Committed.Version)
	}
}

// TestReconcileDetectsTamperedPayloadHash ensures the disk-truth check also
// covers the payload blob, not just the metadata file: a recorded slot whose
// payload was torn/corrupted is broken and must never be reported as the
// running known-good version.
func TestReconcileDetectsTamperedPayloadHash(t *testing.T) {
	s, dir := openStore(t)
	defer s.Close()
	if err := s.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	round(t, s, 2) // committed v2, retained v1

	// Flip payload bytes of the COMMITTED slot: the blob no longer hashes to
	// the hash recorded in state.json.
	ap := filepath.Join(dir, "slot-"+s.inner.ActiveSlot+".bin")
	b, err := os.ReadFile(ap)
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xFF
	if err := os.WriteFile(ap, b, 0o644); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatalf("device must still open: %v", err)
	}
	defer s2.Close()
	st, _ := s2.State()
	// The only other healthy slot carries retained v1: the boot pointer must
	// flip there rather than stay on the torn payload.
	if st.Committed.Version != 1 {
		t.Fatalf("torn active payload must fall back to healthy retained v1, got current=%d", st.Committed.Version)
	}
	if st.Pending != nil {
		t.Fatal("dangling pending must be cleared when falling back from a broken active slot")
	}
	t.Logf("scenario=active-payload-torn basis=sha256(blob)!=record result=fallback_current=%d", st.Committed.Version)
}

// TestReconcileKeepsHealthyRetainedSlot confirms ordinary healthy state is
// never touched by reconciliation (it is a repair path, not a reset path).
func TestReconcileKeepsHealthyRetainedSlot(t *testing.T) {
	s, dir := openStore(t)
	defer s.Close()
	if err := s.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	round(t, s, 2)
	round(t, s, 3)
	s.Close()

	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	st, _ := s2.State()
	if st.Committed.Version != 3 || !st.Staged.Present || st.Staged.Version != 2 {
		t.Fatalf("healthy state must be preserved, got committed=%d retained=%+v", st.Committed.Version, st.Staged)
	}
	if got := sha256.Sum256(mustReadFile(t, filepath.Join(dir, "slot-"+s2.inner.ActiveSlot+".bin"))); got != [32]byte(st.Committed.PayloadHash) {
		t.Fatal("active payload hash must match recorded hash")
	}
	t.Logf("scenario=healthy-state input=v3+v2 basis=all-slots-verified result=committed=%d retained=%d", st.Committed.Version, st.Staged.Version)
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
