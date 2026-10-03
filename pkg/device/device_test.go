package device

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
)

func slot(v uint64) SlotState {
	return SlotState{Model: "d1", Target: "app", Version: v, PayloadHash: firmware.HashPayload([]byte{byte(v)})}
}

func openStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "dev")
	s, err := Open(dir, "d1")
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestFactoryInitAndPersistence(t *testing.T) {
	s, dir := openStore(t)
	if err := s.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Reopen: committed state must survive.
	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatal(err)
	}
	st, err := s2.State()
	if err != nil {
		t.Fatal(err)
	}
	if st.Committed.Version != 1 {
		t.Fatalf("version=%d want 1", st.Committed.Version)
	}
	if err := s2.FactoryInit(slot(9), []byte{9}); err == nil {
		t.Fatal("second factory init must be refused")
	}
	s2.Close()
}

func TestStageIdempotentIdenticalContent(t *testing.T) {
	s, _ := openStore(t)
	defer s.Close()
	if err := s.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	m := slot(2)
	if err := s.Stage(m, []byte{2}); err != nil {
		t.Fatal(err)
	}
	// Same version + hash: retry succeeds silently.
	if err := s.Stage(m, []byte{2}); err != nil {
		t.Fatalf("identical re-stage should be idempotent: %v", err)
	}
	// Different content in pending slot: rejected.
	other := slot(3)
	if err := s.Stage(other, []byte{3}); err == nil {
		t.Fatal("conflicting stage must be rejected")
	}
}

func TestActivationRollbackPhysicalSlots(t *testing.T) {
	s, _ := openStore(t)
	defer s.Close()
	if err := s.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Stage(slot(2), []byte{2}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.State()
	if !st.Staged.Present || st.Committed.Version != 1 {
		t.Fatalf("after stage committed must remain v1, got %+v", st)
	}
	if err := s.Activate(); err != nil {
		t.Fatal(err)
	}
	st, _ = s.State()
	if st.Committed.Version != 2 {
		t.Fatalf("after activate committed=%d want 2", st.Committed.Version)
	}
	if err := s.Rollback(); err != nil {
		t.Fatal(err)
	}
	st, _ = s.State()
	if st.Committed.Version != 1 || st.Pending != nil || st.Staged.Present {
		t.Fatalf("rollback state wrong: %+v", st)
	}
}

func TestStageCrashLeavesNoHalfWrittenState(t *testing.T) {
	s, dir := openStore(t)
	defer s.Close()
	if err := s.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	err := s.Stage(slot(2), []byte{2}, WithFaultHook(func(step string) error {
		if step == "stage.blob" {
			return errors.New("disk error")
		}
		return nil
	}))
	if err == nil {
		t.Fatal("expected injected error")
	}
	s.Close()

	// Reopen: device must still show v1 committed, no pending, no temp files.
	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := s2.State()
	if st.Committed.Version != 1 || st.Pending != nil {
		t.Fatalf("crash recovery state wrong: %+v", st)
	}
}

func TestActivateWithoutPending(t *testing.T) {
	s, _ := openStore(t)
	defer s.Close()
	_ = s.FactoryInit(slot(1), []byte{1})
	if err := s.Activate(); err != ErrNotPending {
		t.Fatalf("got %v want ErrNotPending", err)
	}
	if err := s.Confirm(); err != ErrNotPending {
		t.Fatalf("got %v want ErrNotPending", err)
	}
	if err := s.Rollback(); err != ErrNotPending {
		t.Fatalf("got %v want ErrNotPending", err)
	}
}

func TestModelGuardOnReopen(t *testing.T) {
	s, dir := openStore(t)
	_ = s.FactoryInit(slot(1), []byte{1})
	s.Close()
	if _, err := Open(dir, "d2"); err == nil {
		t.Fatal("opening store with foreign model must fail")
	}
}

func TestChainedUpgradesKeepOnlyTwoVersions(t *testing.T) {
	s, dir := openStore(t)
	defer s.Close()
	if err := s.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	// Chain v1 -> v2 -> v3 -> v4, confirming each step.
	for _, v := range []uint64{2, 3, 4} {
		if err := s.Stage(slot(v), []byte{byte(v)}); err != nil {
			t.Fatalf("stage v%d: %v", v, err)
		}
		if err := s.Activate(); err != nil {
			t.Fatalf("activate v%d: %v", v, err)
		}
		if err := s.Confirm(); err != nil {
			t.Fatalf("confirm v%d: %v", v, err)
		}
		st, _ := s.State()
		if st.Committed.Version != v || st.Retained.Version != v-1 {
			t.Fatalf("after confirm v%d: current=%d retained=%d", v, st.Committed.Version, st.Retained.Version)
		}
		if present := countPresent(st); present != 2 {
			t.Fatalf("after v%d device keeps %d versions, want exactly 2: %+v", v, present, st)
		}
	}
	// Post-confirm rollback returns to the retained known-good v3.
	if err := s.RollbackRetained(); err != nil {
		t.Fatal(err)
	}
	st, _ := s.State()
	if st.Committed.Version != 3 || st.Retained.Version != 4 {
		t.Fatalf("after retained rollback: current=%d other=%d", st.Committed.Version, st.Retained.Version)
	}
	// Second rollback is a stable refusal (only one rollback generation kept).
	if err := s.RollbackRetained(); err != ErrNotPending {
		t.Fatalf("second rollback = %v, want ErrNotPending", err)
	}
	// Reinstall v4 without any wipe: upgrade chain continues.
	if err := s.Stage(slot(4), []byte{4}); err != nil {
		t.Fatalf("re-stage v4 after rollback: %v", err)
	}
	if err := s.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(); err != nil {
		t.Fatal(err)
	}
	st, _ = s.State()
	if st.Committed.Version != 4 || st.Retained.Version != 3 {
		t.Fatalf("after reinstall v4: current=%d retained=%d", st.Committed.Version, st.Retained.Version)
	}
	s.Close()
	// Reopen after the whole chain: exactly two versions survive.
	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatal(err)
	}
	st, _ = s2.State()
	if st.Committed.Version != 4 {
		t.Fatalf("reopen current=%d want 4", st.Committed.Version)
	}
	if present := countPresent(st); present != 2 {
		t.Fatalf("reopen keeps %d versions, want 2: %+v", present, st)
	}
}

// countPresent counts distinct physically present versions on the device.
func countPresent(st State) int {
	seen := map[uint64]bool{}
	if st.Committed.Present {
		seen[st.Committed.Version] = true
	}
	if st.Staged.Present {
		seen[st.Staged.Version] = true
	}
	if st.Retained.Present {
		seen[st.Retained.Version] = true
	}
	return len(seen)
}

// TestCrashWhileOverwritingRetainedSlotRepairs is the "history cleanup power
// loss" case at storage level: v2 is confirmed (v1 retained in the inactive
// slot); staging v3 overwrites that retained slot; a write fault interrupts
// the overwrite. On reopen the reconciler must detect the half-overwritten
// retained slot, drop it, and keep v2 bootable; retrying v3 then succeeds.
func TestCrashWhileOverwritingRetainedSlotRepairs(t *testing.T) {
	s, dir := openStore(t)
	defer s.Close()
	if err := s.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Stage(slot(2), []byte{2}); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(); err != nil {
		t.Fatal(err)
	}
	st, _ := s.State()
	if st.Committed.Version != 2 || st.Retained.Version != 1 {
		t.Fatalf("setup wrong: %+v", st)
	}

	// Interrupt overwrite of the retained slot at its payload write.
	err := s.Stage(slot(3), []byte{3}, WithFaultHook(func(step string) error {
		if step == "stage.blob" {
			return errors.New("power loss during retained-slot overwrite")
		}
		return nil
	}))
	if err == nil {
		t.Fatal("expected injected fault")
	}
	s.Close()

	// Reopen: reconcile must keep v2 running with no pending update.
	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatalf("reopen after cleanup crash: %v", err)
	}
	st, _ = s2.State()
	if st.Committed.Version != 2 {
		t.Fatalf("after reconcile running=%d want 2", st.Committed.Version)
	}
	if st.Pending != nil {
		t.Fatalf("pending must be nil after reconcile, got %+v", st.Pending)
	}
	if st.Retained.Present {
		t.Fatalf("half-overwritten retained slot must be discarded, got v%d", st.Retained.Version)
	}

	// The device must be able to continue upgrading without any wipe.
	if err := s2.Stage(slot(3), []byte{3}); err != nil {
		t.Fatalf("retry stage v3 after repair: %v", err)
	}
	if err := s2.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := s2.Confirm(); err != nil {
		t.Fatal(err)
	}
	st, _ = s2.State()
	if st.Committed.Version != 3 || st.Retained.Version != 2 {
		t.Fatalf("after retry: current=%d retained=%d", st.Committed.Version, st.Retained.Version)
	}
}

// TestCrashAfterRetainedMetaBeforeStateRepairs interrupts the overwrite after
// both slot files were replaced atomically but before state.json records the
// new content — reconciliation must notice the mismatch and recover.
func TestCrashAfterRetainedMetaBeforeStateRepairs(t *testing.T) {
	s, dir := openStore(t)
	defer s.Close()
	if err := s.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Stage(slot(2), []byte{2}); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(); err != nil {
		t.Fatal(err)
	}
	err := s.Stage(slot(3), []byte{3}, WithFaultHook(func(step string) error {
		if step == "stage.state" {
			return errors.New("power loss after slot files replaced")
		}
		return nil
	}))
	if err == nil {
		t.Fatal("expected injected fault")
	}
	s.Close()

	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	st, _ := s2.State()
	if st.Committed.Version != 2 || st.Pending != nil {
		t.Fatalf("reconciled state wrong: %+v", st)
	}
}
