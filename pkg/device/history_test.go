package device

import (
	"errors"
	"os"
	"sort"
	"testing"
)

// stageActivateConfirm drives one full update round at the store level.
func round(t *testing.T, s *Store, v uint64) {
	t.Helper()
	if err := s.Stage(slot(v), []byte{byte(v)}); err != nil {
		t.Fatalf("stage v%d: %v", v, err)
	}
	if err := s.Activate(); err != nil {
		t.Fatalf("activate v%d: %v", v, err)
	}
	if err := s.Confirm(); err != nil {
		t.Fatalf("confirm v%d: %v", v, err)
	}
}

func TestStageOverwritesRetainedPreviousWhenNoPending(t *testing.T) {
	s, _ := openStore(t)
	defer s.Close()
	if err := s.FactoryInit(slot(1)); err != nil {
		t.Fatal(err)
	}
	round(t, s, 2) // v1 retained as previous known-good

	st, _ := s.State()
	if !st.Staged.Present || st.Staged.Version != 1 {
		t.Fatalf("after confirm, previous v1 must be retained, got %+v", st.Staged)
	}
	// Next round must reuse the slot without any manual cleanup.
	round(t, s, 3)
	st, _ = s.State()
	if st.Committed.Version != 3 || !st.Staged.Present || st.Staged.Version != 2 {
		t.Fatalf("after second round: committed=%d retained=%+v", st.Committed.Version, st.Staged)
	}
	t.Logf("scenario=continuous-rounds committed=%d retained_previous=%d", st.Committed.Version, st.Staged.Version)
}

func TestStageConflictUsesSentinel(t *testing.T) {
	s, _ := openStore(t)
	defer s.Close()
	_ = s.FactoryInit(slot(1))
	if err := s.Stage(slot(2), []byte{2}); err != nil {
		t.Fatal(err)
	}
	err := s.Stage(slot(3), []byte{3})
	if !errors.Is(err, ErrSlotConflict) {
		t.Fatalf("conflicting stage must wrap ErrSlotConflict, got %v", err)
	}
}

func TestRevertToRetainedPrevious(t *testing.T) {
	s, _ := openStore(t)
	defer s.Close()
	_ = s.FactoryInit(slot(1))
	round(t, s, 2)

	if err := s.Revert(); err != nil {
		t.Fatalf("revert: %v", err)
	}
	st, _ := s.State()
	if st.Committed.Version != 1 || st.Staged.Present || st.Pending != nil {
		t.Fatalf("after revert: %+v", st)
	}
	// Nothing left to revert to: stable sentinel.
	if err := s.Revert(); !errors.Is(err, ErrNothingToRevert) {
		t.Fatalf("second revert got %v want ErrNothingToRevert", err)
	}
	// Revert refuses while an update is pending.
	round(t, s, 2)
	if err := s.Stage(slot(3), []byte{3}); err != nil {
		t.Fatal(err)
	}
	if err := s.Revert(); err == nil {
		t.Fatal("revert during pending update must be refused")
	}
}

func TestBootSweepsInterruptedHistoryCleanup(t *testing.T) {
	s, dir := openStore(t)
	defer s.Close()
	_ = s.FactoryInit(slot(1))
	round(t, s, 2) // committed v2, retained v1

	// Crash while overwriting the retained v1 slot with v3 (after the slot
	// metadata file was replaced but before state.json was persisted).
	err := s.Stage(slot(3), []byte{3}, WithFaultHook(func(step string) error {
		if step == "stage.state" {
			return errors.New("power loss")
		}
		return nil
	}))
	if err == nil {
		t.Fatal("expected injected fault")
	}
	s.Close()

	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rolledBack, err := s2.RecoverOnBoot()
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack {
		t.Fatal("no trial was active; must not report rollback")
	}
	st, _ := s2.State()
	if st.Committed.Version != 2 {
		t.Fatalf("device must stay on known-good v2, got %d", st.Committed.Version)
	}
	if st.Staged.Present {
		t.Fatalf("inconsistent retained slot must be pruned, got %+v", st.Staged)
	}
	// The device must accept the interrupted upgrade again.
	round(t, s2, 3)
	st, _ = s2.State()
	if st.Committed.Version != 3 {
		t.Fatalf("retry after interrupted cleanup: committed=%d want 3", st.Committed.Version)
	}
	t.Logf("scenario=interrupted-cleanup recovered_to=2 then upgraded_to=%d", st.Committed.Version)
}

func TestHistoryStaysBoundedOverManyRounds(t *testing.T) {
	s, dir := openStore(t)
	defer s.Close()
	_ = s.FactoryInit(slot(1))
	for v := uint64(2); v <= 12; v++ {
		round(t, s, v)
	}
	st, _ := s.State()
	if st.Committed.Version != 12 || st.Staged.Version != 11 {
		t.Fatalf("after 11 rounds: committed=%d retained=%d", st.Committed.Version, st.Staged.Version)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	want := []string{"lock", "slot-A.bin", "slot-A.json", "slot-B.bin", "slot-B.json", "state.json"}
	if len(names) != len(want) {
		t.Fatalf("on-disk files must stay bounded: got %v want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("on-disk files must stay bounded: got %v want %v", names, want)
		}
	}
	t.Logf("scenario=bounded-history rounds=11 files=%v", names)
}

// TestReadReconcilesStateWithDisk simulates the interrupted-cleanup window
// directly: state.json still records the retained v1 slot, but the slot's
// on-disk metadata was already overwritten by the next stage. Any read must
// reconcile the two instead of reporting (or rolling back to) a version whose
// payload is no longer on disk.
func TestReadReconcilesStateWithDisk(t *testing.T) {
	s, dir := openStore(t)
	_ = s.FactoryInit(slot(1))
	round(t, s, 2) // committed v2, retained v1 in the inactive slot
	s.Close()

	// Crash window: the inactive slot's meta file was replaced by a v3 stage,
	// state.json was never updated. After round(2) the active slot is B, so
	// the retained v1 lives in slot A.
	bad := slot(3)
	bad.Present = true
	writeSlotMeta(t, dir, "A", bad)

	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	st, err := s2.State()
	if err != nil {
		t.Fatalf("state must be readable: %v", err)
	}
	if st.Committed.Version != 2 {
		t.Fatalf("committed=%d want 2", st.Committed.Version)
	}
	if st.Staged.Present {
		t.Fatalf("stale retained slot must be pruned on read, got %+v", st.Staged)
	}
	// Persisted: a second open sees the same reconciled state.
	s2.Close()
	s3, err := Open(dir, "d1")
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	st3, _ := s3.State()
	if st3.Committed.Version != 2 || st3.Staged.Present {
		t.Fatalf("reconciled state must persist, got %+v", st3)
	}
	// And the next upgrade reuses the slot normally.
	round(t, s3, 3)
	st4, _ := s3.State()
	if st4.Committed.Version != 3 || !st4.Staged.Present || st4.Staged.Version != 2 {
		t.Fatalf("chain must continue after reconcile, got %+v", st4)
	}
	t.Logf("scenario=read-reconcile committed=%d retained=%d", st4.Committed.Version, st4.Staged.Version)
}
