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
	if err := s.FactoryInit(slot(1)); err != nil {
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
	if err := s2.FactoryInit(slot(9)); err == nil {
		t.Fatal("second factory init must be refused")
	}
	s2.Close()
}

func TestStageIdempotentIdenticalContent(t *testing.T) {
	s, _ := openStore(t)
	defer s.Close()
	if err := s.FactoryInit(slot(1)); err != nil {
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
	if err := s.FactoryInit(slot(1)); err != nil {
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
	if err := s.FactoryInit(slot(1)); err != nil {
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
	_ = s.FactoryInit(slot(1))
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
	_ = s.FactoryInit(slot(1))
	s.Close()
	if _, err := Open(dir, "d2"); err == nil {
		t.Fatal("opening store with foreign model must fail")
	}
}
