package device

import (
	"errors"
	"testing"
)

// TestUpdateLockSerializesInstances models two CLI processes opening the same
// device directory at once: the first takes the non-blocking device lock, the
// second must get ErrUpdateBusy rather than wait or corrupt state. Releasing the
// lock lets the next caller acquire it (simulating the process finishing).
func TestUpdateLockSerializesInstances(t *testing.T) {
	s1, dir := openStore(t)
	defer s1.Close()
	if err := s1.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := s1.Lock(); err != nil {
		t.Fatalf("first lock: %v", err)
	}
	// Re-entrant for the same holder.
	if err := s1.Lock(); err != nil {
		t.Fatalf("re-entrant lock: %v", err)
	}

	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.Lock(); !errors.Is(err, ErrUpdateBusy) {
		t.Fatalf("second instance lock = %v, want ErrUpdateBusy", err)
	}

	// First process finishes and releases; the lock is immediately reusable.
	if err := s1.Unlock(); err != nil {
		t.Fatal(err)
	}
	if err := s2.Lock(); err != nil {
		t.Fatalf("lock after release: %v", err)
	}
}

// TestLockReleasedOnClose ensures a crashed-or-finished process cannot leak the
// lock: closing the store releases it for the next opener.
func TestLockReleasedOnClose(t *testing.T) {
	s1, dir := openStore(t)
	if err := s1.FactoryInit(slot(1), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := s1.Lock(); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir, "d1")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.Lock(); err != nil {
		t.Fatalf("lock must be free after Close: %v", err)
	}
}
