package device

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// lockFileName is the advisory lock serializing whole-device update
// transactions across processes (e.g. two CLI invocations started at the same
// time). It is never part of the crash-safe state machine.
const lockFileName = "update.lock"

// ErrUpdateBusy is returned when a second process (or engine instance with
// its own file handle) already holds the device update lock.
var ErrUpdateBusy = errors.New("device: another update is in progress")

// lockMu serializes Lock/Unlock calls within one process for the same store.
type fileLock struct {
	mu sync.Mutex
	f  *os.File
}

// Lock acquires the device-wide advisory lock without blocking. It returns
// ErrUpdateBusy immediately when the lock is already held by another caller,
// so the loser of two concurrent update requests gets a stable rejection
// instead of being silently queued. The lock is re-entrant per Store: a
// second Lock by the same holder is a no-op balanced by Unlock.
func (s *Store) Lock() error {
	s.lock.mu.Lock()
	defer s.lock.mu.Unlock()
	if s.lock.f != nil {
		return nil
	}
	path := filepath.Join(s.dir, lockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("device: open lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return ErrUpdateBusy
		}
		return fmt.Errorf("device: acquire lock: %w", err)
	}
	s.lock.f = f
	return nil
}

// Unlock releases the device-wide advisory lock. It is a no-op when no lock
// is held by this store.
func (s *Store) Unlock() error {
	s.lock.mu.Lock()
	defer s.lock.mu.Unlock()
	if s.lock.f == nil {
		return nil
	}
	err := syscall.Flock(int(s.lock.f.Fd()), syscall.LOCK_UN)
	if closeErr := s.lock.f.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	s.lock.f = nil
	return err
}
