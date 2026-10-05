package device

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	stateFileName = "state.json"
	tmpSuffix     = ".tmp"
	slotA         = "A"
	slotB         = "B"
)

// internalState is the crash-safe on-disk layout: two physical slots plus an
// atomic boot pointer. Activating an update only flips the pointer inside the
// atomically replaced state.json, so a power loss can never produce a slot
// that is half-new/half-old.
type internalState struct {
	Schema     int                  `json:"schema"`
	Model      string               `json:"model"`
	ActiveSlot string               `json:"active_slot"`
	Slots      map[string]SlotState `json:"slots"`
	Pending    *PendingActivation   `json:"pending,omitempty"`
	BootCount  int                  `json:"boot_count"`
}

// Open opens (or initializes) a device store in dir for the given model. The
// open itself is serialized on the cross-process lock: leftover temp files
// from an interrupted write are removed while holding it, then the state is
// loaded and reconciled with the slot files on disk, so the store is usable
// and consistent from the first call on.
func Open(dir, model string) (*Store, error) {
	if model == "" {
		return nil, errors.New("device: empty model")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("device: mkdir: %w", err)
	}
	lf, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("device: open lock file: %w", err)
	}
	s := &Store{dir: dir, model: model, mu: &sync.Mutex{}, lockFile: lf, inner: internalState{}}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		_ = lf.Close()
		return nil, fmt.Errorf("device: acquire store lock: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) }()
	if err := removeTemps(dir); err != nil {
		_ = lf.Close()
		return nil, err
	}
	if err := s.reloadLocked(); err != nil {
		_ = lf.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the store lock and the lock file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockFile == nil {
		return nil
	}
	_ = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
	err := s.lockFile.Close()
	s.lockFile = nil
	return err
}

func removeTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), tmpSuffix) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return fmt.Errorf("device: cleanup temp: %w", err)
			}
		}
	}
	return nil
}

// persistLocked writes state atomically: temp file, fsync, rename. A crash at
// any point leaves either the previous state or the new state, never a tear.
// The temp name is unique to this process and operation, so two processes can
// never interleave writes into the same temp file.
func (s *Store) persistLocked() error {
	s.inner.Schema = 1
	b, err := json.MarshalIndent(&s.inner, "", "  ")
	if err != nil {
		return fmt.Errorf("device: marshal state: %w", err)
	}
	return s.writeFileAtomic(filepath.Join(s.dir, stateFileName), b)
}

// State returns an external snapshot view of the durable state: the active
// slot is "Committed", the inactive slot is "Staged". The state is re-read
// from disk and reconciled with the slot files before the snapshot is taken,
// so the view always agrees with what is actually on disk.
func (s *Store) State() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.beginOpLocked(); err != nil {
		return State{}, err
	}
	defer s.endOpLocked()
	return s.viewLocked(), nil
}

func (s *Store) viewLocked() State {
	inactive := otherSlot(s.inner.ActiveSlot)
	out := State{
		Model:     s.inner.Model,
		Committed: s.inner.Slots[s.inner.ActiveSlot],
		Staged:    s.inner.Slots[inactive],
		Pending:   s.inner.Pending,
		BootCount: s.inner.BootCount,
	}
	if out.Pending != nil {
		p := *s.inner.Pending
		out.Pending = &p
	}
	return out
}

func otherSlot(x string) string {
	if x == slotA {
		return slotB
	}
	return slotA
}

// FactoryInit writes the initial known-good firmware into slot A. Only
// allowed on a store without a committed image.
func (s *Store) FactoryInit(init SlotState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.beginOpLocked(); err != nil {
		return err
	}
	defer s.endOpLocked()
	if cur := s.inner.Slots[s.inner.ActiveSlot]; cur.Present {
		return errors.New("device: factory init refused, committed firmware already present")
	}
	init.Present = true
	if init.InstalledAt.IsZero() {
		init.InstalledAt = time.Now().UTC()
	}
	if err := s.writeSlotFilesLocked(s.inner.ActiveSlot, init, nil, nil); err != nil {
		return err
	}
	s.inner.Slots[s.inner.ActiveSlot] = init
	return s.persistLocked()
}
