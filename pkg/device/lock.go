package device

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockFileName is the cross-process mutex for one device directory. Every
// store operation (reads included) is bracketed by an exclusive flock on this
// file, so two independent processes can never interleave read-modify-write
// cycles on state.json: exactly one of them observes the other's committed
// changes.
const lockFileName = "lock"

// beginOpLocked serializes one store operation across processes. Call with
// s.mu already held; pair with endOpLocked. After it returns, s.inner reflects
// the newest committed on-disk state (reloaded after acquiring the lock, so
// changes committed by other processes are visible) and has been reconciled
// with the slot files actually present on disk.
func (s *Store) beginOpLocked() error {
	if s.lockFile == nil {
		return errors.New("device: store is closed")
	}
	if err := syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("device: acquire store lock: %w", err)
	}
	if err := s.reloadLocked(); err != nil {
		_ = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
		return err
	}
	return nil
}

// endOpLocked releases the cross-process lock.
func (s *Store) endOpLocked() {
	if s.lockFile != nil {
		_ = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
	}
}

// reloadLocked replaces the in-memory state with the committed on-disk state
// and reconciles it with the slot files on disk. A store that was never
// initialized (no state.json yet) is initialized here.
func (s *Store) reloadLocked() error {
	path := filepath.Join(s.dir, stateFileName)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if s.inner.Slots != nil {
			return errors.New("device: state file missing from initialized store")
		}
		s.inner = internalState{Model: s.model, ActiveSlot: slotA, Slots: map[string]SlotState{}}
		return s.persistLocked()
	}
	if err != nil {
		return fmt.Errorf("device: read state: %w", err)
	}
	var in internalState
	if err := json.Unmarshal(b, &in); err != nil {
		return fmt.Errorf("device: corrupt state file: %w", err)
	}
	if in.Schema != 1 {
		return fmt.Errorf("device: unsupported state schema %d", in.Schema)
	}
	if in.Model != s.model {
		return fmt.Errorf("device: store belongs to model %q, asked for %q", in.Model, s.model)
	}
	if in.ActiveSlot != slotA && in.ActiveSlot != slotB {
		return fmt.Errorf("device: corrupt active slot %q", in.ActiveSlot)
	}
	if in.Slots == nil {
		in.Slots = map[string]SlotState{}
	}
	s.inner = in
	return s.reconcileLocked()
}

// reconcileLocked aligns the loaded state with the slot files actually on
// disk before the state is read or used. When no update is pending, the
// inactive slot may only hold the retained previous known-good version; if a
// crash or write failure interrupted the overwrite of that slot mid-Stage,
// state.json and the on-disk slot metadata disagree. The disagreement is
// resolved in favour of the committed known-good version: the inconsistent
// slot is pruned (never booted, never reported as a rollback target) and the
// pruned state is persisted, so every subsequent read agrees with disk.
//
// While an update is pending the inactive slot legitimately holds either the
// staged trial or the previous known-good version needed for rollback; that
// case is owned by RecoverOnBoot and is left untouched here.
func (s *Store) reconcileLocked() error {
	if s.inner.Pending != nil {
		return nil
	}
	if s.inactiveConsistentLocked() {
		return nil
	}
	if err := s.pruneInactiveLocked(); err != nil {
		return err
	}
	s.inner.BootCount = 0
	return s.persistLocked()
}
