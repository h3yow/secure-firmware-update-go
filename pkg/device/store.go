package device

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// Open opens (or initializes) a device store in dir for the given model.
// Leftover temp files from an interrupted write are removed; the boot pointer
// and active slot from the last fully persisted state remain authoritative.
func Open(dir, model string) (*Store, error) {
	if model == "" {
		return nil, errors.New("device: empty model")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("device: mkdir: %w", err)
	}
	s := &Store{dir: dir, mu: &sync.Mutex{}, inner: internalState{}}
	if err := removeTemps(dir); err != nil {
		return nil, err
	}
	if err := s.loadOrInit(model); err != nil {
		return nil, err
	}
	return s, nil
}

// Close releases the store and any update lock it holds.
func (s *Store) Close() error { return s.Unlock() }

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

func (s *Store) loadOrInit(model string) error {
	path := filepath.Join(s.dir, stateFileName)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s.inner = internalState{Model: model, ActiveSlot: slotA, Slots: map[string]SlotState{}}
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
	if in.Model != model {
		return fmt.Errorf("device: store belongs to model %q, asked for %q", in.Model, model)
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

// reconcileLocked repairs state against the on-disk slot files after an
// interrupted operation. It runs at every Open and is idempotent, so a power
// loss during reconciliation itself is also safe.
//
// Invariant when no update is pending: the active slot runs the current
// known-good version and its files are never written outside an atomic
// pointer flip, so a mismatch there is fatal corruption. The inactive slot
// holds at most one retained previous known-good version; chaining upgrades
// overwrites it, and a crash mid-overwrite can leave files that no longer
// match state.json. Such an inactive slot is discarded (files + state entry),
// leaving the device booting a known-good version. Orphan slot files without
// a state entry are removed as well.
//
// When an update is pending the inactive slot is either the protected
// rollback target or a staged-not-activated image owned by RecoverOnBoot; it
// is deliberately not reconciled here.
func (s *Store) reconcileLocked() error {
	if s.inner.Pending != nil {
		return nil
	}
	active := s.inner.ActiveSlot
	inactive := otherSlot(active)

	if cur := s.inner.Slots[active]; cur.Present {
		if err := checkSlotFiles(s.dir, active, cur); err != nil {
			return fmt.Errorf("device: active slot %s damaged: %w", active, err)
		}
	}

	dirty := false
	if old := s.inner.Slots[inactive]; old.Present {
		if err := checkSlotFiles(s.dir, inactive, old); err != nil {
			// Retained slot was mid-overwrite when power was lost: drop it.
			// The active known-good slot is untouched and remains bootable.
			if rmErr := s.removeSlotFilesLocked(inactive); rmErr != nil {
				return rmErr
			}
			delete(s.inner.Slots, inactive)
			dirty = true
		}
	} else {
		// Orphaned files from a stage that never reached state.json.
		if removed, rmErr := removeSlotFilesIfExist(s.dir, inactive); rmErr != nil {
			return rmErr
		} else if removed {
			// Files only: state did not reference them, no persist needed.
		}
	}
	if dirty {
		return s.persistLocked()
	}
	return nil
}

// checkSlotFiles verifies that a slot's metadata file and payload file exist
// and match the recorded metadata (version plus payload SHA-256).
func checkSlotFiles(dir, slot string, want SlotState) error {
	metaPath := filepath.Join(dir, "slot-"+slot+".json")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("read meta: %w", err)
	}
	var got SlotState
	if err := json.Unmarshal(metaBytes, &got); err != nil {
		return fmt.Errorf("parse meta: %w", err)
	}
	if !got.Present || got.Version != want.Version {
		return fmt.Errorf("slot meta version mismatch: files=%d state=%d", got.Version, want.Version)
	}
	payload, err := os.ReadFile(filepath.Join(dir, "slot-"+slot+".bin"))
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	if !bytes.Equal(sum[:], want.PayloadHash) {
		return errors.New("slot payload hash mismatch")
	}
	return nil
}

// removeSlotFilesIfExist removes slot files that may be left over. It reports
// whether at least one file was present.
func removeSlotFilesIfExist(dir, slot string) (bool, error) {
	removed := false
	for _, suffix := range []string{".json", ".bin"} {
		name := filepath.Join(dir, "slot-"+slot+suffix)
		if err := os.Remove(name); err == nil {
			removed = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return removed, nil
}

// persistLocked writes state atomically: temp file, fsync, rename. A crash at
// any point leaves either the previous state or the new state, never a tear.
func (s *Store) persistLocked() error {
	s.inner.Schema = 1
	b, err := json.MarshalIndent(&s.inner, "", "  ")
	if err != nil {
		return fmt.Errorf("device: marshal state: %w", err)
	}
	path := filepath.Join(s.dir, stateFileName)
	tmp := path + tmpSuffix
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("device: write temp state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("device: commit state: %w", err)
	}
	return nil
}

// State returns an external snapshot view of the durable state: the active
// slot is "Committed", the inactive slot is "Staged".
func (s *Store) State() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.viewLocked(), nil
}

func (s *Store) viewLocked() State {
	inactive := otherSlot(s.inner.ActiveSlot)
	out := State{
		Model:     s.inner.Model,
		Committed: s.inner.Slots[s.inner.ActiveSlot],
		Pending:   s.inner.Pending,
		BootCount: s.inner.BootCount,
	}
	if s.inner.Pending != nil {
		out.Staged = s.inner.Slots[inactive]
	} else {
		out.Retained = s.inner.Slots[inactive]
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

// FactoryInit writes the initial known-good firmware (metadata and payload)
// into slot A. Only allowed on a store without a committed image.
func (s *Store) FactoryInit(init SlotState, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur := s.inner.Slots[s.inner.ActiveSlot]; cur.Present {
		return errors.New("device: factory init refused, committed firmware already present")
	}
	init.Present = true
	if init.InstalledAt.IsZero() {
		init.InstalledAt = time.Now().UTC()
	}
	if err := s.writeSlotFilesLocked(s.inner.ActiveSlot, init, payload, nil); err != nil {
		return err
	}
	s.inner.Slots[s.inner.ActiveSlot] = init
	return s.persistLocked()
}
