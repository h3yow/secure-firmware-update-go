package device

import (
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
	lockFileName  = "store.lock"
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
	// Hold the cross-process lock for the whole open+recovery sequence so two
	// processes initializing or recovering the same device cannot interleave.
	lk, err := openDirLock(dir)
	if err != nil {
		return nil, err
	}
	if err := lk.acquire(); err != nil {
		return nil, err
	}
	if err := removeTemps(dir); err != nil {
		_ = lk.release()
		return nil, err
	}
	if err := s.loadOrInit(model); err != nil {
		_ = lk.release()
		return nil, err
	}
	// Reconcile against disk truth before anyone can use the store: opening a
	// device must never leave a reported version that disagrees with the slot
	// payload actually on disk.
	if err := s.reconcileLocked(); err != nil {
		_ = lk.release()
		return nil, err
	}
	if err := lk.release(); err != nil {
		return nil, err
	}
	s.lock = lk
	return s, nil
}

// Close releases store resources and shuts the cross-process lock file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock != nil {
		lk := s.lock
		s.lock = nil
		if err := lk.close(); err != nil {
			return err
		}
	}
	return nil
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

func (s *Store) loadOrInit(model string) error {
	b, err := readStateFile(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		s.inner = internalState{Model: model, ActiveSlot: slotA, Slots: map[string]SlotState{}}
		return s.persistLocked()
	}
	if err != nil {
		return err
	}
	var in internalState
	if err := unmarshalState(b, &in); err != nil {
		return err
	}
	if in.Schema != 1 {
		return errUnsupportedSchema(in.Schema)
	}
	if in.Model != model {
		return fmt.Errorf("device: store belongs to model %q, asked for %q", in.Model, model)
	}
	if in.ActiveSlot != slotA && in.ActiveSlot != slotB {
		return errBadActiveSlot(in.ActiveSlot)
	}
	if in.Slots == nil {
		in.Slots = map[string]SlotState{}
	}
	s.inner = in
	return nil
}

func readStateFile(dir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, stateFileName))
}

func unmarshalState(b []byte, in *internalState) error {
	if err := json.Unmarshal(b, in); err != nil {
		return fmt.Errorf("device: corrupt state file: %w", err)
	}
	return nil
}

func errUnsupportedSchema(n int) error {
	return fmt.Errorf("device: unsupported state schema %d", n)
}

func errBadActiveSlot(name string) error {
	return fmt.Errorf("device: corrupt active slot %q", name)
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
// slot is "Committed", the inactive slot is "Staged". Opening the
// transaction first reconciles state.json with the slot files on disk, so
// the returned view can never disagree with what the device would boot.
func (s *Store) State() (State, error) {
	tx, err := s.Begin()
	if err != nil {
		return State{}, err
	}
	out := tx.Snapshot()
	if err := tx.Commit(); err != nil {
		return State{}, err
	}
	return out, nil
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

// FactoryInit writes the initial known-good firmware (metadata + payload)
// into the active slot. Only allowed on a store without a committed image.
// The payload is written so the factory slot passes the same on-disk hash
// verification as every later staged slot.
func (s *Store) FactoryInit(init SlotState, payload []byte) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	defer tx.Abort()
	if cur := s.inner.Slots[s.inner.ActiveSlot]; cur.Present {
		return errors.New("device: factory init refused, committed firmware already present")
	}
	if len(payload) == 0 {
		return errors.New("device: factory init needs a non-empty payload")
	}
	init.Present = true
	if init.InstalledAt.IsZero() {
		init.InstalledAt = time.Now().UTC()
	}
	if err := s.writeSlotFilesLocked(s.inner.ActiveSlot, init, payload, nil); err != nil {
		return err
	}
	s.inner.Slots[s.inner.ActiveSlot] = init
	if err := s.persistLocked(); err != nil {
		return err
	}
	return tx.Commit()
}
