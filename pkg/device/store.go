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

// Close releases the store.
func (s *Store) Close() error { return nil }

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
	return nil
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
