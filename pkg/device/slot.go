package device

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FaultHook allows tests to inject a crash/failure at a named step.
// Step names: "stage.meta", "stage.blob", "stage.state",
// "activate.state", "confirm.state", "rollback.state", "revert.state",
// "boot.state".
type FaultHook func(step string) error

type options struct {
	fault FaultHook
}

// Option configures a mutating store operation.
type Option func(*options)

// WithFaultHook injects a crash/failure at a named internal step.
func WithFaultHook(h FaultHook) Option {
	return func(o *options) { o.fault = h }
}

func resolve(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func (o options) fire(step string) error {
	if o.fault != nil {
		if err := o.fault(step); err != nil {
			return fmt.Errorf("injected fault at %s: %w", step, err)
		}
	}
	return nil
}

// writeFileAtomic writes data to name via temp+fsync+rename.
func (s *Store) writeFileAtomic(name string, data []byte) error {
	tmp := name + tmpSuffix
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

// writeSlotFilesLocked writes a slot's metadata and payload. Each file is
// replaced atomically; the active slot's files are never touched during
// staging.
func (s *Store) writeSlotFilesLocked(slot string, meta SlotState, payload []byte, fault FaultHook) error {
	fire := func(step string) error {
		if fault != nil {
			if err := fault(step); err != nil {
				return err
			}
		}
		return nil
	}
	if err := fire("stage.meta"); err != nil {
		return err
	}
	metaBytes, err := json.MarshalIndent(&meta, "", "  ")
	if err != nil {
		return err
	}
	if err := s.writeFileAtomic(filepath.Join(s.dir, "slot-"+slot+".json"), metaBytes); err != nil {
		return err
	}
	if err := fire("stage.blob"); err != nil {
		return err
	}
	if payload != nil {
		if err := s.writeFileAtomic(filepath.Join(s.dir, "slot-"+slot+".bin"), payload); err != nil {
			return err
		}
	}
	return nil
}

// Stage writes the payload into the inactive slot. The inactive slot may be
// in one of three states:
//
//   - empty: the payload is written fresh;
//   - holding a pending (staged, not yet activated) update: re-staging the
//     exact same (version, hash) content is an idempotent no-op, staging
//     different content is rejected with ErrSlotConflict so two concurrent
//     updates can never both take effect;
//   - holding the retained previous known-good version (no update pending):
//     it is overwritten. This is the bounded-history cleanup: the device
//     keeps at most "current + previous", and reclaiming the oldest slot is
//     fused into the next staging. The overwrite is crash-safe because each
//     file is replaced atomically and state.json is updated last; a crash
//     mid-overwrite is detected and pruned by RecoverOnBoot.
func (s *Store) Stage(meta SlotState, payload []byte, opts ...Option) error {
	o := resolve(opts)
	s.mu.Lock()
	defer s.mu.Unlock()

	meta.Present = true
	if meta.InstalledAt.IsZero() {
		meta.InstalledAt = time.Now().UTC()
	}
	target := otherSlot(s.inner.ActiveSlot)

	if p := s.inner.Pending; p != nil {
		if p.ToVersion == meta.Version && bytes.Equal(p.StagedHash, meta.PayloadHash) {
			// The pending update itself is being (re-)staged: whether it is
			// still sitting in the inactive slot or was already activated,
			// repeating it is an idempotent no-op.
			return nil
		}
		if existing := s.inner.Slots[target]; existing.Present {
			return fmt.Errorf("device: slot %s holds pending version %d, cannot stage %d: %w", target, existing.Version, meta.Version, ErrSlotConflict)
		}
	}

	if err := s.writeSlotFilesLocked(target, meta, payload, o.fault); err != nil {
		return err
	}
	s.inner.Slots[target] = meta
	from := s.inner.Slots[s.inner.ActiveSlot]
	s.inner.Pending = &PendingActivation{
		FromVersion: from.Version,
		ToVersion:   meta.Version,
		StagedHash:  append([]byte(nil), meta.PayloadHash...),
		CreatedAt:   time.Now().UTC(),
	}
	if err := o.fire("stage.state"); err != nil {
		return err
	}
	if err := s.persistLocked(); err != nil {
		return err
	}
	return nil
}

// Activate flips the boot pointer to the staged slot in a single atomic state
// write. The new image runs as a trial: it must be confirmed at the next boot,
// otherwise RecoverOnBoot rolls back.
func (s *Store) Activate(opts ...Option) error {
	o := resolve(opts)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inner.Pending == nil {
		return ErrNotPending
	}
	if active := s.inner.Slots[s.inner.ActiveSlot]; active.Present &&
		active.Version == s.inner.Pending.ToVersion &&
		bytes.Equal(active.PayloadHash, s.inner.Pending.StagedHash) {
		// Already activated (e.g. a duplicated install request): idempotent.
		return nil
	}
	inactive := otherSlot(s.inner.ActiveSlot)
	staged, ok := s.inner.Slots[inactive]
	if !ok || !staged.Present {
		return errors.New("device: pending activation but staged slot content is missing")
	}
	if !bytes.Equal(staged.PayloadHash, s.inner.Pending.StagedHash) {
		return errors.New("device: staged payload changed between stage and activate")
	}
	if err := o.fire("activate.state"); err != nil {
		return err
	}
	s.inner.ActiveSlot = inactive
	s.inner.BootCount = 0
	if err := s.persistLocked(); err != nil {
		return err
	}
	return nil
}

// Confirm marks the active trial image as good and clears the rollback state.
func (s *Store) Confirm(opts ...Option) error {
	o := resolve(opts)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inner.Pending == nil {
		return ErrNotPending
	}
	if err := o.fire("confirm.state"); err != nil {
		return err
	}
	s.inner.Pending = nil
	s.inner.BootCount = 0
	if err := s.persistLocked(); err != nil {
		return err
	}
	return nil
}

// Rollback restores the previous known-good slot atomically and clears the
// staged trial. It is safe to call whether or not the trial was activated.
func (s *Store) Rollback(opts ...Option) error {
	o := resolve(opts)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inner.Pending == nil {
		return ErrNotPending
	}
	active := s.inner.Slots[s.inner.ActiveSlot]
	if active.Version != s.inner.Pending.ToVersion {
		// Trial was staged but never activated: pointer already sits on the
		// known-good slot; just discard staging metadata.
		s.inner.ActiveSlot = slotWithVersion(s.inner.Slots, s.inner.Pending.FromVersion, s.inner.ActiveSlot)
	} else {
		s.inner.ActiveSlot = otherSlot(s.inner.ActiveSlot)
	}
	inactive := otherSlot(s.inner.ActiveSlot)
	delete(s.inner.Slots, inactive)
	if err := s.removeSlotFilesLocked(inactive); err != nil {
		return err
	}
	if err := o.fire("rollback.state"); err != nil {
		return err
	}
	s.inner.Pending = nil
	s.inner.BootCount = 0
	return s.persistLocked()
}

func slotWithVersion(slots map[string]SlotState, version uint64, fallback string) string {
	for name, st := range slots {
		if st.Present && st.Version == version {
			return name
		}
	}
	return fallback
}

func (s *Store) removeSlotFilesLocked(slot string) error {
	for _, suffix := range []string{".json", ".bin"} {
		name := filepath.Join(s.dir, "slot-"+slot+suffix)
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Revert flips the device back to the retained previous known-good version
// after the current one was already confirmed. The slot being left is
// discarded, so the device still holds at most two versions afterwards.
// It refuses while an update is pending (use Rollback for trials) and when
// no previous version is retained (ErrNothingToRevert).
func (s *Store) Revert(opts ...Option) error {
	o := resolve(opts)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inner.Pending != nil {
		return errors.New("device: update pending, use Rollback instead of Revert")
	}
	inactive := otherSlot(s.inner.ActiveSlot)
	prev, ok := s.inner.Slots[inactive]
	if !ok || !prev.Present {
		return ErrNothingToRevert
	}
	abandoned := s.inner.ActiveSlot
	if err := o.fire("revert.state"); err != nil {
		return err
	}
	s.inner.ActiveSlot = inactive
	delete(s.inner.Slots, abandoned)
	if err := s.removeSlotFilesLocked(abandoned); err != nil {
		return err
	}
	s.inner.BootCount = 0
	return s.persistLocked()
}

// readSlotMetaLocked reads the on-disk metadata of one slot.
func (s *Store) readSlotMetaLocked(slot string) (SlotState, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, "slot-"+slot+".json"))
	if err != nil {
		return SlotState{}, err
	}
	var meta SlotState
	if err := json.Unmarshal(b, &meta); err != nil {
		return SlotState{}, err
	}
	return meta, nil
}

// pruneInactiveLocked drops the inactive slot's metadata and files. Used when
// a crash interrupted the bounded-history cleanup (overwrite during Stage)
// and left state.json and the slot files disagreeing.
func (s *Store) pruneInactiveLocked() error {
	inactive := otherSlot(s.inner.ActiveSlot)
	delete(s.inner.Slots, inactive)
	return s.removeSlotFilesLocked(inactive)
}

// inactiveConsistentLocked reports whether the retained previous version's
// on-disk metadata still matches state.json. A mismatch means a crash or
// write failure interrupted the overwrite of the old slot mid-Stage.
func (s *Store) inactiveConsistentLocked() bool {
	inactive := otherSlot(s.inner.ActiveSlot)
	recorded, ok := s.inner.Slots[inactive]
	if !ok || !recorded.Present {
		return true // nothing retained: trivially consistent
	}
	onDisk, err := s.readSlotMetaLocked(inactive)
	if err != nil {
		return false
	}
	return onDisk.Version == recorded.Version && bytes.Equal(onDisk.PayloadHash, recorded.PayloadHash)
}

// RecoverOnBoot performs boot-time policy: a trial image that activated but
// was never confirmed (power loss / crash / bad image) is rolled back so the
// device always ends on a known-good version. Returns true when a rollback
// occurred. Confirming after a clean trial boot clears pending.
//
// It also sweeps the bounded version history: if a crash interrupted the
// cleanup (overwrite) of the oldest retained slot, the inconsistent slot is
// pruned so the device keeps booting the committed known-good version and
// future upgrades are never blocked by leftover history.
func (s *Store) RecoverOnBoot(opts ...Option) (bool, error) {
	o := resolve(opts)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inner.Pending == nil {
		if !s.inactiveConsistentLocked() {
			if err := s.pruneInactiveLocked(); err != nil {
				return false, err
			}
			s.inner.BootCount = 0
			if err := o.fire("boot.state"); err != nil {
				return false, err
			}
			return false, s.persistLocked()
		}
		return false, nil
	}
	active := s.inner.Slots[s.inner.ActiveSlot]
	if active.Version != s.inner.Pending.ToVersion {
		// Staged but never activated (power loss before activate): discard.
		inactive := otherSlot(s.inner.ActiveSlot)
		delete(s.inner.Slots, inactive)
		if err := s.removeSlotFilesLocked(inactive); err != nil {
			return false, err
		}
		s.inner.Pending = nil
		s.inner.BootCount = 0
		if err := o.fire("boot.state"); err != nil {
			return false, err
		}
		return false, s.persistLocked()
	}

	// Trial is active. Boot #1: count it and leave the trial running; if the
	// device reboots again without Confirm, roll back. This models a watchdog
	// / failed-health-check boot.
	s.inner.BootCount++
	if s.inner.BootCount <= 1 {
		if err := o.fire("boot.state"); err != nil {
			return false, err
		}
		return false, s.persistLocked()
	}

	// Second unconfirmed boot: automatic rollback.
	prev := otherSlot(s.inner.ActiveSlot)
	if st, ok := s.inner.Slots[prev]; !ok || !st.Present || st.Version != s.inner.Pending.FromVersion {
		return false, errors.New("device: cannot recover, previous known-good slot missing")
	}
	s.inner.ActiveSlot = prev
	delete(s.inner.Slots, otherSlot(s.inner.ActiveSlot))
	if err := s.removeSlotFilesLocked(otherSlot(s.inner.ActiveSlot)); err != nil {
		return false, err
	}
	s.inner.Pending = nil
	s.inner.BootCount = 0
	if err := o.fire("boot.state"); err != nil {
		return false, err
	}
	return true, s.persistLocked()
}

// ReadPayload returns the payload bytes of the currently active slot.
func (s *Store) ReadPayload() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(s.dir, "slot-"+s.inner.ActiveSlot+".bin"))
	if err != nil {
		return nil, fmt.Errorf("device: read active payload: %w", err)
	}
	return b, nil
}
