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
// "activate.state", "confirm.state", "rollback.state", "boot.state".
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

// Stage writes the payload into the inactive slot.
//
// Retention policy: the device keeps at most two versions — the running
// version in the active slot and one rollback-capable known-good version in
// the inactive slot. When no update is pending, the inactive slot holds that
// retained previous known-good version and a new update overwrites it
// directly; this is what lets the device chain upgrades v1 -> v2 -> v3 ...
// without ever accumulating more slots or requiring a wipe.
//
// Re-staging the exact same (version, hash) content while an update is
// pending is a successful no-op so crash retries are idempotent; staging
// different content while an update is pending is rejected.
func (s *Store) Stage(meta SlotState, payload []byte, opts ...Option) error {
	o := resolve(opts)
	s.mu.Lock()
	defer s.mu.Unlock()

	meta.Present = true
	if meta.InstalledAt.IsZero() {
		meta.InstalledAt = time.Now().UTC()
	}
	target := otherSlot(s.inner.ActiveSlot)

	if existing := s.inner.Slots[target]; existing.Present && s.inner.Pending != nil {
		same := existing.Version == meta.Version && bytes.Equal(existing.PayloadHash, meta.PayloadHash)
		if !same {
			return fmt.Errorf("device: slot %s already holds version %d; reject conflicting stage of %d", target, existing.Version, meta.Version)
		}
		// identical re-stage: idempotent success
		return nil
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
// rollback state. It is safe to call whether or not the trial was activated.
//
// The retained previous known-good version lives in the other physical slot;
// its files must survive (they are the rollback target), so the discarded
// trial/staged content is identified by version identity rather than by slot
// name.
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
		s.inner.ActiveSlot = slotWithVersion(s.inner.Slots, s.inner.Pending.FromVersion, otherSlot(s.inner.ActiveSlot))
	}
	if err := discardVersionLocked(s, s.inner.Pending.ToVersion, s.inner.ActiveSlot); err != nil {
		return err
	}
	if err := o.fire("rollback.state"); err != nil {
		return err
	}
	s.inner.Pending = nil
	s.inner.BootCount = 0
	return s.persistLocked()
}

// discardVersionLocked removes slot state/files belonging to discardVersion,
// skipping keepSlot (the active/known-good slot) and any slot that holds a
// different version.
func discardVersionLocked(s *Store, discardVersion uint64, keepSlot string) error {
	for name, st := range s.inner.Slots {
		if name == keepSlot || !st.Present || st.Version != discardVersion {
			continue
		}
		if err := s.removeSlotFilesLocked(name); err != nil {
			return err
		}
		delete(s.inner.Slots, name)
	}
	return nil
}

// RollbackRetained flips the boot pointer back to the retained previous
// known-good version in the inactive slot. It applies when no trial update is
// pending (the running version was already confirmed). The two slots simply
// exchange roles: after the flip the formerly running version remains on
// device as the retained rollback target, so capacity stays at two versions
// and a second rollback is rejected without any state change.
//
// It returns ErrNotPending when there is no strictly older known-good version
// retained to return to.
func (s *Store) RollbackRetained(opts ...Option) error {
	o := resolve(opts)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inner.Pending != nil {
		return ErrNotPending
	}
	active := s.inner.Slots[s.inner.ActiveSlot]
	retained := s.inner.Slots[otherSlot(s.inner.ActiveSlot)]
	if !retained.Present || retained.Version >= active.Version {
		return ErrNotPending
	}
	if err := o.fire("rollback.state"); err != nil {
		return err
	}
	s.inner.ActiveSlot = otherSlot(s.inner.ActiveSlot)
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

// RecoverOnBoot performs boot-time policy: a trial image that activated but
// was never confirmed (power loss / crash / bad image) is rolled back so the
// device always ends on a known-good version. Returns true when a rollback
// occurred. Confirming after a clean trial boot clears pending.
func (s *Store) RecoverOnBoot(opts ...Option) (bool, error) {
	o := resolve(opts)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inner.Pending == nil {
		return false, nil
	}
	active := s.inner.Slots[s.inner.ActiveSlot]
	if active.Version != s.inner.Pending.ToVersion {
		// Staged but never activated (power loss before activate): discard
		// the staged content by version identity; the known-good slot files
		// are the rollback target and must be preserved.
		if err := discardVersionLocked(s, s.inner.Pending.ToVersion, s.inner.ActiveSlot); err != nil {
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
	prev := slotWithVersion(s.inner.Slots, s.inner.Pending.FromVersion, otherSlot(s.inner.ActiveSlot))
	if st, ok := s.inner.Slots[prev]; !ok || !st.Present || st.Version != s.inner.Pending.FromVersion {
		return false, errors.New("device: cannot recover, previous known-good slot missing")
	}
	s.inner.ActiveSlot = prev
	if err := discardVersionLocked(s, s.inner.Pending.ToVersion, s.inner.ActiveSlot); err != nil {
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
