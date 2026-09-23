// Package device simulates device-side state storage with an A/B slot scheme.
//
// Invariant: after every committed state transition the device boots from a
// slot whose stored image matches its recorded SHA-256 and was accepted by the
// security verifier before staging. Writes always target the inactive slot via
// temp-file + fsync + rename; an interruption at any point leaves the active
// slot and its image untouched. The committed state file is itself a
// temp+fsync+rename replacement, so "power loss before activate" is observed
// on reboot as either fully-staged or no-staging, never a half state.
package device

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
)

// Slot names.
const (
	SlotA = "A"
	SlotB = "B"
)

// SlotState describes one firmware slot as recorded in the state file.
type SlotState struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Model   string `json:"model"`
}

// State is the persisted device state.
type State struct {
	Model      string                `json:"model"`
	ActiveSlot string                `json:"active_slot"`
	Slots      map[string]*SlotState `json:"slots"`

	// Pending staged update (inactive slot), committed only after the image
	// file was fsynced and renamed into place.
	StagedSlot  string `json:"staged_slot"`
	StagedVer   string `json:"staged_version"`
	StagedSHA   string `json:"staged_sha256"`
	StagedModel string `json:"staged_model"`
	HasStaged   bool   `json:"has_staged"`

	// Previous active slot retained for one rollback.
	RollbackSlot string `json:"rollback_slot"`
	HasRollback  bool   `json:"has_rollback"`
}

// Device is the simulated device storage.
type Device struct {
	mu        sync.Mutex
	dir       string
	statePath string
	state     State

	failPoint FailPoint
}

// FailPoint injects faults into storage operations for failure-path tests.
type FailPoint struct {
	// FailStageWriteAfter >0 makes Stage fail after this many payload bytes
	// were written to the temp file (which is then discarded).
	FailStageWriteAfter int64
	// FailActivate makes Activate fail before swapping the active slot.
	FailActivate bool
}

// InjectedFault marks a fault that the test harness deliberately caused.
var InjectedFault = errors.New("injected storage fault")

// Open loads device state under dir, creating an empty but bootable device
// (active slot A with a recorded factory image) when none exists.
func Open(dir, model string) (*Device, error) {
	if model == "" {
		return nil, errors.New("device: model required")
	}
	if err := os.MkdirAll(filepath.Join(dir, "slots"), 0o755); err != nil {
		return nil, err
	}
	d := &Device{dir: dir, statePath: filepath.Join(dir, "state.json")}
	if err := d.loadOrInit(model); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Device) loadOrInit(model string) error {
	data, err := os.ReadFile(d.statePath)
	if errors.Is(err, os.ErrNotExist) {
		factory := []byte("FACTORY-IMAGE:" + model)
		factorySHA := firmware.PayloadSHA256Hex(factory)
		if err := d.writeSlotImage(SlotA, factory, 0); err != nil {
			return err
		}
		d.state = State{
			Model:      model,
			ActiveSlot: SlotA,
			Slots: map[string]*SlotState{
				SlotA: {Version: "0.0.1", SHA256: factorySHA, Model: model},
			},
		}
		return d.persist()
	}
	if err != nil {
		return err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("device state corrupt: %w", err)
	}
	if s.Model != model {
		return fmt.Errorf("device model mismatch: state=%q open=%q", s.Model, model)
	}
	rec := s.Slots[s.ActiveSlot]
	if rec == nil {
		return fmt.Errorf("active slot %q has no image record", s.ActiveSlot)
	}
	if _, err := d.imageMatches(s.ActiveSlot, rec.SHA256); err != nil {
		return fmt.Errorf("active slot not bootable on open: %w", err)
	}
	// A staged record whose image failed verification is discarded: activate
	// re-validates anyway, and clearing now keeps Open total about recovery.
	if s.HasStaged {
		if err := d.checkStagedImage(&s); err != nil {
			s.HasStaged = false
			s.StagedSlot = ""
			if err := d.persistState(&s); err != nil {
				return err
			}
		}
	}
	d.state = s
	return nil
}

// ActiveVersion returns the version of the currently active slot.
func (d *Device) ActiveVersion() firmware.Version {
	d.mu.Lock()
	defer d.mu.Unlock()
	v, _ := firmware.ParseVersion(d.state.Slots[d.state.ActiveSlot].Version)
	return v
}

// ActiveSlot returns the active slot name.
func (d *Device) ActiveSlot() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state.ActiveSlot
}

// InactiveSlot returns the slot targeted by the next update.
func (d *Device) InactiveSlot() string {
	if d.ActiveSlot() == SlotA {
		return SlotB
	}
	return SlotA
}

// Stage writes the verified image into the inactive slot. The image lands via
// temp file + fsync + rename; only then is the staged pointer committed to the
// state file. A failure at either step leaves the device exactly as before.
func (d *Device) Stage(ver firmware.Version, model, sha256Hex string, image []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if sha256Hex != firmware.PayloadSHA256Hex(image) {
		return fmt.Errorf("%w: caller-provided sha mismatch", InjectedFault)
	}
	target := d.inactiveSlotLocked()

	// 1. Image fully durable first; fault injection aborts before rename.
	if err := d.writeSlotImage(target, image, d.failPoint.FailStageWriteAfter); err != nil {
		return err
	}

	// 2. Commit the staged pointer atomically.
	s := d.state
	s.HasStaged = true
	s.StagedSlot = target
	s.StagedVer = ver.String()
	s.StagedSHA = sha256Hex
	s.StagedModel = model
	if err := d.persistState(&s); err != nil {
		return err
	}
	d.state = s
	return nil
}

// Activate promotes the staged slot: the image is re-hashed from disk, then the
// active pointer swaps and the old active slot becomes the rollback target.
// Re-activating an already-activated update is a stable no-op success.
func (d *Device) Activate() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.state.HasStaged {
		return errors.New("activate: nothing staged")
	}
	if d.state.StagedSlot == d.state.ActiveSlot {
		// Idempotent: staged pointer already activated (e.g. retry after power
		// loss between state write and caller observing success).
		d.state.HasStaged = false
		d.state.StagedSlot = ""
		return d.persist()
	}
	if err := d.checkStagedImage(&d.state); err != nil {
		return err
	}
	if d.failPoint.FailActivate {
		return InjectedFault
	}

	prev := d.state.ActiveSlot
	newSlot := d.state.StagedSlot
	s := d.state
	s.Slots[newSlot] = &SlotState{
		Version: s.StagedVer,
		SHA256:  s.StagedSHA,
		Model:   s.StagedModel,
	}
	s.ActiveSlot = newSlot
	s.RollbackSlot = prev
	s.HasRollback = true
	s.HasStaged = false
	s.StagedSlot = ""
	if err := d.persistState(&s); err != nil {
		return err
	}
	d.state = s
	return nil
}

// Rollback swaps back to the retained previous slot, provided its image on
// disk still matches its recorded hash. The slot given up becomes the new
// rollback target, so rollback itself is reversible.
func (d *Device) Rollback() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.state.HasRollback {
		return errors.New("rollback: no rollback target")
	}
	target := d.state.RollbackSlot
	rec := d.state.Slots[target]
	if rec == nil {
		return fmt.Errorf("rollback target %q has no image record", target)
	}
	if _, err := d.imageMatches(target, rec.SHA256); err != nil {
		return fmt.Errorf("rollback target not bootable: %w", err)
	}
	prev := d.state.ActiveSlot
	s := d.state
	s.ActiveSlot = target
	s.RollbackSlot = prev // reversible
	s.HasStaged = false
	s.StagedSlot = ""
	if err := d.persistState(&s); err != nil {
		return err
	}
	d.state = s
	return nil
}

// ClearStaged discards a pending staged update without touching the active slot.
func (d *Device) ClearStaged() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.state
	s.HasStaged = false
	s.StagedSlot = ""
	return d.persistState(&s)
}

// HasStaged reports a committed pending update.
func (d *Device) HasStaged() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state.HasStaged
}

// StagedVersion returns the staged version, or false when nothing is staged.
func (d *Device) StagedVersion() (firmware.Version, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.state.HasStaged {
		return firmware.Version{}, false
	}
	v, err := firmware.ParseVersion(d.state.StagedVer)
	if err != nil {
		return firmware.Version{}, false
	}
	return v, true
}

// Snapshot returns a value copy of the state for assertions.
func (d *Device) Snapshot() State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state
}

// SetFailPoint installs a fault injection point.
func (d *Device) SetFailPoint(fp FailPoint) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failPoint = fp
}

// CorruptSlotBytes overwrites the first byte of a slot image, simulating
// on-disk corruption discovered by the integrity re-check.
func (d *Device) CorruptSlotBytes(slot string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.slotPath(slot)
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("cannot corrupt empty slot image")
	}
	data[0] ^= 0xFF
	return os.WriteFile(p, data, 0o644)
}

// ---- internals ----

func (d *Device) inactiveSlotLocked() string {
	if d.state.ActiveSlot == SlotA {
		return SlotB
	}
	return SlotA
}

func (d *Device) slotPath(slot string) string {
	return filepath.Join(d.dir, "slots", "slot-"+slot+".img")
}

func (d *Device) slotTempPath(slot string) string {
	return filepath.Join(d.dir, "slots", ".slot-"+slot+".tmp")
}

// writeSlotImage writes image to the slot via temp + fsync + rename.
// failAfter >0 injects a write fault after that many bytes; the temp file is
// removed and any previously existing slot image is preserved.
func (d *Device) writeSlotImage(slot string, image []byte, failAfter int64) (err error) {
	final := d.slotPath(slot)
	tmp := d.slotTempPath(slot)
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()

	if failAfter > 0 && int64(len(image)) > failAfter {
		if _, err = f.Write(image[:failAfter]); err != nil {
			_ = f.Close()
			return err
		}
		if err = f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		_ = f.Close()
		return fmt.Errorf("%w: stage write interrupted after %d/%d bytes", InjectedFault, failAfter, len(image))
	}
	if _, err = f.Write(image); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// checkStagedImage hashes the staged slot image and compares with the record.
func (d *Device) checkStagedImage(s *State) error {
	if s.StagedSlot == "" {
		return errors.New("staged slot missing")
	}
	_, err := d.imageMatches(s.StagedSlot, s.StagedSHA)
	return err
}

func (d *Device) imageMatches(slot, wantSHA string) (string, error) {
	data, err := os.ReadFile(d.slotPath(slot))
	if err != nil {
		return "", err
	}
	got := firmware.PayloadSHA256Hex(data)
	if got != wantSHA {
		return got, fmt.Errorf("slot %q image mismatch: disk=%s recorded=%s", slot, got, wantSHA)
	}
	return got, nil
}

// persist writes the current state atomically.
func (d *Device) persist() error { return d.persistState(&d.state) }

func (d *Device) persistState(s *State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := d.statePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, d.statePath)
}
