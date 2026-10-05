package device

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// ErrNoHealthySlot is returned when neither physical slot holds verifiable
// bootable content: the on-disk disagreement cannot be repaired without
// inventing firmware, so the store refuses to operate rather than lie.
var ErrNoHealthySlot = errors.New("device: no healthy slot on disk; state cannot be reconciled")

// slotInspection is the disk-truth view of one physical slot, compared
// against the metadata recorded in state.json.
type slotInspection struct {
	name       string
	recorded   SlotState
	hasRecord  bool
	filesExist bool
	diskMeta   SlotState
	metaParsed bool
	healthy    bool
	orphan     bool // slot files exist although state.json records nothing
}

// inspectSlotLocked classifies one slot by comparing what state.json claims
// with what is actually on disk: the slot metadata file must parse, match
// the recorded (version, payload hash), and the payload blob must hash to
// that value. Anything else means the slot is broken and may never be the
// boot target.
func (s *Store) inspectSlotLocked(name string) slotInspection {
	in := slotInspection{name: name}
	rec, ok := s.inner.Slots[name]
	in.recorded = rec
	in.hasRecord = ok && rec.Present

	metaPath := filepath.Join(s.dir, "slot-"+name+".json")
	blobPath := filepath.Join(s.dir, "slot-"+name+".bin")
	mb, mErr := os.ReadFile(metaPath)
	bb, bErr := os.ReadFile(blobPath)
	in.filesExist = mErr == nil || bErr == nil

	if mErr == nil {
		if err := json.Unmarshal(mb, &in.diskMeta); err == nil {
			in.metaParsed = true
		}
	}

	if !in.hasRecord {
		// No claim in state.json: files here are unproven leftovers.
		in.orphan = in.filesExist
		return in
	}
	if !in.metaParsed {
		return in
	}
	if in.diskMeta.Version != rec.Version ||
		!bytes.Equal(in.diskMeta.PayloadHash, rec.PayloadHash) {
		return in
	}
	if bErr != nil {
		return in
	}
	sum := sha256.Sum256(bb)
	if !bytes.Equal(sum[:], rec.PayloadHash) {
		return in
	}
	in.healthy = true
	return in
}

// reconcileLocked makes the in-memory state agree with the actual slot
// files on disk. It runs on every Open and at the start of every
// transaction, so the reported/current version can never silently disagree
// with the payload the device would really boot:
//
//   - recorded-but-broken slot: its files and record are pruned; a broken
//     slot can never become (or stay) the active boot target;
//   - orphan slot files (no record, e.g. an interrupted delete): removed;
//   - active slot broken but the other slot healthy: boot pointer flips to
//     the healthy slot, the broken slot is pruned, and a dangling pending
//     trial is cleared — the device always ends on a known-good image;
//   - pending update whose staged content no longer exists: cleared so it
//     cannot block future upgrades with a phantom "update in progress".
//
// Repairs are persisted at most once.
func (s *Store) reconcileLocked() error {
	active := s.inner.ActiveSlot
	inactive := otherSlot(active)
	a := s.inspectSlotLocked(active)
	i := s.inspectSlotLocked(inactive)
	changed := false

	// Orphan files on either slot are unproven leftovers from an interrupted
	// delete/overwrite and must never influence a boot decision.
	for _, in := range []slotInspection{a, i} {
		if in.orphan {
			if err := s.removeSlotFilesLocked(in.name); err != nil {
				return err
			}
			changed = true
		}
	}

	switch {
	case a.healthy:
		// Active image really is what state.json says. A broken inactive slot
		// cannot be retained as known-good; prune it.
		if i.hasRecord && !i.healthy {
			if err := s.pruneSlotLocked(inactive); err != nil {
				return err
			}
			changed = true
		}
		// A pruned staged-but-not-activated slot makes any pending record
		// dangle; the generic pending check below clears it.
	case i.healthy:
		// The recorded active image is broken on disk; the other slot is the
		// only verifiable bootable content. Flip to it and discard the broken
		// slot: never stay pointed at firmware the device cannot really run.
		if err := s.removeSlotFilesLocked(active); err != nil {
			return err
		}
		delete(s.inner.Slots, active)
		s.inner.ActiveSlot = inactive
		s.inner.Pending = nil
		s.inner.BootCount = 0
		changed = true
	default:
		// Both slots broken (or absent): do not invent a state.
		if a.filesExist || i.filesExist || a.hasRecord || i.hasRecord {
			return ErrNoHealthySlot
		}
		// Empty store (pre-factory-init): nothing to reconcile.
	}

	// Dangling pending record: neither active nor the staged slot carries the
	// pending ToVersion any more. Drop it so arbitration cannot block on a
	// phantom update.
	if p := s.inner.Pending; p != nil {
		av := activeVersion(s.inner)
		iv := s.inner.Slots[otherSlot(s.inner.ActiveSlot)].Version
		activeOK := s.inner.Slots[s.inner.ActiveSlot].Present && av == p.ToVersion
		stagedOK := s.inner.Slots[otherSlot(s.inner.ActiveSlot)].Present && iv == p.ToVersion
		if !activeOK && !stagedOK {
			s.inner.Pending = nil
			s.inner.BootCount = 0
			changed = true
		}
	}

	if changed {
		return s.persistLocked()
	}
	return nil
}

func activeVersion(in internalState) uint64 {
	return in.Slots[in.ActiveSlot].Version
}

// pruneSlotLocked drops one slot's metadata record and files.
func (s *Store) pruneSlotLocked(slot string) error {
	delete(s.inner.Slots, slot)
	return s.removeSlotFilesLocked(slot)
}
