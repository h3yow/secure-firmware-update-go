package update

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/verify"
)

// New wires a verifier and device store into an engine.
func New(st *device.Store, v *verify.Verifier, now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	return &Engine{store: st, verifier: v, now: now}
}

// beginOp serializes every mutating engine operation. The in-engine try-lock
// guarantees that concurrent goroutines using the same Engine see exactly one
// winner; the losing request deterministically gets update_busy. It also takes
// the process-level device lock, which extends the same guarantee to separate
// processes (concurrent CLI invocations).
func (e *Engine) beginOp() bool {
	e.gateMu.Lock()
	if e.busy {
		e.gateMu.Unlock()
		return false
	}
	e.busy = true
	e.gateMu.Unlock()
	return true
}

func (e *Engine) endOp() {
	e.gateMu.Lock()
	e.busy = false
	e.gateMu.Unlock()
	_ = e.store.Unlock()
}

func busyOutcome(current uint64) Outcome {
	return Outcome{
		Code:         OutcomeRejected,
		Reason:       Reason{Policy: PolicyUpdateBusy, Detail: "another update operation is in progress on this device"},
		FromVersion:  current,
		ToVersion:    current,
		CurrentAfter: current,
	}
}

// Install is the main entry point: verify -> target/version policy ->
// stage -> activate. On any rejection or injected write failure the device
// stays on its known-good version. Repeating a completed install yields a
// same_version_replay rejection; two concurrent installs against one device
// resolve deterministically: exactly one runs, the other gets update_busy.
func (e *Engine) Install(pkg *firmware.Package, opts ...device.Option) Outcome {
	// The gate try-lock is always first: a losing concurrent caller returns
	// update_busy without waiting on any store lock held by the winner.
	if !e.beginOp() {
		current, _ := e.currentVersion()
		return busyOutcome(current)
	}
	defer e.endOp()
	current, err := e.currentVersion()
	if err != nil {
		return failedSafe(0, 0, "cannot read device state: "+err.Error())
	}
	if err := e.store.Lock(); err != nil {
		if errors.Is(err, device.ErrUpdateBusy) {
			return busyOutcome(current)
		}
		return failedSafe(current, current, "cannot acquire device lock: "+err.Error())
	}

	st, err := e.store.State()
	if err != nil {
		return failedSafe(current, current, "cannot read device state: "+err.Error())
	}
	from := st.Committed.Version
	pkgVersion := uint64(0)
	if pkg != nil {
		pkgVersion = pkg.Meta.Version
	}

	// Stage 1: cryptographic verification.
	vr := e.verifier.VerifyPackage(pkg)
	if !vr.OK {
		return Outcome{
			Code:         OutcomeRejected,
			Reason:       Reason{Verification: vr.Code, Detail: vr.Message},
			FromVersion:  from,
			ToVersion:    vr.Version,
			CurrentAfter: from,
		}
	}

	// Stage 2: device binding and anti-rollback policy.
	if pc, detail := checkPolicy(st, pkg); pc != PolicyNone {
		return Outcome{
			Code:         OutcomeRejected,
			Reason:       Reason{Policy: pc, Detail: detail},
			FromVersion:  from,
			ToVersion:    pkg.Meta.Version,
			CurrentAfter: from,
		}
	}

	// Stage 3: stage into inactive slot. When no trial is pending this
	// overwrites the single retained previous known-good version, which is
	// what keeps on-device history bounded to two versions while chaining
	// upgrades.
	slot := device.SlotState{
		Model:       pkg.Meta.Model,
		Target:      pkg.Meta.TargetSlot,
		Version:     pkg.Meta.Version,
		PayloadHash: append([]byte(nil), pkg.Meta.PayloadHash...),
		InstalledAt: e.now().UTC(),
	}
	if err := e.store.Stage(slot, pkg.Payload, opts...); err != nil {
		return failedSafe(from, pkg.Meta.Version, "staging failed: "+err.Error())
	}

	// Stage 4: activate (atomic boot-pointer flip).
	if err := e.store.Activate(opts...); err != nil {
		// Activation failure after successful staging must not strand the
		// device: explicit rollback discards the staged slot and keeps the
		// known-good version active.
		_ = e.store.Rollback()
		return failedSafe(from, pkg.Meta.Version, "activation failed: "+err.Error())
	}

	return Outcome{
		Code:         OutcomeInstalled,
		Reason:       Reason{Detail: "signature valid, version strictly newer, image activated as trial"},
		FromVersion:  from,
		ToVersion:    pkgVersion,
		CurrentAfter: pkgVersion,
	}
}

// checkPolicy enforces: model match, target slot match, strictly increasing
// version, and no overlapping unconfirmed trial. Downgrades, replays and
// trial-busy installs are each distinct reasons.
func checkPolicy(st device.State, pkg *firmware.Package) (PolicyCode, string) {
	m := pkg.Meta
	if m.Model != st.Model {
		return PolicyModelMismatch, fmt.Sprintf("package model %q does not match device %q", m.Model, st.Model)
	}
	if st.Committed.Present && m.TargetSlot != st.Committed.Target {
		return PolicyTargetMismatch, fmt.Sprintf("package target %q does not match device target %q", m.TargetSlot, st.Committed.Target)
	}
	if st.Pending != nil {
		// A trial image is running unconfirmed. A retry of the exact same
		// (version, hash) update is a deterministic replay rejection;
		// anything else must wait for confirm/rollback so the rollback
		// target cannot be silently overwritten.
		if m.Version == st.Pending.ToVersion && bytes.Equal(m.PayloadHash, st.Pending.StagedHash) {
			return PolicySameVersionReplay, fmt.Sprintf("package version %d is already installed and awaiting confirmation", m.Version)
		}
		return PolicyTrialUnconfirmed, fmt.Sprintf("trial version %d is unconfirmed; confirm or roll back before installing version %d", st.Pending.ToVersion, m.Version)
	}
	if st.Committed.Present {
		switch {
		case m.Version < st.Committed.Version:
			return PolicyDowngrade, fmt.Sprintf("package version %d is lower than installed %d", m.Version, st.Committed.Version)
		case m.Version == st.Committed.Version:
			return PolicySameVersionReplay, fmt.Sprintf("package version %d is already installed", m.Version)
		}
	}
	return PolicyNone, ""
}

func (e *Engine) currentVersion() (uint64, error) {
	st, err := e.store.State()
	if err != nil {
		return 0, err
	}
	return st.Committed.Version, nil
}

// ConfirmBoot confirms the running trial image as good. Calling it when no
// trial exists is a stable no-op. On confirm the previous known-good version
// remains in the inactive slot as the single retained rollback target.
func (e *Engine) ConfirmBoot() Outcome {
	if !e.beginOp() {
		current, _ := e.currentVersion()
		return busyOutcome(current)
	}
	defer e.endOp()
	current, err := e.currentVersion()
	if err != nil {
		return failedSafe(0, 0, "cannot read device state: "+err.Error())
	}
	if err := e.store.Lock(); err != nil {
		if errors.Is(err, device.ErrUpdateBusy) {
			return busyOutcome(current)
		}
		return failedSafe(current, current, "cannot acquire device lock: "+err.Error())
	}

	st, err := e.store.State()
	if err != nil {
		return failedSafe(current, current, "cannot read device state: "+err.Error())
	}
	from, cur := pendingRange(st)
	if st.Pending == nil {
		return Outcome{
			Code:         OutcomeIdempotentNoop,
			Reason:       Reason{Detail: "no trial image pending confirmation"},
			FromVersion:  st.Committed.Version,
			ToVersion:    st.Committed.Version,
			CurrentAfter: st.Committed.Version,
		}
	}
	if err := e.store.Confirm(); err != nil {
		return failedSafe(from, cur, "confirm failed: "+err.Error())
	}
	return Outcome{
		Code:         OutcomeConfirmed,
		Reason:       Reason{Detail: "active image confirmed as known-good; previous version retained as rollback target"},
		FromVersion:  from,
		ToVersion:    cur,
		CurrentAfter: cur,
	}
}

// Rollback returns to a known-good version:
//
//   - while an unconfirmed trial is pending it discards the trial and returns
//     to the version the update started from (identical final state to the
//     automatic boot-recovery path);
//   - after confirmation it flips back to the single retained previous
//     known-good version, which itself remains reachable as the rollback
//     target afterwards;
//   - with neither case available it is a stable no-op.
func (e *Engine) Rollback(opts ...device.Option) Outcome {
	if !e.beginOp() {
		current, _ := e.currentVersion()
		return busyOutcome(current)
	}
	defer e.endOp()
	current, err := e.currentVersion()
	if err != nil {
		return failedSafe(0, 0, "cannot read device state: "+err.Error())
	}
	if err := e.store.Lock(); err != nil {
		if errors.Is(err, device.ErrUpdateBusy) {
			return busyOutcome(current)
		}
		return failedSafe(current, current, "cannot acquire device lock: "+err.Error())
	}

	st, err := e.store.State()
	if err != nil {
		return failedSafe(current, current, "cannot read device state: "+err.Error())
	}
	from, cur := pendingRange(st)
	if st.Pending != nil {
		if err := e.store.Rollback(opts...); err != nil {
			return failedSafe(from, cur, "rollback failed: "+err.Error())
		}
		after, _ := e.store.State()
		return Outcome{
			Code:         OutcomeRolledBack,
			Reason:       Reason{Detail: fmt.Sprintf("discarded unconfirmed trial %d and returned to known-good %d", cur, from)},
			FromVersion:  from,
			ToVersion:    cur,
			CurrentAfter: after.Committed.Version,
		}
	}
	// Confirmed state: use the retained previous known-good version.
	if !st.Retained.Present || st.Retained.Version >= st.Committed.Version {
		return Outcome{
			Code:         OutcomeIdempotentNoop,
			Reason:       Reason{Detail: "no retained known-good version to roll back to"},
			FromVersion:  st.Committed.Version,
			ToVersion:    st.Committed.Version,
			CurrentAfter: st.Committed.Version,
		}
	}
	if err := e.store.RollbackRetained(opts...); err != nil {
		return failedSafe(st.Committed.Version, st.Retained.Version, "rollback failed: "+err.Error())
	}
	after, _ := e.store.State()
	return Outcome{
		Code:         OutcomeRolledBack,
		Reason:       Reason{Detail: fmt.Sprintf("returned from confirmed %d to retained known-good %d", st.Committed.Version, st.Retained.Version)},
		FromVersion:  st.Committed.Version,
		ToVersion:    st.Retained.Version,
		CurrentAfter: after.Committed.Version,
	}
}

// Boot applies crash/watchdog recovery and reports the resulting state.
func (e *Engine) Boot(opts ...device.Option) (Outcome, error) {
	if !e.beginOp() {
		current, _ := e.currentVersion()
		return busyOutcome(current), nil
	}
	defer e.endOp()
	current, err := e.currentVersion()
	if err != nil {
		return failedSafe(0, 0, "cannot read device state: "+err.Error()), err
	}
	if err := e.store.Lock(); err != nil {
		if errors.Is(err, device.ErrUpdateBusy) {
			return busyOutcome(current), nil
		}
		return failedSafe(current, current, "cannot acquire device lock: "+err.Error()), err
	}

	before, _ := e.store.State()
	from, trial := pendingRange(before)
	rolledBack, err := e.store.RecoverOnBoot(opts...)
	if err != nil {
		st, _ := e.store.State()
		return failedSafe(st.Committed.Version, trial, "boot recovery failed: "+err.Error()), err
	}
	st, err := e.store.State()
	if err != nil {
		return Outcome{}, err
	}
	if rolledBack {
		return Outcome{
			Code:         OutcomeRolledBack,
			Reason:       Reason{Detail: "unconfirmed trial detected at boot; rolled back to known-good"},
			FromVersion:  from,
			ToVersion:    trial,
			CurrentAfter: st.Committed.Version,
		}, nil
	}
	return Outcome{
		Code:         OutcomeIdempotentNoop,
		Reason:       Reason{Detail: "boot recovery: device on known-good version"},
		FromVersion:  from,
		ToVersion:    trial,
		CurrentAfter: st.Committed.Version,
	}, nil
}

func pendingRange(st device.State) (from, current uint64) {
	if st.Pending != nil {
		return st.Pending.FromVersion, st.Pending.ToVersion
	}
	return st.Committed.Version, st.Committed.Version
}

func failedSafe(from, to uint64, detail string) Outcome {
	return Outcome{
		Code:         OutcomeFailedSafe,
		Reason:       Reason{Detail: detail},
		FromVersion:  from,
		ToVersion:    to,
		CurrentAfter: from,
	}
}
