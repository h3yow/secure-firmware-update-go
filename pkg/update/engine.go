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

// Install is the main entry point: acquire the cross-device exclusive
// transaction, then verify -> target/version policy -> stage -> activate.
//
// The whole operation runs in one transaction that is also exclusive across
// processes (flock on the device directory), so two installs arriving in
// separate processes are fully serialized: the second one sees the first
// one's committed pending state and either joins it (identical package,
// idempotent) or loses with the stable update_in_progress rejection. On any
// rejection or injected write failure the device stays on its known-good
// version.
func (e *Engine) Install(pkg *firmware.Package, opts ...device.Option) (o Outcome) {
	tx, err := e.store.Begin()
	if err != nil {
		return failedSafe(0, 0, "cannot open device transaction: "+err.Error())
	}
	defer func() {
		if err := recover(); err != nil {
			_ = tx.Abort()
			panic(err)
		}
	}()

	// Decide whether the transaction may be released normally; any early
	// rejection path must abort it (the device was not mutated) so the flock
	// is dropped promptly.
	committed := false
	defer func() {
		if !committed {
			_ = tx.Abort()
		}
	}()

	st := tx.Snapshot()
	from, _ := pendingRange(st)

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

	// Stage 2: in-flight update arbitration. While another update is pending
	// (staged or in trial), only the exact same package may proceed — that is
	// an idempotent retry of the interrupted install, which already passed
	// policy once, so the policy stage is skipped for it. Any different
	// package loses with one stable rejection, no matter its version: two
	// concurrent requests can never both take effect.
	retry := false
	if st.Pending != nil {
		same := st.Pending.ToVersion == pkg.Meta.Version && bytes.Equal(st.Pending.StagedHash, pkg.Meta.PayloadHash)
		if !same {
			return Outcome{
				Code: OutcomeRejected,
				Reason: Reason{Policy: PolicyUpdateInProgress, Detail: fmt.Sprintf(
					"update to version %d already in progress; retry after it is confirmed or rolled back", st.Pending.ToVersion)},
				FromVersion:  from,
				ToVersion:    pkg.Meta.Version,
				CurrentAfter: from,
			}
		}
		retry = true
	}

	// Stage 3: device binding and anti-rollback policy.
	if pc, detail := checkPolicy(st, pkg); !retry && pc != PolicyNone {
		return Outcome{
			Code:         OutcomeRejected,
			Reason:       Reason{Policy: pc, Detail: detail},
			FromVersion:  from,
			ToVersion:    pkg.Meta.Version,
			CurrentAfter: from,
		}
	}

	// Stage 4: stage into the inactive slot.
	slot := device.SlotState{
		Model:       pkg.Meta.Model,
		Target:      pkg.Meta.TargetSlot,
		Version:     pkg.Meta.Version,
		PayloadHash: append([]byte(nil), pkg.Meta.PayloadHash...),
		InstalledAt: e.now().UTC(),
	}
	if err := tx.Stage(slot, pkg.Payload, opts...); err != nil {
		if errors.Is(err, device.ErrSlotConflict) {
			// A different update is already in flight (e.g. two concurrent
			// installs): this one loses with a stable, explainable rejection
			// and the device state is untouched.
			return Outcome{
				Code:         OutcomeRejected,
				Reason:       Reason{Policy: PolicyUpdateInProgress, Detail: err.Error()},
				FromVersion:  from,
				ToVersion:    pkg.Meta.Version,
				CurrentAfter: from,
			}
		}
		return failedSafe(from, pkg.Meta.Version, "staging failed: "+err.Error())
	}

	// Stage 5: activate (atomic boot-pointer flip).
	if err := tx.Activate(opts...); err != nil {
		// Activation failure after successful staging must not strand the
		// device: explicit rollback discards the staged slot and keeps the
		// known-good version active.
		_ = tx.Rollback()
		return failedSafe(from, pkg.Meta.Version, "activation failed: "+err.Error())
	}

	o = Outcome{
		Code:         OutcomeInstalled,
		Reason:       Reason{Detail: "signature valid, version strictly newer, image activated as trial"},
		FromVersion:  from,
		ToVersion:    pkg.Meta.Version,
		CurrentAfter: pkg.Meta.Version,
	}
	if err := tx.Commit(); err != nil {
		return failedSafe(from, pkg.Meta.Version, "commit transaction failed: "+err.Error())
	}
	committed = true
	return o
}

// checkPolicy enforces: model match, target slot match, strictly increasing
// version. Downgrades and same-version replays are distinct reasons.
func checkPolicy(st device.State, pkg *firmware.Package) (PolicyCode, string) {
	m := pkg.Meta
	if m.Model != st.Model {
		return PolicyModelMismatch, fmt.Sprintf("package model %q does not match device %q", m.Model, st.Model)
	}
	if st.Committed.Present && m.TargetSlot != st.Committed.Target {
		return PolicyTargetMismatch, fmt.Sprintf("package target %q does not match device target %q", m.TargetSlot, st.Committed.Target)
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

// ConfirmBoot confirms the running trial image as good. Calling it when no
// trial exists is a stable no-op.
func (e *Engine) ConfirmBoot() Outcome {
	tx, err := e.store.Begin()
	if err != nil {
		return failedSafe(0, 0, "cannot open device transaction: "+err.Error())
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Abort()
		}
	}()

	st := tx.Snapshot()
	if st.Pending == nil {
		return Outcome{
			Code:         OutcomeIdempotentNoop,
			Reason:       Reason{Detail: "no trial image pending confirmation"},
			FromVersion:  st.Committed.Version,
			ToVersion:    st.Committed.Version,
			CurrentAfter: st.Committed.Version,
		}
	}
	from, cur := pendingRange(st)
	if err := tx.Confirm(); err != nil {
		return failedSafe(from, cur, "confirm failed: "+err.Error())
	}
	if err := tx.Commit(); err != nil {
		return failedSafe(from, cur, "commit transaction failed: "+err.Error())
	}
	committed = true
	return Outcome{
		Code:         OutcomeConfirmed,
		Reason:       Reason{Detail: "active image confirmed as known-good"},
		FromVersion:  from,
		ToVersion:    cur,
		CurrentAfter: cur,
	}
}

// Rollback explicitly returns to a known-good version. Two cases:
//
//   - an update is pending (trial staged or activated): the trial is
//     discarded and the device returns to Pending.FromVersion;
//   - no update pending but a previous known-good version is retained: the
//     device reverts to it (post-confirm rollback of a continuous chain).
//
// Rolling back when neither applies is a stable no-op. The trial path is
// identical to the automatic boot-recovery path.
func (e *Engine) Rollback(opts ...device.Option) Outcome {
	tx, err := e.store.Begin()
	if err != nil {
		return failedSafe(0, 0, "cannot open device transaction: "+err.Error())
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Abort()
		}
	}()

	st := tx.Snapshot()
	if st.Pending == nil {
		if !st.Staged.Present {
			return Outcome{
				Code:         OutcomeIdempotentNoop,
				Reason:       Reason{Detail: "no update to roll back"},
				FromVersion:  st.Committed.Version,
				ToVersion:    st.Committed.Version,
				CurrentAfter: st.Committed.Version,
			}
		}
		// Post-confirm revert to the retained previous known-good version.
		prev := st.Staged.Version
		if err := tx.Revert(opts...); err != nil {
			return failedSafe(st.Committed.Version, prev, "revert failed: "+err.Error())
		}
		o := Outcome{
			Code:         OutcomeRolledBack,
			Reason:       Reason{Detail: fmt.Sprintf("reverted from confirmed version %d to retained known-good %d", st.Committed.Version, prev)},
			FromVersion:  st.Committed.Version,
			ToVersion:    prev,
			CurrentAfter: prev,
		}
		if err := tx.Commit(); err != nil {
			return failedSafe(st.Committed.Version, prev, "commit transaction failed: "+err.Error())
		}
		committed = true
		return o
	}
	from, cur := pendingRange(st)
	if err := tx.Rollback(opts...); err != nil {
		return failedSafe(from, cur, "rollback failed: "+err.Error())
	}
	after := tx.Snapshot()
	o := Outcome{
		Code:         OutcomeRolledBack,
		Reason:       Reason{Detail: fmt.Sprintf("returned from version %d to known-good %d", cur, from)},
		FromVersion:  from,
		ToVersion:    cur,
		CurrentAfter: after.Committed.Version,
	}
	if err := tx.Commit(); err != nil {
		return failedSafe(from, cur, "commit transaction failed: "+err.Error())
	}
	committed = true
	return o
}

// Boot applies crash/watchdog recovery and reports the resulting state.
func (e *Engine) Boot(opts ...device.Option) (Outcome, error) {
	tx, err := e.store.Begin()
	if err != nil {
		return failedSafe(0, 0, "cannot open device transaction: "+err.Error()), err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Abort()
		}
	}()

	before := tx.Snapshot()
	from, trial := pendingRange(before)
	rolledBack, err := tx.RecoverOnBoot(opts...)
	if err != nil {
		st := tx.Snapshot()
		return failedSafe(st.Committed.Version, trial, "boot recovery failed: "+err.Error()), err
	}
	st := tx.Snapshot()
	if err := tx.Commit(); err != nil {
		return failedSafe(st.Committed.Version, trial, "commit transaction failed: "+err.Error()), err
	}
	committed = true
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
