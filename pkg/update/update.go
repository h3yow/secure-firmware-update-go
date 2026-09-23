// Package update is the orchestration entry point. It ties signature and
// integrity verification (pkg/security), anti-rollback policy, A/B staging,
// activation and rollback (pkg/device) into consistent, idempotent flows that
// are reachable through two entries:
//
//   - one-shot: Install = verify -> stage -> activate
//   - staged:    Prepare (verify -> stage), later Activate
//
// Both entries apply the identical ordered policy, so an identical package
// always produces an identical verdict regardless of the entry used.
package update

import (
	"fmt"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/security"
	"github.com/h3yow/secure-firmware-update-go/pkg/verdict"
)

// Engine orchestrates updates for one device.
type Engine struct {
	Dev      *device.Device
	Verifier *security.Verifier
}

// New creates an update engine.
func New(d *device.Device, v *security.Verifier) *Engine {
	return &Engine{Dev: d, Verifier: v}
}

// Outcome explains a decision for both success and failure.
type Outcome struct {
	Action  string // verify|install|prepare|activate|rollback
	Success bool
	Version string // version decided upon (active after commit)
	Slot    string // active slot after commit
	Failure *verdict.Failure
}

func ok(action, version, slot string) *Outcome {
	return &Outcome{Action: action, Success: true, Version: version, Slot: slot}
}

func fail(action string, f *verdict.Failure) *Outcome {
	return &Outcome{Action: action, Success: false, Failure: f}
}

func failf(action, version, slot string, code verdict.Code, reason, input, basis string) *Outcome {
	o := fail(action, verdict.New(code, reason, input, basis))
	o.Version = version
	o.Slot = slot
	return o
}

// VerifyOnly checks a package without touching device state. Target slot is
// derived from the device's current A/B plan exactly as during installation.
func (e *Engine) VerifyOnly(pkgPath string) *Outcome {
	r := e.verifyPackage("verify", pkgPath)
	if r.f != nil {
		return fail("verify", r.f)
	}
	return ok("verify", r.pkg.Manifest.Version, e.Dev.ActiveSlot())
}

// Install runs verify -> stage -> activate in one call.
func (e *Engine) Install(pkgPath string) *Outcome {
	r := e.verifyPackage("install", pkgPath)
	if r.f != nil {
		return fail("install", r.f)
	}
	if o := e.stageVerified("install", r.pkg, r.manifestVer); !o.Success {
		return o
	}
	return e.activateStaged("install")
}

// Prepare stages a verified package without activating it.
func (e *Engine) Prepare(pkgPath string) *Outcome {
	r := e.verifyPackage("prepare", pkgPath)
	if r.f != nil {
		return fail("prepare", r.f)
	}
	if o := e.stageVerified("prepare", r.pkg, r.manifestVer); !o.Success {
		return o
	}
	return ok("prepare", r.pkg.Manifest.Version, e.Dev.ActiveSlot())
}

// Activate promotes a previously staged update. With no staging pending it is
// a stable, explained no-op failure (nothing to activate).
func (e *Engine) Activate() *Outcome {
	return e.activateStaged("activate")
}

// Rollback reverts the last activation.
func (e *Engine) Rollback() *Outcome {
	if err := e.Dev.Rollback(); err != nil {
		return failf("rollback", e.Dev.ActiveVersion().String(), e.Dev.ActiveSlot(),
			verdict.CodeNoRollback, "no rollback target available", "(rollback)", err.Error())
	}
	return ok("rollback", e.Dev.ActiveVersion().String(), e.Dev.ActiveSlot())
}

type verifyRun struct {
	pkg         *firmware.Package
	manifestVer firmware.Version
	f           *verdict.Failure
}

// verifyPackage performs the shared ordered pipeline used by every entry:
// parse -> security verification -> version policy.
func (e *Engine) verifyPackage(action, pkgPath string) verifyRun {
	input := pkgPath
	pkg, err := firmware.ParseFile(pkgPath)
	if err != nil {
		return verifyRun{f: verdict.New(verdict.CodeMalformedPackage,
			"firmware package cannot be parsed", input, err.Error())}
	}
	pkg.SourcePath = pkgPath
	res := e.Verifier.Verify(pkg, e.Dev.Snapshot().Model)
	if !res.Accepted {
		return verifyRun{pkg: pkg, f: res.Failure}
	}
	mv, err := firmware.ParseVersion(res.Manifest.Version)
	if err != nil {
		return verifyRun{pkg: pkg, f: verdict.New(verdict.CodeMalformedPackage,
			"manifest version unparseable", input, err.Error())}
	}

	// Version policy: strictly greater than active, and not a same-version
	// replay. This precedes slot planning so replay/downgrade is reported with
	// its precise reason even when the package's target slot has rotated.
	active := e.Dev.ActiveVersion()
	switch mv.Compare(active) {
	case -1:
		return verifyRun{pkg: pkg, manifestVer: mv, f: verdict.New(verdict.CodeDowngrade,
			"firmware version is older than the active version", input,
			fmt.Sprintf("package=%s active=%s", mv, active))}
	case 0:
		return verifyRun{pkg: pkg, manifestVer: mv, f: verdict.New(verdict.CodeReplay,
			"firmware version equals the active version", input,
			fmt.Sprintf("package=%s active=%s; equal-version replay is rejected", mv, active))}
	}

	// Target-slot policy: the package must explicitly address the inactive
	// slot the device plans to write.
	target := e.Dev.InactiveSlot()
	if pkg.Manifest.TargetSlot != target {
		return verifyRun{pkg: pkg, manifestVer: mv, f: verdict.New(verdict.CodeTargetMismatch,
			"firmware target slot does not match device plan", input,
			fmt.Sprintf("package_target=%q device_target=%q (active=%q)",
				pkg.Manifest.TargetSlot, target, e.Dev.ActiveSlot()))}
	}
	return verifyRun{pkg: pkg, manifestVer: mv}
}

// stageVerified stages an already verified package. Re-running the exact same
// update while it is still pending is idempotent: when the same version/SHA is
// already staged, staging is simply confirmed.
func (e *Engine) stageVerified(action string, pkg *firmware.Package, mv firmware.Version) *Outcome {
	input := pkg.SourcePath
	if stagedVer, has := e.Dev.StagedVersion(); has {
		snap := e.Dev.Snapshot()
		if stagedVer.Compare(mv) == 0 && snap.StagedSHA == pkg.Manifest.PayloadSHA256 &&
			snap.StagedModel == pkg.Manifest.Model && snap.StagedSlot == e.Dev.InactiveSlot() {
			return ok(action, mv.String(), e.Dev.ActiveSlot())
		}
	}
	if err := e.Dev.Stage(mv, pkg.Manifest.Model, pkg.Manifest.PayloadSHA256, pkg.Payload); err != nil {
		code := verdict.CodeIOFailure
		basis := err.Error()
		if isInjectedFault(err) {
			code = verdict.CodeStagingFailure
			basis = "staging write interrupted; active slot unchanged: " + err.Error()
		}
		return failf(action, e.Dev.ActiveVersion().String(), e.Dev.ActiveSlot(),
			code, "failed while staging firmware image", input, basis)
	}
	return ok(action, mv.String(), e.Dev.ActiveSlot())
}

// activateStaged validates the pending staging against the device plan and
// commits it. A stale staged record (target slot no longer inactive) is a
// distinct mismatch failure rather than a silent swap.
func (e *Engine) activateStaged(action string) *Outcome {
	snap := e.Dev.Snapshot()
	if !snap.HasStaged {
		return failf(action, e.Dev.ActiveVersion().String(), snap.ActiveSlot,
			verdict.CodeNothingStaged, "no staged update to activate", "(activate)",
			"device has no committed pending update")
	}
	if snap.StagedSlot != e.Dev.InactiveSlot() {
		return failf(action, e.Dev.ActiveVersion().String(), snap.ActiveSlot,
			verdict.CodeStagedMismatch, "staged slot does not match the inactive slot",
			"(activate)", fmt.Sprintf("staged=%s inactive=%s", snap.StagedSlot, e.Dev.InactiveSlot()))
	}
	if err := e.Dev.Activate(); err != nil {
		return failf(action, e.Dev.ActiveVersion().String(), snap.ActiveSlot,
			verdict.CodeIOFailure, "activation failed; device remains on known-good slot",
			"(activate)", err.Error())
	}
	return ok(action, e.Dev.ActiveVersion().String(), e.Dev.ActiveSlot())
}

func isInjectedFault(err error) bool {
	return err != nil && errorHas(err, device.InjectedFault)
}

func errorHas(err, target error) bool {
	if err == target {
		return true
	}
	type unwrapper interface{ Unwrap() error }
	for {
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
		if err == nil {
			return false
		}
		if err == target {
			return true
		}
	}
}
