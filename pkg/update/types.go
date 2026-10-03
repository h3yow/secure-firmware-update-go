// Package update orchestrates verification, version policy, staging,
// activation, boot confirmation and rollback so that every entry point
// (library API or CLI) yields the same explainable conclusion.
package update

import (
	"sync"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/verify"
)

// OutcomeCode classifies the result of an update entry point.
type OutcomeCode string

const (
	OutcomeInstalled      OutcomeCode = "installed"       // staged + activated, awaiting confirm
	OutcomeConfirmed      OutcomeCode = "confirmed"       // active image confirmed good
	OutcomeRolledBack     OutcomeCode = "rolled_back"     // returned to previous known-good
	OutcomeRejected       OutcomeCode = "rejected"        // verification or policy rejection
	OutcomeIdempotentNoop OutcomeCode = "idempotent_noop" // repeated request, state already final
	OutcomeFailedSafe     OutcomeCode = "failed_safe"     // write/crash failure; device stays known-good
)

// PolicyCode is a distinguishable machine-readable rejection reason for the
// version/target policy stage (kept separate from verify.FailureCode).
type PolicyCode string

const (
	PolicyNone              PolicyCode = ""
	PolicyModelMismatch     PolicyCode = "model_mismatch"
	PolicyTargetMismatch    PolicyCode = "target_mismatch"
	PolicyDowngrade         PolicyCode = "downgrade"
	PolicySameVersionReplay PolicyCode = "same_version_replay"
	// PolicyUpdateBusy is returned to the loser of two concurrent update
	// requests against the same engine/device. Exactly one request runs;
	// the other always gets this stable, retryable rejection.
	PolicyUpdateBusy PolicyCode = "update_busy"
	// PolicyTrialUnconfirmed rejects a new install while an unconfirmed trial
	// image is still running. The operator must confirm or roll back first,
	// otherwise the A/B rollback chain would be ambiguous.
	PolicyTrialUnconfirmed PolicyCode = "trial_unconfirmed"
)

// Reason is the unified explanation carried by every outcome.
type Reason struct {
	Verification verify.FailureCode `json:"verification,omitempty"`
	Policy       PolicyCode         `json:"policy,omitempty"`
	Detail       string             `json:"detail,omitempty"`
}

// Outcome is the explainable result returned by every engine entry point.
type Outcome struct {
	Code         OutcomeCode `json:"code"`
	Reason       Reason      `json:"reason"`
	FromVersion  uint64      `json:"from_version"`
	ToVersion    uint64      `json:"to_version"`
	CurrentAfter uint64      `json:"current_after"`
}

// Engine wires verification to the device store.
type Engine struct {
	store    *device.Store
	verifier *verify.Verifier
	now      func() time.Time

	// gate serializes mutating operations within one engine (library API
	// used by multiple goroutines). Try-lock semantics make the losing
	// concurrent request receive a deterministic update_busy rejection
	// instead of queuing or corrupting state.
	gateMu sync.Mutex
	busy   bool
}
