// Package verdict defines distinguishable failure reasons reported by the
// firmware update engine. Every rejection carries a stable Code plus a
// human-readable explanation and the evidence the decision was based on, so
// that different entry points (one-shot vs. staged) report identical reasons
// for identical inputs.
package verdict

import "fmt"

// Code is a stable, machine-readable failure identifier.
type Code string

const (
	CodeOK Code = "ok"

	// Package envelope / integrity
	CodeMalformedPackage Code = "malformed_package"
	CodePayloadTampered  Code = "payload_tampered"

	// Trust chain / key resolution
	CodeUnknownKey         Code = "unknown_signing_key"
	CodeKeyExpired         Code = "signing_key_expired"
	CodeKeyNotYetValid     Code = "signing_key_not_yet_valid"
	CodeKeyPurposeMismatch Code = "signing_key_purpose_mismatch"
	CodeAmbiguousKeys      Code = "ambiguous_signing_keys"
	CodeBadSignature       Code = "bad_signature"

	// Targeting / policy
	CodeModelMismatch  Code = "model_mismatch"
	CodeTargetMismatch Code = "target_mismatch"
	CodeDowngrade      Code = "downgrade_rejected"
	CodeReplay         Code = "same_version_replay"

	// Staging / activation lifecycle
	CodeStagingFailure Code = "staging_failure"
	CodeNothingStaged  Code = "nothing_staged"
	CodeStagedMismatch Code = "staged_image_mismatch"
	CodeNoRollback     Code = "no_rollback_target"
	CodeIOFailure      Code = "io_failure"
)

// Failure is an explained rejection: why an input was rejected and on what
// evidence. It implements the error interface.
type Failure struct {
	// Code is the stable machine-readable reason.
	Code Code
	// Reason is a short human-readable explanation.
	Reason string
	// Input describes the rejected input (package path, key id, version...).
	Input string
	// Basis describes the evidence used for the decision.
	Basis string
}

func (f *Failure) Error() string {
	if f == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s (input=%s; basis=%s)", f.Code, f.Reason, f.Input, f.Basis)
}

// New builds an explained failure.
func New(code Code, reason, input, basis string) *Failure {
	return &Failure{Code: code, Reason: reason, Input: input, Basis: basis}
}
