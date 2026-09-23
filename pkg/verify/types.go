// Package verify performs signature and integrity verification of firmware
// packages against a local root of trust.
package verify

import (
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
)

// FailureCode is a distinguishable machine-readable failure reason.
type FailureCode string

const (
	FailureNone                FailureCode = ""
	FailureMalformedPackage    FailureCode = "malformed_package"
	FailureUnknownKey          FailureCode = "unknown_key"
	FailureKeyExpired          FailureCode = "key_expired"
	FailureKeyNotYetValid      FailureCode = "key_not_yet_valid"
	FailureKeyPurposeMismatch  FailureCode = "key_purpose_mismatch"
	FailureBadSignature        FailureCode = "bad_signature"
	FailurePayloadHashMismatch FailureCode = "payload_hash_mismatch"
)

// Result is the explainable outcome of verification.
type Result struct {
	OK      bool
	Code    FailureCode
	Message string
	KeyID   string
	Version uint64
}

// Verifier verifies packages against a root of trust.
type Verifier struct {
	root *trust.RootOfTrust
	now  func() time.Time
}
