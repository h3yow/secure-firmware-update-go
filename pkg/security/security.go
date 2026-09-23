// Package security verifies firmware packages against a root of trust.
// Checks run in one fixed order so that the same package always yields the
// same reason through every entry point:
//
//  1. manifest schema well-formedness
//  2. trust chain: key id known, currently valid, purpose firmware-signing
//  3. cryptographic signature over the exact canonical manifest bytes
//  4. payload integrity: length and SHA-256 match the signed manifest
//  5. model targeting
//
// Version (anti-rollback) and target-slot policy are applied afterwards by
// pkg/update, since they depend on the device's live A/B state. No network
// access and no real key material are involved.
package security

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
	"github.com/h3yow/secure-firmware-update-go/pkg/verdict"
)

// Verifier verifies packages against a root of trust at a clock-controlled time.
type Verifier struct {
	Root  *trust.Root
	NowFn func() time.Time
}

// NewVerifier creates a verifier using the wall clock.
func NewVerifier(r *trust.Root) *Verifier {
	return &Verifier{Root: r, NowFn: time.Now}
}

// VerifyResult explains a verification decision.
type VerifyResult struct {
	Accepted bool
	Manifest firmware.Manifest
	Failure  *verdict.Failure
}

func reject(code verdict.Code, reason, input, basis string) *VerifyResult {
	return &VerifyResult{Accepted: false, Failure: verdict.New(code, reason, input, basis)}
}

// Verify runs chain, signature, integrity and model checks. Slot-target
// policy is intentionally left to the orchestration layer (see pkg/update):
// target-slot suitability depends on the live A/B plan, while all checks here
// depend only on the package, the trust root and the device model.
func (v *Verifier) Verify(pkg *firmware.Package, expectedModel string) *VerifyResult {
	now := v.NowFn()
	input := pkg.SourcePath
	if input == "" {
		input = fmt.Sprintf("package keyid=%s version=%s", pkg.KeyID, pkg.Manifest.Version)
	}
	m := pkg.Manifest

	// 1. schema
	if m.Schema != firmware.CurrentSchema {
		return reject(verdict.CodeMalformedPackage,
			"unsupported manifest schema", input,
			fmt.Sprintf("schema=%d, supported=%d", m.Schema, firmware.CurrentSchema))
	}

	// 2. trust chain: unique, currently valid, correct-purpose key
	key, ambiguous, keyBasis := v.Root.AcceptableKey(pkg.KeyID, trust.PurposeFirmware, now)
	if ambiguous {
		return reject(verdict.CodeAmbiguousKeys,
			"multiple trusted keys match the package key id; refusing to select one",
			input, keyBasis)
	}
	if key == nil {
		return reject(v.classifyUnknownKey(pkg.KeyID, now, &keyBasis),
			"signing key is not acceptable", input, keyBasis)
	}

	// 3. signature over the exact canonical manifest bytes
	if len(pkg.Signature) != ed25519.SignatureSize {
		return reject(verdict.CodeBadSignature,
			"signature has wrong length", input,
			fmt.Sprintf("sig_len=%d, want=%d (key=%s)", len(pkg.Signature), ed25519.SignatureSize, key.ID))
	}
	if !ed25519.Verify(ed25519.PublicKey(key.Public), pkg.ManifestBytes, pkg.Signature) {
		return reject(verdict.CodeBadSignature,
			"signature does not verify against the trusted key", input,
			fmt.Sprintf("key=%s alg=%s manifest_bytes=%d", key.ID, key.Algorithm, len(pkg.ManifestBytes)))
	}

	// 4. payload integrity against signed manifest
	if int64(len(pkg.Payload)) != m.PayloadSize {
		return reject(verdict.CodePayloadTampered,
			"payload length disagrees with signed manifest", input,
			fmt.Sprintf("actual=%d signed=%d", len(pkg.Payload), m.PayloadSize))
	}
	actualHash := firmware.PayloadSHA256Hex(pkg.Payload)
	if actualHash != m.PayloadSHA256 {
		return reject(verdict.CodePayloadTampered,
			"payload SHA-256 disagrees with signed manifest", input,
			fmt.Sprintf("actual=%s signed=%s", actualHash, m.PayloadSHA256))
	}

	// 5. model targeting
	if m.Model != expectedModel {
		return reject(verdict.CodeModelMismatch,
			"firmware model does not match device", input,
			fmt.Sprintf("package_model=%q device_model=%q", m.Model, expectedModel))
	}

	return &VerifyResult{Accepted: true, Manifest: m}
}

// classifyUnknownKey distinguishes unknown id from expired / future / purpose
// failures for a key that *is* present in the root but not acceptable.
// AcceptableKey returns nil both for "id unknown" and for "known but invalid";
// we re-inspect the raw key list to produce a precise reason.
func (v *Verifier) classifyUnknownKey(id string, now time.Time, basis *string) verdict.Code {
	k := v.Root.FindKey(id)
	if k == nil {
		return verdict.CodeUnknownKey
	}
	switch {
	case now.Unix() < k.NotBefore:
		return verdict.CodeKeyNotYetValid
	case now.Unix() > k.NotAfter:
		return verdict.CodeKeyExpired
	default:
		// Known, in-window, but lacks the firmware purpose.
		for _, p := range k.Purposes {
			if p == trust.PurposeFirmware {
				// Should be unreachable: AcceptableKey would have accepted.
				return verdict.CodeUnknownKey
			}
		}
		return verdict.CodeKeyPurposeMismatch
	}
}
