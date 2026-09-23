package verify

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
)

// New creates a Verifier bound to the given root of trust.
func New(root *trust.RootOfTrust, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{root: root, now: now}
}

// VerifyPackage performs, in strict order:
//  1. structural sanity of the package,
//  2. trust-chain decision for the single key named by the package,
//  3. signature verification over the canonical metadata,
//  4. payload integrity against the signed hash.
//
// The first failed stage determines the returned FailureCode so callers get
// one distinguishable, explainable reason.
func (v *Verifier) VerifyPackage(pkg *firmware.Package) Result {
	if pkg == nil {
		return reject(FailureMalformedPackage, "nil package", "", 0)
	}
	m := pkg.Meta
	if m.KeyID == "" || m.Model == "" || m.TargetSlot == "" {
		return reject(FailureMalformedPackage, "missing required metadata fields", m.KeyID, m.Version)
	}
	if len(pkg.Signature) != ed25519.SignatureSize {
		return reject(FailureMalformedPackage, fmt.Sprintf("signature has wrong length %d", len(pkg.Signature)), m.KeyID, m.Version)
	}

	// Stage 2: trust chain. Lookup + Evaluate must agree on the same key;
	// no other key is ever tried.
	reg, found := v.root.Lookup(m.KeyID)
	decision := v.root.Evaluate(m.KeyID, firmware.PurposeFirmware, v.now())
	if !found {
		return reject(FailureUnknownKey, decision.Reason, m.KeyID, m.Version)
	}
	if !decision.Accepted {
		return reject(mapTrustReason(reg, decision, v.now()), decision.Reason, m.KeyID, m.Version)
	}

	// Stage 3: signature over canonical metadata.
	canonical, err := firmware.CanonicalEncode(m)
	if err != nil {
		return reject(FailureMalformedPackage, err.Error(), m.KeyID, m.Version)
	}
	if !ed25519.Verify(ed25519.PublicKey(reg.PublicKey), canonical, pkg.Signature) {
		return reject(FailureBadSignature, "signature does not verify against trusted key", m.KeyID, m.Version)
	}

	// Stage 4: integrity.
	got := firmware.HashPayload(pkg.Payload)
	if !bytes.Equal(got, m.PayloadHash) || m.PayloadSize != int64(len(pkg.Payload)) {
		return reject(FailurePayloadHashMismatch, "payload hash/size does not match signed metadata", m.KeyID, m.Version)
	}

	return Result{OK: true, Code: FailureNone, Message: "signature and integrity verified", KeyID: m.KeyID, Version: m.Version}
}

func reject(code FailureCode, msg, keyID string, version uint64) Result {
	return Result{OK: false, Code: code, Message: msg, KeyID: keyID, Version: version}
}

// mapTrustReason translates the explainable trust decision into a precise
// failure code, preferring purpose mismatch over timing when both could be
// cited, because purpose is an identity-level constraint.
func mapTrustReason(k trust.PublicKey, d trust.Decision, now time.Time) FailureCode {
	if k.Purpose != firmware.PurposeFirmware {
		return FailureKeyPurposeMismatch
	}
	t := now.UTC()
	if t.Before(k.NotBefore) {
		return FailureKeyNotYetValid
	}
	return FailureKeyExpired
}
