package security

import (
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/signing"
	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
	"github.com/h3yow/secure-firmware-update-go/pkg/verdict"
)

const model = "box-100"

func fixedClock(s string) func() time.Time {
	tt, _ := time.Parse(time.RFC3339, s)
	return func() time.Time { return tt }
}

type fixture struct {
	signers map[string]*signing.Signer
	root    *trust.Root
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ids := []string{"cur", "next", "old", "maint"}
	fx := &fixture{signers: map[string]*signing.Signer{}}
	keys := []trust.Key{}
	unix := func(s string) int64 {
		tt, _ := time.Parse(time.RFC3339, s)
		return tt.Unix()
	}
	for _, id := range ids {
		s, err := signing.GenerateKey(id, "test:"+id)
		if err != nil {
			t.Fatal(err)
		}
		fx.signers[id] = s
		k := trust.Key{ID: id, Algorithm: trust.AlgEd25519, Public: s.Public()}
		switch id {
		case "cur":
			k.NotBefore, k.NotAfter = unix("2026-01-01T00:00:00Z"), unix("2026-12-31T00:00:00Z")
			k.Purposes = []trust.Purpose{trust.PurposeFirmware}
		case "next":
			k.NotBefore, k.NotAfter = unix("2027-01-01T00:00:00Z"), unix("2028-12-31T00:00:00Z")
			k.Purposes = []trust.Purpose{trust.PurposeFirmware}
		case "old":
			k.NotBefore, k.NotAfter = unix("2024-01-01T00:00:00Z"), unix("2025-12-31T00:00:00Z")
			k.Purposes = []trust.Purpose{trust.PurposeFirmware}
		case "maint":
			k.NotBefore, k.NotAfter = unix("2026-01-01T00:00:00Z"), unix("2026-12-31T00:00:00Z")
			k.Purposes = []trust.Purpose{trust.PurposeOther}
		}
		keys = append(keys, k)
	}
	fx.root = &trust.Root{Version: 1, Keys: keys}
	return fx
}

// signAs signs the manifest with signerID but stamps the package with keyID,
// letting tests express "valid key id, wrong key material" precisely.
func (fx *fixture) signAs(t *testing.T, signerID, keyID string, m firmware.Manifest, payload []byte) *firmware.Package {
	t.Helper()
	s := fx.signers[signerID]
	if s == nil {
		t.Fatalf("no signer %q", signerID)
	}
	m.Schema = firmware.CurrentSchema
	m.PayloadSize = int64(len(payload))
	m.PayloadSHA256 = firmware.PayloadSHA256Hex(payload)
	mb, err := firmware.CanonicalManifest(&m)
	if err != nil {
		t.Fatal(err)
	}
	return &firmware.Package{
		Manifest:      m,
		ManifestBytes: mb,
		Signature:     s.Sign(mb),
		KeyID:         keyID,
		Payload:       payload,
	}
}

func baseManifest() (firmware.Manifest, []byte) {
	payload := []byte("firmware-image-bytes")
	return firmware.Manifest{
		PackageID:  "pkg-1",
		Model:      model,
		TargetSlot: "B",
		Version:    "1.0.0",
		PayloadKey: "rel",
		IssuedAt:   1,
	}, payload
}

func (fx *fixture) verifier(at string) *Verifier {
	v := NewVerifier(fx.root)
	v.NowFn = fixedClock(at)
	return v
}

func TestValidPackageAccepted(t *testing.T) {
	fx := newFixture(t)
	m, p := baseManifest()
	pkg := fx.signAs(t, "cur", "cur", m, p)
	res := fx.verifier("2026-09-23T00:00:00Z").Verify(pkg, model)
	if !res.Accepted {
		t.Fatalf("expected acceptance, got %s", res.Failure)
	}
}

func TestFailureReasonsAreDistinguishable(t *testing.T) {
	fx := newFixture(t)
	m, payload := baseManifest()

	type tc struct {
		name     string
		at       string
		signerID string
		keyID    string
		mutate   func(p *firmware.Package)
		modelArg string
		want     verdict.Code
	}
	cases := []tc{
		{"unknown key", "2026-09-23T00:00:00Z", "cur", "ghost", nil, model, verdict.CodeUnknownKey},
		{"expired key", "2026-09-23T00:00:00Z", "old", "old", nil, model, verdict.CodeKeyExpired},
		{"future key at 2026", "2026-09-23T00:00:00Z", "next", "next", nil, model, verdict.CodeKeyNotYetValid},
		{"wrong key material for trusted id", "2026-09-23T00:00:00Z", "old", "cur", nil, model, verdict.CodeBadSignature},
		{"rotated-in key accepted in its window", "2027-06-01T00:00:00Z", "next", "next", nil, model, verdict.CodeOK},
		{"wrong purpose", "2026-09-23T00:00:00Z", "maint", "maint", nil, model, verdict.CodeKeyPurposeMismatch},
		{"corrupted signature", "2026-09-23T00:00:00Z", "cur", "cur", func(p *firmware.Package) { p.Signature[0] ^= 1 }, model, verdict.CodeBadSignature},
		{"truncated signature", "2026-09-23T00:00:00Z", "cur", "cur", func(p *firmware.Package) { p.Signature = p.Signature[:3] }, model, verdict.CodeBadSignature},
		{"payload tamper", "2026-09-23T00:00:00Z", "cur", "cur", func(p *firmware.Package) { p.Payload[0] ^= 1 }, model, verdict.CodePayloadTampered},
		{"payload length tamper", "2026-09-23T00:00:00Z", "cur", "cur", func(p *firmware.Package) { p.Payload = append(p.Payload, 0) }, model, verdict.CodePayloadTampered},
		{"model mismatch", "2026-09-23T00:00:00Z", "cur", "cur", nil, "box-200", verdict.CodeModelMismatch},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mm, pp := m, append([]byte(nil), payload...)
			pkg := fx.signAs(t, c.signerID, c.keyID, mm, pp)
			if c.mutate != nil {
				c.mutate(pkg)
			}
			res := fx.verifier(c.at).Verify(pkg, c.modelArg)
			if c.want == verdict.CodeOK {
				if !res.Accepted {
					t.Fatalf("expected acceptance, got %s", res.Failure)
				}
				return
			}
			if res.Accepted {
				t.Fatalf("input=%s: expected reject %q but accepted", c.name, c.want)
			}
			if res.Failure.Code != c.want {
				t.Fatalf("case=%s\ninput=%s\nexpected=%q got=%q\nreason=%s\nbasis=%s",
					c.name, res.Failure.Input, c.want, res.Failure.Code, res.Failure.Reason, res.Failure.Basis)
			}
		})
	}
}

func TestManifestTamperBreaksSignature(t *testing.T) {
	fx := newFixture(t)
	m, payload := baseManifest()
	pkg := fx.signAs(t, "cur", "cur", m, payload)
	pkg.Manifest.PackageID = "pkg-2"
	mb, err := firmware.CanonicalManifest(&pkg.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	pkg.ManifestBytes = mb
	res := fx.verifier("2026-09-23T00:00:00Z").Verify(pkg, model)
	if res.Accepted || res.Failure.Code != verdict.CodeBadSignature {
		t.Fatalf("modified manifest must fail signature, got %+v", res)
	}
}
