package verify

import (
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
)

var testNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

type fixture struct {
	root    *trust.RootOfTrust
	signers map[string]trust.TestKey
	v       *Verifier
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := trust.NewRoot()
	signers := map[string]trust.TestKey{}
	mk := func(id, seed, purpose string, nb, na time.Time) trust.TestKey {
		k, err := trust.GenerateTestKey(id, seed, purpose, nb, na)
		if err != nil {
			t.Fatalf("generate key %s: %v", id, err)
		}
		if err := root.AddKey(trust.PublicKey{
			ID: id, PublicKey: k.Public, Purpose: firmware.Purpose(purpose),
			NotBefore: nb, NotAfter: na,
		}); err != nil {
			t.Fatalf("add key %s: %v", id, err)
		}
		signers[id] = k
		return k
	}
	mk("active", "seed-active", string(firmware.PurposeFirmware), testNow.Add(-10*day), testNow.Add(10*day))
	mk("active2", "seed-active2", string(firmware.PurposeFirmware), testNow.Add(-5*day), testNow.Add(5*day))
	mk("future", "seed-future", string(firmware.PurposeFirmware), testNow.Add(2*day), testNow.Add(30*day))
	mk("expired", "seed-expired", string(firmware.PurposeFirmware), testNow.Add(-30*day), testNow.Add(-1*day))
	mk("recovery", "seed-rec", string(firmware.PurposeRecovery), testNow.Add(-10*day), testNow.Add(10*day))
	v := New(root, func() time.Time { return testNow })
	return fixture{root: root, signers: signers, v: v}
}

func (f fixture) pkg(t *testing.T, keyID string, version uint64, mutate func(*firmware.Package)) *firmware.Package {
	t.Helper()
	key, ok := f.signers[keyID]
	if !ok {
		t.Fatalf("no signer %q", keyID)
	}
	p, err := firmware.NewBuilder().Build("dev1", "app", version, []byte("body-"+itoa(version)), keyID, testNow.Add(-time.Hour), key.Sign)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if mutate != nil {
		mutate(p)
	}
	return p
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// assertReject ensures the exact failure code and prints input + basis.
func assertReject(t *testing.T, name string, r Result, want FailureCode) {
	t.Helper()
	if r.OK {
		t.Fatalf("%s: expected rejection %q but package ACCEPTED; input key=%q version=%d",
			name, want, r.KeyID, r.Version)
	}
	if r.Code != want {
		t.Fatalf("%s: expected %q but got %q (%s); input key=%q version=%d; basis=%s",
			name, want, r.Code, r.Message, r.KeyID, r.Version, r.Message)
	}
	t.Logf("%s: correctly rejected code=%q key=%q version=%d basis=%q", name, r.Code, r.KeyID, r.Version, r.Message)
}

func TestVerifyAcceptsValidPackage(t *testing.T) {
	f := newFixture(t)
	r := f.v.VerifyPackage(f.pkg(t, "active", 5, nil))
	if !r.OK {
		t.Fatalf("valid package rejected: %s", r.Message)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	f := newFixture(t)
	p := f.pkg(t, "active", 5, func(p *firmware.Package) { p.Payload[0] ^= 0xFF })
	assertReject(t, "tampered-payload", f.v.VerifyPackage(p), FailurePayloadHashMismatch)
}

func TestVerifyRejectsTamperedMetadata(t *testing.T) {
	f := newFixture(t)
	p := f.pkg(t, "active", 5, func(p *firmware.Package) { p.Meta.Version = 6 })
	assertReject(t, "tampered-metadata-version", f.v.VerifyPackage(p), FailureBadSignature)
}

func TestVerifyRejectsWrongKeySignature(t *testing.T) {
	f := newFixture(t)
	// Both keys are currently valid for firmware; signature was made with
	// active2 but the package names active, so trust passes but Ed25519 fails.
	signer := f.signers["active2"]
	p, err := firmware.NewBuilder().Build("dev1", "app", 5, []byte("body-5"), "active", testNow.Add(-time.Hour), signer.Sign)
	if err != nil {
		t.Fatal(err)
	}
	assertReject(t, "wrong-key-for-signature", f.v.VerifyPackage(p), FailureBadSignature)
}

func TestVerifyRejectsUnknownKey(t *testing.T) {
	f := newFixture(t)
	rogue, err := trust.GenerateTestKey("rogue", "rogue-seed", string(firmware.PurposeFirmware), testNow.Add(-day), testNow.Add(day))
	if err != nil {
		t.Fatal(err)
	}
	p, err := firmware.NewBuilder().Build("dev1", "app", 5, []byte("body-5"), "rogue", testNow.Add(-time.Hour), rogue.Sign)
	if err != nil {
		t.Fatal(err)
	}
	assertReject(t, "unknown-key", f.v.VerifyPackage(p), FailureUnknownKey)
}

func TestVerifyRejectsExpiredAndFutureKeys(t *testing.T) {
	f := newFixture(t)
	assertReject(t, "expired-key", f.v.VerifyPackage(f.pkg(t, "expired", 5, nil)), FailureKeyExpired)
	assertReject(t, "future-key", f.v.VerifyPackage(f.pkg(t, "future", 5, nil)), FailureKeyNotYetValid)
}

func TestVerifyRejectsRecoveryKeyForFirmware(t *testing.T) {
	f := newFixture(t)
	assertReject(t, "purpose-mismatch", f.v.VerifyPackage(f.pkg(t, "recovery", 5, nil)), FailureKeyPurposeMismatch)
}

func TestKeyBoundaryInstants(t *testing.T) {
	// At exactly NotBefore the key is valid; at exactly NotAfter it is expired.
	nb := testNow.Add(-time.Hour)
	na := testNow
	k, err := trust.GenerateTestKey("edge", "e", string(firmware.PurposeFirmware), nb, na)
	if err != nil {
		t.Fatal(err)
	}
	root := trust.NewRoot()
	if err := root.AddKey(trust.PublicKey{ID: "edge", PublicKey: k.Public, Purpose: firmware.PurposeFirmware, NotBefore: nb, NotAfter: na}); err != nil {
		t.Fatal(err)
	}
	d := root.Evaluate("edge", firmware.PurposeFirmware, nb)
	if !d.Accepted {
		t.Fatalf("key should be valid exactly at NotBefore: %s", d.Reason)
	}
	d = root.Evaluate("edge", firmware.PurposeFirmware, na)
	if d.Accepted {
		t.Fatalf("key should be expired exactly at NotAfter")
	}
}

func TestRoundTripMalformedContainers(t *testing.T) {
	if _, err := firmware.Decode([]byte("XXXX")); err == nil {
		t.Fatal("bad magic must error")
	}
	if _, err := firmware.Decode(append([]byte(firmware.ContainerMagic), 0, 0)); err == nil {
		t.Fatal("truncated container must error")
	}
	f := newFixture(t)
	if r := f.v.VerifyPackage(nil); r.Code != FailureMalformedPackage {
		t.Fatalf("nil package = %v, want malformed_package", r.Code)
	}
}
