package signing

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
)

func TestSignPackageRoundtripAndTamper(t *testing.T) {
	dir := t.TempDir()
	s, err := GenerateKey("k1", "seed-xyz")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Public()) != ed25519.PublicKeySize {
		t.Fatalf("public key size %d", len(s.Public()))
	}
	payload := []byte("payload-bytes")
	m := firmware.Manifest{
		PackageID: "p", Model: "m", TargetSlot: "B",
		Version: "1.2.3", PayloadKey: "k", IssuedAt: 7,
	}
	path := filepath.Join(dir, "a.fwpkg")
	if err := s.SignPackage(m, payload, path); err != nil {
		t.Fatal(err)
	}
	pkg, err := firmware.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.KeyID != "k1" {
		t.Fatalf("key id=%q", pkg.KeyID)
	}
	pub := ed25519.PublicKey(s.Public())
	if !ed25519.Verify(pub, pkg.ManifestBytes, pkg.Signature) {
		t.Fatal("signature must verify against signer public key")
	}
	if pkg.Manifest.PayloadSHA256 != firmware.PayloadSHA256Hex(payload) {
		t.Fatal("signed payload hash mismatch")
	}

	// Determinism: same label reproduces the same key.
	s2, _ := GenerateKey("k1", "seed-xyz")
	if string(s2.Public()) != string(s.Public()) {
		t.Fatal("deterministic key derivation changed")
	}
}
