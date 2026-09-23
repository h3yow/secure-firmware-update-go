// Package signing produces signed firmware packages with locally generated
// Ed25519 keys. Keys are deterministically derived from a seed label purely
// for reproducible local tests; no external services or real key material are
// ever involved.
package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
)

// Signer holds an Ed25519 private key and the key id it signs as.
type Signer struct {
	KeyID string
	priv  ed25519.PrivateKey
}

// deriveSeed produces a deterministic 32-byte test seed from a label.
// This is NOT a security boundary: it exists only so tests and demos are
// reproducible without storing private key material in the repository.
func deriveSeed(seedLabel string) [32]byte {
	var seed [32]byte
	sum := sha256.Sum256([]byte("secure-firmware-update-go/test-key/v1:" + seedLabel))
	copy(seed[:], sum[:])
	return seed
}

// GenerateKey deterministically derives a test key from a seed label.
func GenerateKey(keyID string, seedLabel string) (*Signer, error) {
	if keyID == "" {
		return nil, fmt.Errorf("signing: empty key id")
	}
	seed := deriveSeed(seedLabel)
	// ed25519.NewKeyFromSeed copies the seed internally.
	priv := ed25519.NewKeyFromSeed(seed[:])
	return &Signer{KeyID: keyID, priv: priv}, nil
}

// Public returns the raw Ed25519 public key (32 bytes).
func (s *Signer) Public() []byte {
	pub := s.priv.Public().(ed25519.PublicKey)
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, pub)
	return out
}

// Sign returns the raw Ed25519 signature over message.
func (s *Signer) Sign(message []byte) []byte {
	return ed25519.Sign(s.priv, message)
}

// SignPackage fills manifest integrity fields, serializes and writes a signed
// firmware package to outPath (written via temp file + rename).
func (s *Signer) SignPackage(m firmware.Manifest, payload []byte, outPath string) error {
	m.Schema = firmware.CurrentSchema
	m.PayloadSize = int64(len(payload))
	m.PayloadSHA256 = firmware.PayloadSHA256Hex(payload)

	manifestBytes, err := firmware.CanonicalManifest(&m)
	if err != nil {
		return err
	}
	sig := s.Sign(manifestBytes)
	encoded, err := firmware.Encode(manifestBytes, sig, s.KeyID, payload)
	if err != nil {
		return err
	}
	return writeFileAtomic(outPath, encoded)
}

func writeFileAtomic(path string, data []byte) (err error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".fwpkg-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
