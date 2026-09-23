package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"
)

// TestKey is a deterministic, locally generated signing key. It is NOT real
// key material: the private scalar is derived from a human-readable seed via
// SHA-256 and exists only in process memory.
type TestKey struct {
	ID        string
	seed      string
	priv      ed25519.PrivateKey
	Public    []byte
	Purpose   string
	NotBefore time.Time
	NotAfter  time.Time
}

// GenerateTestKey deterministically derives an Ed25519 test key from seed.
// The same (id, seed) arguments always yield the same key pair.
func GenerateTestKey(id, seed, purpose string, notBefore, notAfter time.Time) (TestKey, error) {
	if id == "" || seed == "" {
		return TestKey{}, errors.New("trust: key id and seed are required")
	}
	if !notBefore.Before(notAfter) {
		return TestKey{}, errors.New("trust: NotBefore must be strictly before NotAfter")
	}
	digest := sha256.Sum256([]byte("sfw-testkey|" + id + "|" + seed + "|" + purpose))
	priv := ed25519.NewKeyFromSeed(digest[:])
	return TestKey{
		ID:        id,
		seed:      seed,
		priv:      priv,
		Public:    append([]byte(nil), priv.Public().(ed25519.PublicKey)...),
		Purpose:   purpose,
		NotBefore: notBefore.UTC(),
		NotAfter:  notAfter.UTC(),
	}, nil
}

// Sign signs message with the deterministic test key.
func (k TestKey) Sign(message []byte) ([]byte, error) {
	if k.priv == nil {
		return nil, errors.New("trust: uninitialized test key")
	}
	return ed25519.Sign(k.priv, message), nil
}
