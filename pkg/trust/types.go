// Package trust implements the local-only root of trust: trusted public keys
// with validity windows and intended purposes, plus deterministic in-memory
// test key material. No network and no real key material is involved.
package trust

import (
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
)

// PublicKey is one trusted verification key in the root of trust.
type PublicKey struct {
	ID        string
	PublicKey []byte // Ed25519 public key
	Purpose   firmware.Purpose
	NotBefore time.Time
	NotAfter  time.Time
}

// RootOfTrust is the set of currently trusted keys. Multiple keys may be
// valid at the same time during rotation; acceptance is decided strictly by
// the package's KeyID, never by silently trying every key.
type RootOfTrust struct {
	keys []PublicKey
}

// Decision explains why a key was accepted or rejected.
type Decision struct {
	Accepted bool
	KeyID    string
	Reason   string
}
