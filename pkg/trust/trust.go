// Package trust implements the local root of trust: a set of trusted public
// keys with validity windows and intended purposes, stored as local JSON.
// During key rotation several keys may be trusted at once; resolution of the
// acceptable key for a package is fully deterministic and never silently
// prefers one matching key over another.
package trust

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Purpose constrains what a trusted key may be used for.
type Purpose string

const (
	// PurposeFirmware is the purpose required to sign firmware packages.
	PurposeFirmware Purpose = "firmware-signing"
	PurposeOther    Purpose = "other"
)

// Algorithm identifiers accepted in a trust root.
const (
	AlgEd25519 = "ed25519"
)

// Key is one trusted public key with its validity window and purposes.
type Key struct {
	ID        string    `json:"id"`
	Algorithm string    `json:"algorithm"`
	Public    []byte    `json:"public"`
	NotBefore int64     `json:"not_before"` // unix seconds, inclusive
	NotAfter  int64     `json:"not_after"`  // unix seconds, inclusive
	Purposes  []Purpose `json:"purposes"`
}

// Root is the root of trust loaded from a local file.
type Root struct {
	Version int   `json:"version"`
	Keys    []Key `json:"keys"`
}

// Load reads and validates a trust root JSON file.
func Load(path string) (*Root, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load trust root %s: %w", path, err)
	}
	var r Root
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse trust root %s: %w", path, err)
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Save writes a trust root JSON file atomically (temp file + fsync + rename).
func (r *Root) Save(path string) error {
	if err := r.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".trust-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (r *Root) validate() error {
	seen := map[string]bool{}
	for _, k := range r.Keys {
		if k.ID == "" {
			return fmt.Errorf("trust root: key with empty id")
		}
		if seen[k.ID] {
			// Duplicate IDs make "the unique key for this id" undefined.
			return fmt.Errorf("trust root: duplicate key id %q", k.ID)
		}
		seen[k.ID] = true
		if k.Algorithm != AlgEd25519 {
			return fmt.Errorf("trust root: key %q unsupported algorithm %q", k.ID, k.Algorithm)
		}
		if len(k.Public) != ed25519.PublicKeySize {
			return fmt.Errorf("trust root: key %q public key must be %d bytes, got %d", k.ID, ed25519.PublicKeySize, len(k.Public))
		}
		if k.NotBefore > k.NotAfter {
			return fmt.Errorf("trust root: key %q validity window inverted (%d > %d)", k.ID, k.NotBefore, k.NotAfter)
		}
		if len(k.Purposes) == 0 {
			return fmt.Errorf("trust root: key %q has no purposes", k.ID)
		}
	}
	return nil
}

// FindKey returns the trusted key with the given id, or nil.
func (r *Root) FindKey(id string) *Key {
	for i := range r.Keys {
		if r.Keys[i].ID == id {
			return &r.Keys[i]
		}
	}
	return nil
}

// hasPurpose reports whether k lists purpose p.
func (k *Key) hasPurpose(p Purpose) bool {
	for _, q := range k.Purposes {
		if q == p {
			return true
		}
	}
	return false
}

// Validity explains a key's time-window status at t.
type Validity int

const (
	ValidityTimeOK  Validity = iota
	ValidityFuture           // NotBefore is in the future
	ValidityExpired          // NotAfter is in the past
)

func (k *Key) validityAt(t time.Time) Validity {
	now := t.Unix()
	switch {
	case now < k.NotBefore:
		return ValidityFuture
	case now > k.NotAfter:
		return ValidityExpired
	default:
		return ValidityTimeOK
	}
}

// AcceptableKey resolves the unique acceptable key for id at time t for the
// given purpose. Trust roots reject duplicate IDs at load time, so at most one
// key with the id exists; ambiguous therefore stays reserved for duplicated
// material situations and is returned defensively. The returned reason string
// explains the basis of the decision.
func (r *Root) AcceptableKey(id string, purpose Purpose, t time.Time) (key *Key, ambiguous bool, reason string) {
	var matches []Key
	for _, k := range r.Keys {
		if k.ID == id {
			matches = append(matches, k)
		}
	}
	if len(matches) == 0 {
		return nil, false, fmt.Sprintf("no trusted key with id=%q", id)
	}
	if len(matches) > 1 {
		// Deterministic listing of the colluding IDs for the error basis.
		ids := make([]string, len(matches))
		for i := range matches {
			ids[i] = matches[i].ID
		}
		sort.Strings(ids)
		return nil, true, fmt.Sprintf("%d keys share id=%q: %v", len(matches), id, ids)
	}
	k := &matches[0]
	switch k.validityAt(t) {
	case ValidityFuture:
		return nil, false, fmt.Sprintf("key %q not valid before %s (now=%s)", k.ID, time.Unix(k.NotBefore, 0).UTC().Format(time.RFC3339), t.UTC().Format(time.RFC3339))
	case ValidityExpired:
		return nil, false, fmt.Sprintf("key %q expired at %s (now=%s)", k.ID, time.Unix(k.NotAfter, 0).UTC().Format(time.RFC3339), t.UTC().Format(time.RFC3339))
	}
	if !k.hasPurpose(purpose) {
		return nil, false, fmt.Sprintf("key %q purposes %v do not include required purpose %q", k.ID, k.Purposes, purpose)
	}
	return k, false, fmt.Sprintf("key %q within validity window and purpose %q allowed", k.ID, purpose)
}
