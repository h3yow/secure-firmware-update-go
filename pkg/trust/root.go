package trust

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
)

// NewRoot creates an empty root of trust.
func NewRoot() *RootOfTrust { return &RootOfTrust{} }

// AddKey registers a trusted public key. Duplicate IDs and overlapping
// purpose windows for the same key ID are rejected so rotation state remains
// unambiguous.
func (r *RootOfTrust) AddKey(k PublicKey) error {
	if k.ID == "" {
		return errors.New("trust: empty key id")
	}
	if len(k.PublicKey) == 0 {
		return errors.New("trust: empty public key")
	}
	if k.Purpose != firmware.PurposeFirmware && k.Purpose != firmware.PurposeRecovery {
		return fmt.Errorf("trust: unknown key purpose %q", k.Purpose)
	}
	if !k.NotBefore.Before(k.NotAfter) {
		return fmt.Errorf("trust: key %q has empty/negative validity window", k.ID)
	}
	for i := range r.keys {
		old := r.keys[i]
		if old.ID != k.ID {
			continue
		}
		if old.Purpose == k.Purpose && windowsOverlap(old.NotBefore, old.NotAfter, k.NotBefore, k.NotAfter) {
			return fmt.Errorf("trust: key %q already registered with overlapping validity for purpose %q", k.ID, k.Purpose)
		}
	}
	k.NotBefore = k.NotBefore.UTC()
	k.NotAfter = k.NotAfter.UTC()
	k.PublicKey = append([]byte(nil), k.PublicKey...)
	r.keys = append(r.keys, k)
	sort.SliceStable(r.keys, func(i, j int) bool { return r.keys[i].ID < r.keys[j].ID })
	return nil
}

func windowsOverlap(aB, aA, bB, bA time.Time) bool {
	return aB.Before(bA) && bB.Before(aA)
}

// Lookup returns the registered key with the given id. Keys of different
// purposes may share an id; the caller narrows with Evaluate.
func (r *RootOfTrust) Lookup(id string) (PublicKey, bool) {
	for _, k := range r.keys {
		if k.ID == id {
			return k, true
		}
	}
	return PublicKey{}, false
}

// Keys returns a copy of the registered keys (sorted by ID).
func (r *RootOfTrust) Keys() []PublicKey {
	out := make([]PublicKey, len(r.keys))
	copy(out, r.keys)
	return out
}

// Evaluate decides deterministically whether the key identified by keyID is
// acceptable for purpose at instant now. It never falls back to "try every
// key": the package names exactly one KeyID and that key must be present,
// match the purpose, and be inside [NotBefore, NotAfter). At the exact
// NotAfter instant a key is already expired (half-open window).
func (r *RootOfTrust) Evaluate(keyID string, purpose firmware.Purpose, now time.Time) Decision {
	now = now.UTC()
	var matches []PublicKey
	for _, k := range r.keys {
		if k.ID == keyID {
			matches = append(matches, k)
		}
	}
	if len(matches) == 0 {
		return Decision{Accepted: false, KeyID: keyID, Reason: "no registered key with this id"}
	}
	// Purpose is a hard filter; a recovery key can never sign firmware.
	var purposeMatches []PublicKey
	for _, k := range matches {
		if k.Purpose == purpose {
			purposeMatches = append(purposeMatches, k)
		}
	}
	if len(purposeMatches) == 0 {
		return Decision{Accepted: false, KeyID: keyID, Reason: fmt.Sprintf("key exists but none is valid for purpose %q", purpose)}
	}
	// Registration rejects overlapping windows for the same (id, purpose),
	// so at most one entry can contain now. We still select deterministically.
	sort.SliceStable(purposeMatches, func(i, j int) bool {
		return purposeMatches[i].NotBefore.Before(purposeMatches[j].NotBefore)
	})
	for _, k := range purposeMatches {
		if now.Before(k.NotBefore) {
			return Decision{Accepted: false, KeyID: keyID, Reason: fmt.Sprintf("key not yet valid before %s", k.NotBefore.Format(time.RFC3339))}
		}
		if now.Equal(k.NotAfter) || now.After(k.NotAfter) {
			return Decision{Accepted: false, KeyID: keyID, Reason: fmt.Sprintf("key expired at %s", k.NotAfter.Format(time.RFC3339))}
		}
		return Decision{Accepted: true, KeyID: keyID, Reason: "key within validity window and matching purpose"}
	}
	return Decision{Accepted: false, KeyID: keyID, Reason: "no usable key window"}
}
