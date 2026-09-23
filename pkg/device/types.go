// Package device simulates an on-device firmware state store with two slots:
// a committed known-good slot and a staging slot. All transitions are
// crash-safe via atomic file renames on the local filesystem.
package device

import (
	"errors"
	"sync"
	"time"
)

// SlotState describes what is stored in one slot.
type SlotState struct {
	Model       string    `json:"model"`
	Target      string    `json:"target"`
	Version     uint64    `json:"version"`
	PayloadHash []byte    `json:"payload_hash"`
	InstalledAt time.Time `json:"installed_at"`
	Present     bool      `json:"present"`
}

// PendingActivation records a staged install awaiting activation.
type PendingActivation struct {
	FromVersion uint64    `json:"from_version"` // known-good version to roll back to
	ToVersion   uint64    `json:"to_version"`   // staged version to activate
	StagedHash  []byte    `json:"staged_hash"`
	CreatedAt   time.Time `json:"created_at"`
}

// State is the full durable device state.
type State struct {
	Model     string
	Committed SlotState
	Staged    SlotState
	Pending   *PendingActivation // nil when not mid-update
	BootCount int                // boots of the active (unconfirmed) image
}

// ErrNotPending is returned when activation is requested without staging.
var ErrNotPending = errors.New("no staged update pending activation")

// Store is the file-backed device state store.
type Store struct {
	dir   string
	mu    *sync.Mutex
	inner internalState
}
