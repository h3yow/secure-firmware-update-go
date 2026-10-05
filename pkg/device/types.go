// Package device simulates an on-device firmware state store with two slots:
// a committed known-good slot and a staging slot. All transitions are
// crash-safe via atomic file renames on the local filesystem.
package device

import (
	"errors"
	"os"
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

// ErrSlotConflict is returned when a different update is staged while one is
// already pending: only one update may be in flight at a time.
var ErrSlotConflict = errors.New("a different update is already staged")

// ErrNothingToRevert is returned when a revert to the previous known-good
// version is requested but no previous version is retained on device.
var ErrNothingToRevert = errors.New("no previous known-good version retained")

// Store is the file-backed device state store.
//
// Concurrency contract: s.mu serializes goroutines inside this process, and
// an exclusive flock on <dir>/lock serializes whole operations across
// processes. Every operation re-reads state.json after taking the flock and
// reconciles it with the slot files on disk before use, so a Store never acts
// on a stale cached view of another process's commits.
type Store struct {
	dir      string
	model    string
	mu       *sync.Mutex
	lockFile *os.File
	inner    internalState
}
