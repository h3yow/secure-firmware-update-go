// Package firmware defines the locally simulated firmware package format,
// its binary (de)serialization and integrity hashing.
package firmware

import "time"

// Purpose identifies the intended use of a signing key / signature.
type Purpose string

const (
	// PurposeFirmware signs firmware packages intended for installation.
	PurposeFirmware Purpose = "firmware"
	// PurposeRecovery signs recovery images (cannot be used for ordinary updates).
	PurposeRecovery Purpose = "recovery"
)

// Metadata is the signed header of a firmware package.
type Metadata struct {
	Model       string    // target device model; must match the device
	TargetSlot  string    // target slot, e.g. "app"
	Version     uint64    // monotonically increasing firmware version
	PayloadHash []byte    // SHA-256 of the payload bytes
	PayloadSize int64     // length of the payload bytes
	KeyID       string    // id of the key expected to verify Signature
	IssuedAt    time.Time // package issuance time
}

// Package is a parsed firmware package: metadata, raw payload and signature
// over the canonical metadata encoding.
type Package struct {
	Meta      Metadata
	Payload   []byte
	Signature []byte
}
