// Package demo wires a fully local demonstration environment: deterministic
// test Ed25519 keys, a trust root exercising key-rotation edge cases, a
// simulated A/B device and a directory for signed packages. Nothing here
// contacts any external service or uses real key material.
package demo

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/security"
	"github.com/h3yow/secure-firmware-update-go/pkg/signing"
	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
)

// Well-known key ids and model used by the demo environment.
const (
	ModelBox100 = "box-100"

	KeyCurrent = "key-fw-2026" // valid during 2026, firmware purpose
	KeyNext    = "key-fw-2027" // valid from 2027 (not-yet-valid in 2026)
	KeyOld     = "key-fw-2024" // expired end of 2025
	KeyOther   = "key-maint"   // in-window but wrong purpose
)

// Environment bundles local demo artifacts.
type Environment struct {
	Dir       string
	Root      *trust.Root
	Device    *device.Device
	Verifier  *security.Verifier
	TrustPath string
	DeviceDir string
	Packages  string
}

// Signer returns the deterministic demo signer for a key id.
func Signer(keyID string) (*signing.Signer, error) {
	return signing.GenerateKey(keyID, "demo:"+keyID)
}

func utc(y int, mon time.Month, d int) int64 {
	return time.Date(y, mon, d, 0, 0, 0, 0, time.UTC).Unix()
}

// Setup creates a fresh demo environment under dir.
func Setup(dir string) (*Environment, error) {
	ids := []string{KeyCurrent, KeyNext, KeyOld, KeyOther}
	keys := make([]trust.Key, 0, len(ids))
	for _, id := range ids {
		s, err := Signer(id)
		if err != nil {
			return nil, err
		}
		k := trust.Key{
			ID:        id,
			Algorithm: trust.AlgEd25519,
			Public:    s.Public(),
		}
		switch id {
		case KeyCurrent:
			k.NotBefore = utc(2026, 1, 1)
			k.NotAfter = utc(2026, 12, 31)
			k.Purposes = []trust.Purpose{trust.PurposeFirmware}
		case KeyNext:
			k.NotBefore = utc(2027, 1, 1)
			k.NotAfter = utc(2028, 12, 31)
			k.Purposes = []trust.Purpose{trust.PurposeFirmware}
		case KeyOld:
			k.NotBefore = utc(2024, 1, 1)
			k.NotAfter = utc(2025, 12, 31)
			k.Purposes = []trust.Purpose{trust.PurposeFirmware}
		case KeyOther:
			k.NotBefore = utc(2026, 1, 1)
			k.NotAfter = utc(2026, 12, 31)
			k.Purposes = []trust.Purpose{trust.PurposeOther}
		}
		keys = append(keys, k)
	}

	root := &trust.Root{Version: 1, Keys: keys}
	trustPath := filepath.Join(dir, "trust.json")
	if err := root.Save(trustPath); err != nil {
		return nil, fmt.Errorf("save trust root: %w", err)
	}
	devDir := filepath.Join(dir, "device")
	dev, err := device.Open(devDir, ModelBox100)
	if err != nil {
		return nil, err
	}
	return &Environment{
		Dir:       dir,
		Root:      root,
		Device:    dev,
		Verifier:  security.NewVerifier(root),
		TrustPath: trustPath,
		DeviceDir: devDir,
		Packages:  filepath.Join(dir, "packages"),
	}, nil
}

// Open loads an existing demo environment from dir.
func Open(dir string) (*Environment, error) {
	root, err := trust.Load(filepath.Join(dir, "trust.json"))
	if err != nil {
		return nil, err
	}
	dev, err := device.Open(filepath.Join(dir, "device"), ModelBox100)
	if err != nil {
		return nil, err
	}
	return &Environment{
		Dir:       dir,
		Root:      root,
		Device:    dev,
		Verifier:  security.NewVerifier(root),
		TrustPath: filepath.Join(dir, "trust.json"),
		DeviceDir: filepath.Join(dir, "device"),
		Packages:  filepath.Join(dir, "packages"),
	}, nil
}

// SetClock pins the verifier clock (used by --at).
func (e *Environment) SetClock(t time.Time) {
	e.Verifier.NowFn = func() time.Time { return t }
}
