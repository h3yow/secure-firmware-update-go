// Command fwupdate is a local, self-contained CLI for the firmware update
// engine: trust-root setup, deterministic package signing, verification and
// the one-shot/staged update and rollback flows against a simulated A/B device.
//
// Everything runs against local files; no network or real key material is used.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/h3yow/secure-firmware-update-go/internal/demo"
	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/update"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	dir := envOr("FWDEMO_DIR", ".fwdemo")

	var err error
	switch cmd {
	case "init":
		_, err = demo.Setup(dir)
		if err == nil {
			fmt.Printf("initialized demo environment in %s (model=%s, factory 0.0.1 on slot A)\n", dir, demo.ModelBox100)
		}
	case "sign":
		err = cmdSign(dir, args)
	case "verify", "install", "prepare", "activate", "rollback", "status", "root", "tamper":
		err = cmdFlow(dir, cmd, args)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `fwupdate - local secure firmware update demo

usage:
  fwupdate init
  fwupdate sign   <version> <key-id> <out.fwpkg> [--target A|B]
  fwupdate verify <pkg.fwpkg>
  fwupdate install  <pkg.fwpkg>     (verify -> stage -> activate, one-shot)
  fwupdate prepare  <pkg.fwpkg>     (verify -> stage; activate separately)
  fwupdate activate
  fwupdate rollback
  fwupdate status
  fwupdate root
  fwupdate tamper <in.fwpkg> <out.fwpkg>   (flip one payload byte)

global options (via flags on any flow command):
  --at RFC3339     pin verification clock (key expiry demos)
  --dir PATH       demo directory (default .fwdemo or $FWDEMO_DIR)

demo key ids:
  key-fw-2026  valid, firmware-signing purpose   (use for normal packages)
  key-fw-2027  not valid until 2027
  key-fw-2024  expired end of 2025
  key-maint    valid window but wrong purpose
`)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// popFlags extracts --at and --dir from args, returning the positional args.
func popFlags(args []string) (pos []string, at time.Time, dirOverride string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--at":
			i++
			if i >= len(args) {
				return nil, at, "", fmt.Errorf("--at needs an RFC3339 value")
			}
			at, err = time.Parse(time.RFC3339, args[i])
			if err != nil {
				return nil, at, "", fmt.Errorf("--at: %w", err)
			}
		case strings.HasPrefix(a, "--at="):
			at, err = time.Parse(time.RFC3339, strings.TrimPrefix(a, "--at="))
			if err != nil {
				return nil, at, "", fmt.Errorf("--at: %w", err)
			}
		case a == "--dir":
			i++
			if i >= len(args) {
				return nil, at, "", fmt.Errorf("--dir needs a value")
			}
			dirOverride = args[i]
		case strings.HasPrefix(a, "--dir="):
			dirOverride = strings.TrimPrefix(a, "--dir=")
		default:
			pos = append(pos, a)
		}
	}
	return pos, at, dirOverride, nil
}

func openEnv(dir string, at time.Time) (*demo.Environment, error) {
	e, err := demo.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("open demo env (did you run 'fwupdate init'?): %w", err)
	}
	if !at.IsZero() {
		e.SetClock(at.UTC())
	}
	return e, nil
}

func cmdSign(dir string, args []string) error {
	pos, _, dirOverride, err := popFlags(args)
	if err != nil {
		return err
	}
	if dirOverride != "" {
		dir = dirOverride
	}
	target := device.SlotB
	filtered := make([]string, 0, len(pos))
	for i := 0; i < len(pos); i++ {
		a := pos[i]
		switch {
		case a == "--target":
			i++
			if i >= len(pos) || (pos[i] != device.SlotA && pos[i] != device.SlotB) {
				return fmt.Errorf("--target must be A or B")
			}
			target = pos[i]
		case strings.HasPrefix(a, "--target="):
			t := strings.TrimPrefix(a, "--target=")
			if t != device.SlotA && t != device.SlotB {
				return fmt.Errorf("--target must be A or B")
			}
			target = t
		default:
			filtered = append(filtered, a)
		}
	}
	pos = filtered
	if len(pos) != 3 {
		return fmt.Errorf("sign needs <version> <key-id> <out.fwpkg>")
	}
	version, keyID, out := pos[0], pos[1], pos[2]
	if _, err := firmware.ParseVersion(version); err != nil {
		return err
	}
	s, err := demo.Signer(keyID)
	if err != nil {
		return err
	}
	// Deterministic demo payload: readable header padded to 256 bytes.
	head := fmt.Sprintf("FIRMWARE model=%s version=%s target=%s", demo.ModelBox100, version, target)
	payload := make([]byte, 256)
	copy(payload, head)

	m := firmware.Manifest{
		PackageID:  "pkg-" + version,
		Model:      demo.ModelBox100,
		TargetSlot: target,
		Version:    version,
		PayloadKey: "release",
		IssuedAt:   time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC).Unix(),
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	if err := s.SignPackage(m, payload, out); err != nil {
		return err
	}
	fmt.Printf("signed %s with %s -> %s (target slot %s)\n", version, keyID, out, target)
	return nil
}

func cmdFlow(dir, cmd string, args []string) error {
	pos, at, dirOverride, err := popFlags(args)
	if err != nil {
		return err
	}
	if dirOverride != "" {
		dir = dirOverride
	}
	if cmd == "tamper" {
		if len(pos) != 2 {
			return fmt.Errorf("tamper needs <in.fwpkg> <out.fwpkg>")
		}
		return tamper(pos[0], pos[1])
	}

	e, err := openEnv(dir, at)
	if err != nil {
		return err
	}
	eng := update.New(e.Device, e.Verifier)

	switch cmd {
	case "root":
		fmt.Printf("trust root %s, %d keys:\n", e.TrustPath, len(e.Root.Keys))
		for _, k := range e.Root.Keys {
			fmt.Printf("  - %-12s %s  [%s,%s]  purposes=%v\n", k.ID, k.Algorithm,
				time.Unix(k.NotBefore, 0).UTC().Format("2006-01-02"),
				time.Unix(k.NotAfter, 0).UTC().Format("2006-01-02"), k.Purposes)
		}
		return nil
	case "status":
		s := e.Device.Snapshot()
		fmt.Printf("model=%s active=%s version=%s has_staged=%v", s.Model, s.ActiveSlot,
			s.Slots[s.ActiveSlot].Version, s.HasStaged)
		if s.HasStaged {
			fmt.Printf(" staged=%s@%s", s.StagedSlot, s.StagedVer)
		}
		if s.HasRollback {
			fmt.Printf(" rollback_slot=%s@%s", s.RollbackSlot, s.Slots[s.RollbackSlot].Version)
		}
		fmt.Println()
		return nil
	case "verify":
		if len(pos) != 1 {
			return fmt.Errorf("verify needs <pkg.fwpkg>")
		}
		return printOutcome(eng.VerifyOnly(pos[0]))
	case "install":
		if len(pos) != 1 {
			return fmt.Errorf("install needs <pkg.fwpkg>")
		}
		return printOutcome(eng.Install(pos[0]))
	case "prepare":
		if len(pos) != 1 {
			return fmt.Errorf("prepare needs <pkg.fwpkg>")
		}
		return printOutcome(eng.Prepare(pos[0]))
	case "activate":
		return printOutcome(eng.Activate())
	case "rollback":
		return printOutcome(eng.Rollback())
	}
	return nil
}

func printOutcome(o *update.Outcome) error {
	if o.Success {
		fmt.Printf("[ACCEPT] action=%s active_slot=%s version=%s\n", o.Action, o.Slot, o.Version)
		return nil
	}
	f := o.Failure
	fmt.Printf("[REJECT] action=%s code=%s\n", o.Action, f.Code)
	fmt.Printf("  reason: %s\n", f.Reason)
	fmt.Printf("  input : %s\n", f.Input)
	fmt.Printf("  basis : %s\n", f.Basis)
	return fmt.Errorf("%s", f.Code)
}

// tamper flips one byte inside the payload region of a package container,
// preserving the (now invalid) manifest and signature.
func tamper(in, out string) error {
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	// Payload is the final field; flip a byte near the end of the file.
	i := len(data) - 1
	if i < len(firmware.Magic)+20 {
		return fmt.Errorf("package too small to tamper")
	}
	data[i] ^= 0xFF
	return os.WriteFile(out, data, 0o644)
}
