// Command fwupdate is the local CLI entry point for the simulated secure
// firmware update engine. Everything is on the local filesystem with
// deterministic in-memory test keys: no network and no real key material.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
	"github.com/h3yow/secure-firmware-update-go/pkg/update"
	"github.com/h3yow/secure-firmware-update-go/pkg/verify"
)

// fixedNow keeps every local run reproducible regardless of wall clock.
var fixedNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

const (
	model  = "device-X100"
	target = "app"
	keyV1  = "k1"
	keyV2  = "k2"
	day    = 24 * time.Hour
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	rootDir := os.Getenv("SFW_HOME")
	if rootDir == "" {
		rootDir = filepath.Join(os.TempDir(), "sfw-demo")
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(rootDir)
	case "build":
		err = cmdBuild(rootDir, args)
	case "install":
		err = cmdInstall(rootDir, args)
	case "confirm":
		err = cmdConfirm(rootDir)
	case "rollback":
		err = cmdRollback(rootDir)
	case "boot":
		err = cmdBoot(rootDir)
	case "status":
		err = cmdStatus(rootDir)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `fwupdate - local secure firmware update simulation

usage:
  fwupdate init                       initialize device + trust root
  fwupdate build  <file> <version> [key] [--tamper]
  fwupdate install <file>
  fwupdate confirm
  fwupdate rollback
  fwupdate boot
  fwupdate status
`)
	os.Exit(2)
}

// out is where command results are printed; tests swap it for a buffer.
var out io.Writer = os.Stdout

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(out, string(b))
}

// demoRoot builds the trust root: k1 valid last year..yesterday (expired),
// k2 valid since 100 days ago for 200 days (current). This demonstrates
// rotation with one expired and one active key.
func demoRoot() (*trust.RootOfTrust, map[string]trust.TestKey, error) {
	root := trust.NewRoot()
	keys := map[string]trust.TestKey{}

	k1, err := trust.GenerateTestKey(keyV1, "seed-k1", string(firmware.PurposeFirmware),
		fixedNow.Add(-400*day), fixedNow.Add(-1*day))
	if err != nil {
		return nil, nil, err
	}
	k2, err := trust.GenerateTestKey(keyV2, "seed-k2", string(firmware.PurposeFirmware),
		fixedNow.Add(-100*day), fixedNow.Add(100*day))
	if err != nil {
		return nil, nil, err
	}
	for _, k := range []trust.TestKey{k1, k2} {
		keys[k.ID] = k
		if err := root.AddKey(trust.PublicKey{
			ID: k.ID, PublicKey: k.Public,
			Purpose:   firmware.Purpose(k.Purpose),
			NotBefore: k.NotBefore, NotAfter: k.NotAfter,
		}); err != nil {
			return nil, nil, err
		}
	}
	return root, keys, nil
}

func openEngine(rootDir string) (*update.Engine, *device.Store, error) {
	root, _, err := demoRoot()
	if err != nil {
		return nil, nil, err
	}
	st, err := device.Open(filepath.Join(rootDir, "device"), model)
	if err != nil {
		return nil, nil, err
	}
	v := verify.New(root, func() time.Time { return fixedNow })
	return update.New(st, v, func() time.Time { return fixedNow }), st, nil
}

func cmdInit(rootDir string) error {
	if err := os.MkdirAll(filepath.Join(rootDir, "packages"), 0o755); err != nil {
		return err
	}
	st, err := device.Open(filepath.Join(rootDir, "device"), model)
	if err != nil {
		return err
	}
	defer st.Close()
	err = st.FactoryInit(device.SlotState{
		Model:       model,
		Target:      target,
		Version:     1,
		PayloadHash: firmware.HashPayload([]byte("factory-v1")),
		InstalledAt: fixedNow.Add(-30 * day),
	}, []byte("factory-v1"))
	if err != nil {
		return err
	}
	fmt.Println("initialized device with factory firmware v1")
	return cmdStatus(rootDir)
}

func cmdBuild(rootDir string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("build needs <file> <version> [key] [--tamper]")
	}
	file, verStr := args[0], args[1]
	var ver uint64
	if _, err := fmt.Sscanf(verStr, "%d", &ver); err != nil {
		return fmt.Errorf("bad version: %w", err)
	}
	keyID := keyV2
	tamper := false
	for _, a := range args[2:] {
		switch a {
		case "--tamper":
			tamper = true
		default:
			keyID = a
		}
	}
	_, keys, err := demoRoot()
	if err != nil {
		return err
	}
	key, ok := keys[keyID]
	if !ok {
		return fmt.Errorf("unknown test key %q", keyID)
	}
	payload := []byte(fmt.Sprintf("firmware-body-v%d", ver))
	pkg, err := firmware.NewBuilder().Build(model, target, ver, payload, keyID, fixedNow.Add(-time.Hour), key.Sign)
	if err != nil {
		return err
	}
	if tamper {
		// Flip a payload byte in place: container length is unchanged, so it
		// decodes, but the signed SHA-256 no longer matches.
		pkg.Payload[0] ^= 0xFF
	}
	b, err := pkg.Encode()
	if err != nil {
		return err
	}
	path := filepath.Join(rootDir, "packages", file)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("built %s (version %d, signed by %s, tamper=%v)\n", path, ver, keyID, tamper)
	return nil
}

func cmdInstall(rootDir string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("install needs <file>")
	}
	eng, st, err := openEngine(rootDir)
	if err != nil {
		return err
	}
	defer st.Close()
	b, err := os.ReadFile(filepath.Join(rootDir, "packages", args[0]))
	if err != nil {
		return err
	}
	pkg, err := firmware.Decode(b)
	if err != nil {
		return err
	}
	printJSON(eng.Install(pkg))
	return nil
}

func cmdConfirm(rootDir string) error {
	eng, st, err := openEngine(rootDir)
	if err != nil {
		return err
	}
	defer st.Close()
	printJSON(eng.ConfirmBoot())
	return nil
}

func cmdRollback(rootDir string) error {
	eng, st, err := openEngine(rootDir)
	if err != nil {
		return err
	}
	defer st.Close()
	printJSON(eng.Rollback())
	return nil
}

func cmdBoot(rootDir string) error {
	eng, st, err := openEngine(rootDir)
	if err != nil {
		return err
	}
	defer st.Close()
	o, err := eng.Boot()
	if err != nil {
		return err
	}
	printJSON(o)
	return nil
}

func cmdStatus(rootDir string) error {
	_, st, err := openEngine(rootDir)
	if err != nil {
		return err
	}
	defer st.Close()
	s, err := st.State()
	if err != nil {
		return err
	}
	printJSON(s)
	return nil
}
