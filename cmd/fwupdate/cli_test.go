package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/update"
	"github.com/h3yow/secure-firmware-update-go/pkg/verify"
)

// captureOut swaps the CLI output writer for a buffer during fn.
func captureOut(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := out
	out = &buf
	defer func() { out = old }()
	fn()
	return buf.String()
}

func lastOutcome(t *testing.T, jsonOut string) update.Outcome {
	t.Helper()
	var o update.Outcome
	if err := json.Unmarshal(bytes.TrimSpace([]byte(jsonOut)), &o); err != nil {
		t.Fatalf("CLI did not print an Outcome: %v\n%s", err, jsonOut)
	}
	return o
}

// apiRig mirrors the CLI wiring (same model, keys, fixed clock) over a
// separate device directory, so CLI and library outcomes can be compared
// step by step.
type apiRig struct {
	t   *testing.T
	dir string
	st  *device.Store
	eng *update.Engine
}

func newAPIRig(t *testing.T) *apiRig {
	t.Helper()
	r := &apiRig{t: t, dir: filepath.Join(t.TempDir(), "device")}
	root, _, err := demoRoot()
	if err != nil {
		t.Fatal(err)
	}
	st, err := device.Open(r.dir, model)
	if err != nil {
		t.Fatal(err)
	}
	r.st = st
	v := verify.New(root, func() time.Time { return fixedNow })
	r.eng = update.New(st, v, func() time.Time { return fixedNow })
	return r
}

func (r *apiRig) factoryInit() {
	r.t.Helper()
	if err := r.st.FactoryInit(device.SlotState{
		Model: model, Target: target, Version: 1,
		PayloadHash: firmware.HashPayload([]byte("factory-v1")), InstalledAt: fixedNow.Add(-30 * day),
	}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *apiRig) pkg(t *testing.T, ver uint64, keyID string) *firmware.Package {
	t.Helper()
	_, keys, err := demoRoot()
	if err != nil {
		t.Fatal(err)
	}
	p, err := firmware.NewBuilder().Build(model, target, ver,
		[]byte("firmware-body-v"+itoa(ver)), keyID, fixedNow.Add(-time.Hour), keys[keyID].Sign)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestCLIAndAPIAgreeOnContinuousChain drives the same continuous
// upgrade/rollback sequence through the CLI commands and the library API and
// requires identical outcomes (code + reason + versions) at every step.
func TestCLIAndAPIAgreeOnContinuousChain(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SFW_HOME", home)

	// CLI init + API factory init.
	if err := cmdInit(home); err != nil {
		t.Fatal(err)
	}
	rig := newAPIRig(t)
	defer rig.st.Close()
	rig.factoryInit()

	type step struct {
		name string
		cli  func() update.Outcome
		api  func() update.Outcome
	}
	install := func(file string, ver uint64, keyID string) step {
		return step{
			name: "install-" + file,
			cli: func() update.Outcome {
				return lastOutcome(t, captureOut(t, func() {
					if err := cmdInstall(home, []string{file}); err != nil {
						t.Fatal(err)
					}
				}))
			},
			api: func() update.Outcome { return rig.eng.Install(rig.pkg(t, ver, keyID)) },
		}
	}
	simple := func(name string, cliFn func() error, apiFn func() update.Outcome) step {
		return step{
			name: name,
			cli: func() update.Outcome {
				return lastOutcome(t, captureOut(t, func() {
					if err := cliFn(); err != nil {
						t.Fatal(err)
					}
				}))
			},
			api: apiFn,
		}
	}

	build := func(file string, ver uint64, keyID string) {
		args := []string{file, itoa(ver)}
		if keyID != "" {
			args = append(args, keyID)
		}
		if err := cmdBuild(home, args); err != nil {
			t.Fatal(err)
		}
	}
	build("v2.sfw", 2, "")
	build("v3.sfw", 3, "")
	build("v4.sfw", 4, "")
	build("v5k1.sfw", 5, keyV1) // signed with the expired key

	steps := []step{
		install("v2.sfw", 2, keyV2),
		simple("confirm-v2", func() error { return cmdConfirm(home) }, func() update.Outcome { return rig.eng.ConfirmBoot() }),
		install("v3.sfw", 3, keyV2), // continuous: no reset between rounds
		simple("confirm-v3", func() error { return cmdConfirm(home) }, func() update.Outcome { return rig.eng.ConfirmBoot() }),
		simple("revert-to-v2", func() error { return cmdRollback(home) }, func() update.Outcome { return rig.eng.Rollback() }),
		install("v4.sfw", 4, keyV2),
		install("v4.sfw", 4, keyV2), // duplicate submission while pending: idempotent
		install("v3.sfw", 3, keyV2), // different update in flight: stable rejection
		simple("confirm-v4", func() error { return cmdConfirm(home) }, func() update.Outcome { return rig.eng.ConfirmBoot() }),
		install("v3.sfw", 3, keyV2),   // now a plain downgrade
		install("v5k1.sfw", 5, keyV1), // expired key: deterministic rejection
	}
	for i, s := range steps {
		gotCLI := s.cli()
		gotAPI := s.api()
		if gotCLI != gotAPI {
			t.Fatalf("step %d (%s): CLI=%+v API=%+v", i, s.name, gotCLI, gotAPI)
		}
		t.Logf("step=%02d %-16s code=%q %d->%d current=%d basis=%+v",
			i, s.name, gotCLI.Code, gotCLI.FromVersion, gotCLI.ToVersion, gotCLI.CurrentAfter, gotCLI.Reason)
	}
}
