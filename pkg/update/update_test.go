package update

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
	"github.com/h3yow/secure-firmware-update-go/pkg/verify"
)

var now = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

type env struct {
	t       *testing.T
	dir     string
	store   *device.Store
	root    *trust.RootOfTrust
	signers map[string]trust.TestKey
	eng     *Engine
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "dev")
	st, err := device.Open(dir, "dev1")
	if err != nil {
		t.Fatal(err)
	}
	root := trust.NewRoot()
	signers := map[string]trust.TestKey{}
	mk := func(id, purpose string, nb, na time.Time) {
		k, err := trust.GenerateTestKey(id, "seed-"+id, purpose, nb, na)
		if err != nil {
			t.Fatal(err)
		}
		if err := root.AddKey(trust.PublicKey{ID: id, PublicKey: k.Public, Purpose: firmware.Purpose(purpose), NotBefore: nb, NotAfter: na}); err != nil {
			t.Fatal(err)
		}
		signers[id] = k
	}
	mk("k", string(firmware.PurposeFirmware), now.Add(-day), now.Add(day))
	v := verify.New(root, func() time.Time { return now })
	eng := New(st, v, func() time.Time { return now })
	e := &env{t: t, dir: dir, store: st, root: root, signers: signers, eng: eng}
	if err := st.FactoryInit(device.SlotState{
		Model: "dev1", Target: "app", Version: 1,
		PayloadHash: firmware.HashPayload([]byte("v1")), InstalledAt: now.Add(-day),
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) close() { e.t.Helper(); _ = e.store.Close() }

// reopen simulates a device reboot: a brand new Store over the same directory.
func (e *env) reopen() *Engine {
	e.t.Helper()
	_ = e.store.Close()
	st, err := device.Open(e.dir, "dev1")
	if err != nil {
		e.t.Fatal(err)
	}
	e.store = st
	v := verify.New(e.root, func() time.Time { return now })
	e.eng = New(st, v, func() time.Time { return now })
	return e.eng
}

func (e *env) pkg(version uint64, mutate func(*firmware.Package)) *firmware.Package {
	e.t.Helper()
	k := e.signers["k"]
	p, err := firmware.NewBuilder().Build("dev1", "app", version, []byte("body-v"+itoa(version)), "k", now.Add(-time.Hour), k.Sign)
	if err != nil {
		e.t.Fatal(err)
	}
	if mutate != nil {
		mutate(p)
	}
	return p
}

func (e *env) pkgCustom(model, target string, key string, version uint64) *firmware.Package {
	e.t.Helper()
	k, ok := e.signers[key]
	if !ok {
		e.t.Fatalf("no key %q", key)
	}
	p, err := firmware.NewBuilder().Build(model, target, version, []byte("x"), key, now.Add(-time.Hour), k.Sign)
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *env) curVersion() uint64 {
	e.t.Helper()
	st, err := e.store.State()
	if err != nil {
		e.t.Fatal(err)
	}
	return st.Committed.Version
}

func assertCode(t *testing.T, name string, o Outcome, want OutcomeCode, inputDesc string) {
	t.Helper()
	if o.Code != want {
		t.Fatalf("%s: want code=%q got=%q reason=%+v; input=%s", name, want, o.Code, o.Reason, inputDesc)
	}
	t.Logf("%s: code=%q %d->%d current=%d basis=%+v", name, o.Code, o.FromVersion, o.ToVersion, o.CurrentAfter, o.Reason)
}

func TestHappyPathInstallConfirm(t *testing.T) {
	e := setup(t)
	defer e.close()
	o := e.eng.Install(e.pkg(2, nil))
	assertCode(t, "install-v2", o, OutcomeInstalled, "valid v2")
	if e.curVersion() != 2 {
		t.Fatalf("active version=%d want 2", e.curVersion())
	}
	c := e.eng.ConfirmBoot()
	assertCode(t, "confirm", c, OutcomeConfirmed, "confirm after trial boot")
	// Confirming again is a stable no-op.
	c2 := e.eng.ConfirmBoot()
	assertCode(t, "confirm-again", c2, OutcomeIdempotentNoop, "repeat confirm")
}

func TestDowngradeAndReplayRejected(t *testing.T) {
	e := setup(t)
	defer e.close()
	o := e.eng.Install(e.pkg(2, nil))
	assertCode(t, "install-v2", o, OutcomeInstalled, "v2")
	e.eng.ConfirmBoot()

	down := e.eng.Install(e.pkg(1, nil))
	assertCode(t, "downgrade-v1", down, OutcomeRejected, "signed v1 over v2")
	if down.Reason.Policy != PolicyDowngrade {
		t.Fatalf("want downgrade reason, got %+v", down.Reason)
	}
	if e.curVersion() != 2 {
		t.Fatalf("downgrade must not change version, got %d", e.curVersion())
	}

	replay := e.eng.Install(e.pkg(2, nil))
	assertCode(t, "replay-v2", replay, OutcomeRejected, "same v2 again")
	if replay.Reason.Policy != PolicySameVersionReplay {
		t.Fatalf("want same_version_replay, got %+v", replay.Reason)
	}
}

func TestModelAndTargetMismatch(t *testing.T) {
	e := setup(t)
	defer e.close()
	badModel := e.eng.Install(e.pkgCustom("dev-OTHER", "app", "k", 2))
	assertCode(t, "model-mismatch", badModel, OutcomeRejected, "model=dev-OTHER v2")
	if badModel.Reason.Policy != PolicyModelMismatch {
		t.Fatalf("got %+v", badModel.Reason)
	}
	badTarget := e.eng.Install(e.pkgCustom("dev1", "bootloader", "k", 2))
	assertCode(t, "target-mismatch", badTarget, OutcomeRejected, "target=bootloader v2")
	if badTarget.Reason.Policy != PolicyTargetMismatch {
		t.Fatalf("got %+v", badTarget.Reason)
	}
	if e.curVersion() != 1 {
		t.Fatalf("device must remain v1, got %d", e.curVersion())
	}
}

func TestTamperedPackageRejected(t *testing.T) {
	e := setup(t)
	defer e.close()
	o := e.eng.Install(e.pkg(2, func(p *firmware.Package) { p.Payload[0] ^= 1 }))
	assertCode(t, "tampered", o, OutcomeRejected, "bit-flipped payload v2")
	if o.Reason.Verification != verify.FailurePayloadHashMismatch {
		t.Fatalf("want payload_hash_mismatch, got %+v", o.Reason)
	}
	if e.curVersion() != 1 {
		t.Fatalf("tampered install must leave v1, got %d", e.curVersion())
	}
}

func TestStageCrashBeforePersistLeavesKnownGood(t *testing.T) {
	e := setup(t)
	defer e.close()
	injected := errors.New("power loss")
	o := e.eng.Install(e.pkg(2, nil), device.WithFaultHook(func(step string) error {
		if step == "stage.state" {
			return injected
		}
		return nil
	}))
	assertCode(t, "stage-crash", o, OutcomeFailedSafe, "crash at stage.state")

	// Reboot: recovery must leave the device on v1 with no pending update.
	eng := e.reopen()
	bo, err := eng.Boot()
	if err != nil {
		t.Fatal(err)
	}
	if bo.CurrentAfter != 1 {
		t.Fatalf("after stage crash + boot, version=%d want 1", bo.CurrentAfter)
	}
	st, _ := e.store.State()
	if st.Pending != nil {
		t.Fatalf("staged-but-unactivated update must be discarded at boot, pending=%+v", st.Pending)
	}
}

func TestActivateThenPowerLossAutoRollsBack(t *testing.T) {
	e := setup(t)
	defer e.close()
	o := e.eng.Install(e.pkg(2, nil))
	assertCode(t, "install-v2", o, OutcomeInstalled, "v2 activated as trial")

	// Device reboots twice without confirming (watchdog of bad image).
	eng := e.reopen()
	b1, _ := eng.Boot()
	if b1.CurrentAfter != 2 {
		t.Fatalf("first trial boot should keep v2, got %d", b1.CurrentAfter)
	}
	eng2 := e.reopen()
	b2, _ := eng2.Boot()
	assertCode(t, "second-boot-rollback", b2, OutcomeRolledBack, "unconfirmed trial reboot")
	if b2.CurrentAfter != 1 {
		t.Fatalf("auto rollback version=%d want 1", b2.CurrentAfter)
	}

	// Boot again: stable no-op on known-good.
	eng3 := e.reopen()
	b3, _ := eng3.Boot()
	assertCode(t, "boot-after-rollback", b3, OutcomeIdempotentNoop, "boot on known-good")
}

func TestExplicitRollbackMatchesAutomaticPath(t *testing.T) {
	run := func(automatic bool) uint64 {
		e := setup(t)
		defer e.close()
		o := e.eng.Install(e.pkg(2, nil))
		assertCode(t, "install-v2", o, OutcomeInstalled, "v2")
		if automatic {
			eng := e.reopen()
			_, _ = eng.Boot()
			eng2 := e.reopen()
			r, _ := eng2.Boot()
			return r.CurrentAfter
		}
		r := e.eng.Rollback()
		assertCode(t, "explicit-rollback", r, OutcomeRolledBack, "manual rollback")
		return r.CurrentAfter
	}
	if auto := run(true); auto != 1 {
		t.Fatalf("automatic path ended at %d want 1", auto)
	}
	if manual := run(false); manual != 1 {
		t.Fatalf("manual path ended at %d want 1", manual)
	}
}

func TestRollbackIdempotent(t *testing.T) {
	e := setup(t)
	defer e.close()
	e.eng.Install(e.pkg(2, nil))
	r1 := e.eng.Rollback()
	assertCode(t, "rollback-1", r1, OutcomeRolledBack, "rollback")
	r2 := e.eng.Rollback()
	assertCode(t, "rollback-2", r2, OutcomeIdempotentNoop, "repeat rollback")
	if e.curVersion() != 1 {
		t.Fatalf("version=%d want 1", e.curVersion())
	}
}

func TestRetriedInstallAfterCrashIsStable(t *testing.T) {
	e := setup(t)
	defer e.close()
	// Crash before activate state persists.
	_ = e.eng.Install(e.pkg(2, nil), device.WithFaultHook(func(step string) error {
		if step == "activate.state" {
			return errors.New("power loss")
		}
		return nil
	}))
	if e.curVersion() != 1 {
		t.Fatalf("after failed activation version=%d want 1", e.curVersion())
	}
	// Retry the exact same update: it must install cleanly.
	o := e.eng.Install(e.pkg(2, nil))
	assertCode(t, "retry-install", o, OutcomeInstalled, "retry v2 after crash")
	if e.curVersion() != 2 {
		t.Fatalf("retry install version=%d want 2", e.curVersion())
	}
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
