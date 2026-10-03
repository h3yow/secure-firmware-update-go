package update

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
	"github.com/h3yow/secure-firmware-update-go/pkg/verify"
)

// chainEnv is a test rig with a movable clock and multiple signing keys, so
// continuous upgrade chains can cross key-rotation windows.
type chainEnv struct {
	t       *testing.T
	dir     string
	clock   time.Time
	store   *device.Store
	root    *trust.RootOfTrust
	signers map[string]trust.TestKey
	eng     *Engine
}

func newChainEnv(t *testing.T, start time.Time) *chainEnv {
	t.Helper()
	e := &chainEnv{
		t:       t,
		dir:     t.TempDir() + "/dev",
		clock:   start,
		root:    trust.NewRoot(),
		signers: map[string]trust.TestKey{},
	}
	e.reopen()
	return e
}

func (e *chainEnv) addKey(id string, nb, na time.Time) {
	e.t.Helper()
	k, err := trust.GenerateTestKey(id, "seed-"+id, string(firmware.PurposeFirmware), nb, na)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.root.AddKey(trust.PublicKey{
		ID: id, PublicKey: k.Public, Purpose: firmware.PurposeFirmware,
		NotBefore: nb, NotAfter: na,
	}); err != nil {
		e.t.Fatal(err)
	}
	e.signers[id] = k
}

// reopen simulates a device reboot over the same storage directory.
func (e *chainEnv) reopen() {
	e.t.Helper()
	if e.store != nil {
		_ = e.store.Close()
	}
	st, err := device.Open(e.dir, "dev1")
	if err != nil {
		e.t.Fatal(err)
	}
	e.store = st
	v := verify.New(e.root, func() time.Time { return e.clock })
	e.eng = New(st, v, func() time.Time { return e.clock })
}

func (e *chainEnv) pkg(key string, version uint64) *firmware.Package {
	e.t.Helper()
	k, ok := e.signers[key]
	if !ok {
		e.t.Fatalf("no key %q", key)
	}
	p, err := firmware.NewBuilder().Build("dev1", "app", version,
		[]byte(fmt.Sprintf("body-v%d", version)), key, e.clock.Add(-time.Hour), k.Sign)
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *chainEnv) factory(version uint64) {
	e.t.Helper()
	if err := e.store.FactoryInit(device.SlotState{
		Model: "dev1", Target: "app", Version: version,
		PayloadHash: firmware.HashPayload([]byte("factory")), InstalledAt: e.clock.Add(-day),
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *chainEnv) committed() uint64 {
	e.t.Helper()
	st, err := e.store.State()
	if err != nil {
		e.t.Fatal(err)
	}
	return st.Committed.Version
}

func (e *chainEnv) retained() (uint64, bool) {
	e.t.Helper()
	st, err := e.store.State()
	if err != nil {
		e.t.Fatal(err)
	}
	return st.Staged.Version, st.Staged.Present
}

// installConfirm runs one full round: install + reboot + confirm, asserting
// each step's conclusion.
func (e *chainEnv) installConfirm(key string, version uint64) {
	e.t.Helper()
	o := e.eng.Install(e.pkg(key, version))
	assertCode(t0(e.t), fmt.Sprintf("install-v%d", version), o, OutcomeInstalled,
		fmt.Sprintf("key=%s version=%d", key, version))
	e.reopen()
	if _, err := e.eng.Boot(); err != nil {
		e.t.Fatal(err)
	}
	c := e.eng.ConfirmBoot()
	assertCode(t0(e.t), fmt.Sprintf("confirm-v%d", version), c, OutcomeConfirmed, "confirm after trial boot")
	if got := e.committed(); got != version {
		e.t.Fatalf("after round: committed=%d want %d", got, version)
	}
}

func t0(t *testing.T) *testing.T { return t }

func TestContinuousUpgradeChain(t *testing.T) {
	e := newChainEnv(t, now)
	defer e.store.Close()
	e.addKey("k", now.Add(-day), now.Add(30*day))
	e.factory(1)

	for v := uint64(2); v <= 6; v++ {
		e.installConfirm("k", v)
		prev, present := e.retained()
		if !present || prev != v-1 {
			t.Fatalf("after v%d: retained previous=%d present=%v, want %d", v, prev, present, v-1)
		}
		t.Logf("round=v%d committed=%d retained_previous=%d", v, e.committed(), prev)
	}
	if got := e.committed(); got != 6 {
		t.Fatalf("final committed=%d want 6", got)
	}
	// The chain must keep accepting the next version without any reset.
	o := e.eng.Install(e.pkg("k", 7))
	assertCode(t, "install-v7", o, OutcomeInstalled, "v7 after 5 confirmed rounds")
}

func TestUpgradeRollbackUpgradeChain(t *testing.T) {
	e := newChainEnv(t, now)
	defer e.store.Close()
	e.addKey("k", now.Add(-day), now.Add(30*day))
	e.factory(1)

	// v2 trial is rolled back before confirm.
	o := e.eng.Install(e.pkg("k", 2))
	assertCode(t, "install-v2", o, OutcomeInstalled, "v2")
	r := e.eng.Rollback()
	assertCode(t, "rollback-v2-trial", r, OutcomeRolledBack, "rollback pending v2")
	if got := e.committed(); got != 1 {
		t.Fatalf("after rollback committed=%d want 1", got)
	}

	// The chain continues directly with v3: no reset needed.
	e.installConfirm("k", 3)

	// Post-confirm revert returns to the retained previous known-good (v1).
	r2 := e.eng.Rollback()
	assertCode(t, "revert-to-v1", r2, OutcomeRolledBack, "revert after confirm")
	if got := e.committed(); got != 1 {
		t.Fatalf("after revert committed=%d want 1", got)
	}
	if _, present := e.retained(); present {
		t.Fatal("revert discards the abandoned slot; nothing may remain retained")
	}

	// And the chain can still move forward afterwards.
	e.installConfirm("k", 4)
}

func TestCleanupInterruptedMidChain(t *testing.T) {
	e := newChainEnv(t, now)
	defer e.store.Close()
	e.addKey("k", now.Add(-day), now.Add(30*day))
	e.factory(1)
	e.installConfirm("k", 2) // committed v2, retained v1

	// Power loss while the staging of v3 is overwriting the retained v1 slot.
	injected := errors.New("power loss")
	o := e.eng.Install(e.pkg("k", 3), device.WithFaultHook(func(step string) error {
		if step == "stage.blob" {
			return injected
		}
		return nil
	}))
	assertCode(t, "crash-during-cleanup", o, OutcomeFailedSafe, "crash at stage.blob while overwriting v1")

	// Reboot: device stays on committed v2; the half-overwritten history slot
	// is pruned by the boot sweep.
	e.reopen()
	bo, err := e.eng.Boot()
	if err != nil {
		t.Fatal(err)
	}
	if bo.CurrentAfter != 2 {
		t.Fatalf("after interrupted cleanup boot: current=%d want 2", bo.CurrentAfter)
	}
	if _, present := e.retained(); present {
		t.Fatal("inconsistent retained slot must be pruned at boot")
	}
	t.Logf("scenario=cleanup-interrupted recovered_to=%d", bo.CurrentAfter)

	// Neither stuck nor forced to re-init: the same v3 installs cleanly now.
	e.installConfirm("k", 3)
	e.installConfirm("k", 4)
}

func TestConcurrentInstallsSingleWinner(t *testing.T) {
	e := newChainEnv(t, now)
	defer e.store.Close()
	e.addKey("k", now.Add(-day), now.Add(30*day))
	e.factory(1)

	var wg sync.WaitGroup
	outcomes := make([]Outcome, 2)
	for i, v := range []uint64{2, 3} {
		wg.Add(1)
		go func(i int, v uint64) {
			defer wg.Done()
			outcomes[i] = e.eng.Install(e.pkg("k", v))
		}(i, v)
	}
	wg.Wait()

	var installed, rejected int
	for _, o := range outcomes {
		switch {
		case o.Code == OutcomeInstalled:
			installed++
		case o.Code == OutcomeRejected && o.Reason.Policy == PolicyUpdateInProgress:
			rejected++
		default:
			t.Fatalf("unexpected concurrent outcome: %+v", o)
		}
		t.Logf("concurrent-install: code=%q %d->%d policy=%q", o.Code, o.FromVersion, o.ToVersion, o.Reason.Policy)
	}
	if installed != 1 || rejected != 1 {
		t.Fatalf("want exactly 1 installed + 1 rejected, got %d/%d", installed, rejected)
	}
	// State must be coherent: exactly one pending trial, committable.
	st, _ := e.store.State()
	if st.Pending == nil {
		t.Fatal("winner's update must be pending")
	}
	c := e.eng.ConfirmBoot()
	assertCode(t, "confirm-winner", c, OutcomeConfirmed, "confirm after concurrent installs")
	if got := e.committed(); got != st.Pending.ToVersion && got != 2 && got != 3 {
		t.Fatalf("committed=%d unexpected", got)
	}
}

func TestConcurrentDuplicateInstallIsIdempotent(t *testing.T) {
	e := newChainEnv(t, now)
	defer e.store.Close()
	e.addKey("k", now.Add(-day), now.Add(30*day))
	e.factory(1)

	var wg sync.WaitGroup
	outcomes := make([]Outcome, 2)
	for i := range outcomes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcomes[i] = e.eng.Install(e.pkg("k", 2))
		}(i)
	}
	wg.Wait()
	for _, o := range outcomes {
		assertCode(t, "duplicate-install", o, OutcomeInstalled, "same v2 submitted twice concurrently")
	}
	if got := e.committed(); got != 2 {
		t.Fatalf("duplicate install must activate v2 exactly once, committed=%d", got)
	}
	c := e.eng.ConfirmBoot()
	assertCode(t, "confirm", c, OutcomeConfirmed, "confirm after duplicate install")
}

func TestKeyRotationDuringContinuousChain(t *testing.T) {
	e := newChainEnv(t, now)
	defer e.store.Close()
	// Rotation window: old key valid until now+2d, new key valid from now+1d.
	e.addKey("k-old", now.Add(-day), now.Add(2*day))
	e.addKey("k-new", now.Add(day), now.Add(30*day))
	e.factory(1)

	// Before the window: only the old key is usable.
	e.installConfirm("k-old", 2)
	early := e.eng.Install(e.pkg("k-new", 3))
	assertCode(t, "new-key-too-early", early, OutcomeRejected, "v3 signed by k-new before its window")
	if early.Reason.Verification != verify.FailureKeyNotYetValid {
		t.Fatalf("want key_not_yet_valid, got %+v", early.Reason)
	}

	// Inside the rotation window both keys are valid; the chain continues
	// across the key change with a unique conclusion per package.
	e.clock = now.Add(day + 12*time.Hour)
	e.reopen()
	e.installConfirm("k-old", 3)
	e.installConfirm("k-new", 4)

	// After the old key expires it is rejected deterministically, while the
	// new key keeps the chain moving.
	e.clock = now.Add(3 * day)
	e.reopen()
	exp := e.eng.Install(e.pkg("k-old", 5))
	assertCode(t, "old-key-expired", exp, OutcomeRejected, "v5 signed by expired k-old")
	if exp.Reason.Verification != verify.FailureKeyExpired {
		t.Fatalf("want key_expired, got %+v", exp.Reason)
	}
	if got := e.committed(); got != 4 {
		t.Fatalf("expired-key rejection must not move the device, committed=%d want 4", got)
	}
	e.installConfirm("k-new", 5)
}

func TestContinuousChainKeepsDeviceDirBounded(t *testing.T) {
	e := newChainEnv(t, now)
	defer e.store.Close()
	e.addKey("k", now.Add(-day), now.Add(60*day))
	e.factory(1)
	for v := uint64(2); v <= 10; v++ {
		e.installConfirm("k", v)
		// A rollback/revert detour must not grow history either.
		if v == 5 {
			r := e.eng.Rollback()
			assertCode(t, "revert-detour", r, OutcomeRolledBack, "revert v5->v4 mid-chain")
			e.installConfirm("k", 6)
			v = 6
		}
	}
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 { // state.json + 2 slots x (json+bin)
		names := []string{}
		for _, en := range entries {
			names = append(names, en.Name())
		}
		t.Fatalf("device dir must stay bounded after many rounds, got %v", names)
	}
	t.Logf("scenario=bounded-dir rounds=9 files=%d committed=%d", len(entries), e.committed())
}
