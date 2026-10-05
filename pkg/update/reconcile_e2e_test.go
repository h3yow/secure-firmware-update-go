package update

import (
	"errors"
	"testing"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
)

// TestInterruptedCleanupReconciledOnReopenWithoutBoot is the engine-level
// reproduction of the reported long-ops failure: the old-version cleanup
// fused into staging is interrupted; a NEW process then queries status and
// rolls back WITHOUT running boot recovery. The reported current version
// must match the payload actually running (no "says old, runs new"), the
// broken old slot must never be re-enabled, and later upgrades continue.
func TestInterruptedCleanupReconciledOnReopenWithoutBoot(t *testing.T) {
	e := setup(t)
	defer e.close()

	// Two confirmed rounds: current v2, retained v1.
	e.installConfirmEngine(t, 2)

	// Interrupt staging v3 (old-slot cleanup) after slot files replaced.
	injected := errors.New("power loss during cleanup")
	o := e.eng.Install(e.pkg(3, nil), device.WithFaultHook(func(step string) error {
		if step == "stage.state" {
			return injected
		}
		return nil
	}))
	assertCode(t, "crash-cleanup", o, OutcomeFailedSafe, "crash at stage.state overwriting retained slot")

	// Brand-new process, no Boot() call: plain status read.
	eng := e.reopen()
	st, err := e.store.State()
	if err != nil {
		t.Fatalf("status after interrupted cleanup must stay readable: %v", err)
	}
	t.Logf("scenario=interrupted-cleanup-no-boot input=crash-staging-v3 reported_current=%d retained_present=%v pending=%v",
		st.Committed.Version, st.Staged.Present, st.Pending != nil)
	if st.Committed.Version != 2 {
		t.Fatalf("reported current=%d must match really-running payload v2", st.Committed.Version)
	}
	if st.Staged.Present {
		t.Fatal("broken retained slot must not be reported as a usable rollback target")
	}

	// Rollback cannot resurrect the broken slot; nothing retained => no-op.
	r := eng.Rollback()
	assertCode(t, "rollback-after-reconcile", r, OutcomeIdempotentNoop, "no retained known-good after prune")
	if r.CurrentAfter != 2 {
		t.Fatalf("device must stay on known-good v2, got %d", r.CurrentAfter)
	}

	// Upgrades continue normally from the reconciled state.
	o2 := eng.Install(e.pkg(3, nil))
	assertCode(t, "install-v3-after-reconcile", o2, OutcomeInstalled, "v3 accepted after interrupted cleanup")
	if c := eng.ConfirmBoot(); c.Code != OutcomeConfirmed {
		t.Fatalf("confirm v3: %+v", c)
	}
	o3 := eng.Install(e.pkg(4, nil))
	assertCode(t, "install-v4-after-reconcile", o3, OutcomeInstalled, "chain continues to v4")
	t.Logf("result recovered_to=2 continued=3->4 final=%d", eng.ConfirmBoot().CurrentAfter)
}

// installConfirmEngine runs install+confirm in the same engine instance
// (no reboot), used when a test wants to control reopen timing itself.
func (e *env) installConfirmEngine(t *testing.T, v uint64) {
	t.Helper()
	o := e.eng.Install(e.pkg(v, nil))
	assertCode(t, "install", o, OutcomeInstalled, "valid package")
	c := e.eng.ConfirmBoot()
	assertCode(t, "confirm", c, OutcomeConfirmed, "confirm healthy trial")
	if got := e.curVersion(); got != v {
		t.Fatalf("after confirm v%d current=%d", v, got)
	}
}
