package update

import (
	"testing"
)

// TestUpgradeRollbackReupgrade verifies the full operator loop after a
// confirmed upgrade: v1 -> v2 confirmed; roll back to retained v1; upgrade
// again to v2 (no wipe, no re-init); continue the chain to v3.
func TestUpgradeRollbackReupgrade(t *testing.T) {
	e := setup(t)
	defer e.close()

	o := e.eng.Install(e.pkg(2, nil))
	assertCode(t, "install-v2", o, OutcomeInstalled, "valid v2")
	c := e.eng.ConfirmBoot()
	assertCode(t, "confirm-v2", c, OutcomeConfirmed, "v2 healthy")

	rb := e.eng.Rollback()
	assertCode(t, "rollback-to-v1", rb, OutcomeRolledBack, "post-confirm rollback to retained v1")
	if rb.CurrentAfter != 1 {
		t.Fatalf("after rollback current=%d want 1", rb.CurrentAfter)
	}
	st, _ := e.store.State()
	if st.Committed.Version != 1 || st.Retained.Version != 2 {
		t.Fatalf("post-rollback slots: current=%d retained=%d", st.Committed.Version, st.Retained.Version)
	}
	if n := versionsOnDevice(st); n != 2 {
		t.Fatalf("post-rollback keeps %d versions, want 2", n)
	}

	// A second rollback cannot hop to v0: only one rollback generation exists.
	rb2 := e.eng.Rollback()
	assertCode(t, "rollback-again", rb2, OutcomeIdempotentNoop, "no older retained version")
	if e.curVersion() != 1 {
		t.Fatalf("current=%d must remain 1", e.curVersion())
	}

	// Re-upgrade to v2 without any wipe, then continue the chain.
	o = e.eng.Install(e.pkg(2, nil))
	assertCode(t, "reinstall-v2", o, OutcomeInstalled, "same v2 package after rollback")
	e.eng.ConfirmBoot()
	o = e.eng.Install(e.pkg(3, nil))
	assertCode(t, "continue-v3", o, OutcomeInstalled, "chain continues to v3")
	e.eng.ConfirmBoot()
	if e.curVersion() != 3 {
		t.Fatalf("current=%d want 3", e.curVersion())
	}
	st, _ = e.store.State()
	if st.Retained.Version != 2 || versionsOnDevice(st) != 2 {
		t.Fatalf("final retained=%d count=%d, want 2 and count 2", st.Retained.Version, versionsOnDevice(st))
	}
}

// TestManyUpgradeRollbackCyclesDoNotAccumulate runs many alternating
// upgrade/confirm and rollback cycles plus trial rollbacks, then asserts the
// device still holds exactly two versions, later upgrades are never refused
// because of history size, and the last installed version is running.
func TestManyUpgradeRollbackCyclesDoNotAccumulate(t *testing.T) {
	e := setup(t)
	defer e.close()
	current := uint64(1)
	for cycle := 0; cycle < 6; cycle++ {
		next := current + 1
		o := e.eng.Install(e.pkg(next, nil))
		assertCode(t, "cycle-install", o, OutcomeInstalled, "v"+itoa(next))
		e.eng.ConfirmBoot()
		current = next
		st, _ := e.store.State()
		if versionsOnDevice(st) != 2 {
			t.Fatalf("cycle %d: %d versions on device", cycle, versionsOnDevice(st))
		}
		// Every other cycle: exercise the post-confirm retained rollback and
		// upgrade back; the alternating cycles still chain upward afterwards.
		if cycle%2 == 0 {
			rb := e.eng.Rollback()
			assertCode(t, "cycle-retained-rollback", rb, OutcomeRolledBack, "back to v"+itoa(next-1))
			back := e.eng.Install(e.pkg(next, nil))
			assertCode(t, "cycle-reupgrade", back, OutcomeInstalled, "forward to v"+itoa(next)+" again")
			e.eng.ConfirmBoot()
			if e.curVersion() != next {
				t.Fatalf("cycle %d current=%d want %d", cycle, e.curVersion(), next)
			}
		}
	}
	st, _ := e.store.State()
	if st.Committed.Version != current {
		t.Fatalf("final running=%d want %d", st.Committed.Version, current)
	}
	if versionsOnDevice(st) != 2 {
		t.Fatalf("final device keeps %d versions, want 2", versionsOnDevice(st))
	}
}
