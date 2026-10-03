package update

import (
	"testing"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
)

// TestContinuousUpgradeChain covers the headline new behavior: from the
// factory version a device chains v1 -> v2 -> v3 -> v4 -> v5, confirming
// health after every step, with no rollback/wipe/re-init between steps.
// After every step the running version is the last installed one and exactly
// two versions exist on device (current + one rollback target).
func TestContinuousUpgradeChain(t *testing.T) {
	e := setup(t)
	defer e.close()

	for v := uint64(2); v <= 5; v++ {
		input := "valid signed v" + itoa(v) + " signed by key k"
		o := e.eng.Install(e.pkg(v, nil))
		assertCode(t, "install-v"+itoa(v), o, OutcomeInstalled, input)
		if o.CurrentAfter != v {
			t.Fatalf("after install v%d running=%d", v, o.CurrentAfter)
		}
		// Trial is running: another install must wait for confirm.
		blocked := e.eng.Install(e.pkg(v+1, nil))
		assertCode(t, "install-while-trial-v"+itoa(v), blocked, OutcomeRejected, "v"+itoa(v+1)+" while v"+itoa(v)+" unconfirmed")
		if blocked.Reason.Policy != PolicyTrialUnconfirmed {
			t.Fatalf("want trial_unconfirmed, got %+v", blocked.Reason)
		}
		c := e.eng.ConfirmBoot()
		assertCode(t, "confirm-v"+itoa(v), c, OutcomeConfirmed, "health confirmed for v"+itoa(v))

		st, _ := e.store.State()
		if st.Committed.Version != v {
			t.Fatalf("step v%d: running version=%d want %d", v, st.Committed.Version, v)
		}
		if st.Retained.Version != v-1 {
			t.Fatalf("step v%d: retained version=%d want %d", v, st.Retained.Version, v-1)
		}
		if n := versionsOnDevice(st); n != 2 {
			t.Fatalf("step v%d: device keeps %d versions, want exactly 2", v, n)
		}
	}

	// Survives reboot with the last version running and bounded history.
	eng := e.reopen()
	bo, err := eng.Boot()
	if err != nil {
		t.Fatal(err)
	}
	if bo.CurrentAfter != 5 {
		t.Fatalf("after reboot chain current=%d want 5", bo.CurrentAfter)
	}
	st, _ := e.store.State()
	if n := versionsOnDevice(st); n != 2 {
		t.Fatalf("after reboot keeps %d versions, want 2", n)
	}
}

// versionsOnDevice counts distinct present versions visible in device state.
func versionsOnDevice(st device.State) int {
	seen := map[uint64]bool{}
	if st.Committed.Present {
		seen[st.Committed.Version] = true
	}
	if st.Staged.Present {
		seen[st.Staged.Version] = true
	}
	if st.Retained.Present {
		seen[st.Retained.Version] = true
	}
	return len(seen)
}
