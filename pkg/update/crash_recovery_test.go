package update

import (
	"errors"
	"testing"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
)

// TestInstallCrashWhileOverwritingHistoryRecovers is the engine-level history
// cleanup interruption: v2 confirmed (v1 retained); installing v3 overwrites
// the single retained slot; the payload write fails as if power was cut. After
// reboot the device must boot the known-good v2, carry no pending update, and
// the v3 install retried from scratch must complete — no wipe needed.
func TestInstallCrashWhileOverwritingHistoryRecovers(t *testing.T) {
	e := setup(t)
	defer e.close()

	o := e.eng.Install(e.pkg(2, nil))
	assertCode(t, "install-v2", o, OutcomeInstalled, "valid v2")
	if c := e.eng.ConfirmBoot(); c.Code != OutcomeConfirmed {
		t.Fatalf("confirm v2: %+v", c)
	}

	_ = e.eng.Install(e.pkg(3, nil), device.WithFaultHook(func(step string) error {
		if step == "stage.blob" {
			return errors.New("simulated power loss during retained slot overwrite")
		}
		return nil
	}))

	// Reboot: boot recovery must land on v2 with no pending update.
	eng := e.reopen()
	bo, err := eng.Boot()
	if err != nil {
		t.Fatal(err)
	}
	assertCode(t, "boot-after-cleanup-crash", bo, OutcomeIdempotentNoop, "reboot on known-good after retained-slot overwrite crash")
	if bo.CurrentAfter != 2 {
		t.Fatalf("after crash reboot current=%d want 2", bo.CurrentAfter)
	}
	st, _ := e.store.State()
	if st.Pending != nil {
		t.Fatalf("pending=%+v, want nil", st.Pending)
	}
	if st.Committed.Version != 2 {
		t.Fatalf("committed=%d want 2", st.Committed.Version)
	}

	// Chain continues: v3 installs cleanly and becomes running after confirm.
	retry := e.eng.Install(e.pkg(3, nil))
	assertCode(t, "retry-v3", retry, OutcomeInstalled, "retry v3 after crash recovery")
	if c := e.eng.ConfirmBoot(); c.Code != OutcomeConfirmed {
		t.Fatalf("confirm v3: %+v", c)
	}
	if e.curVersion() != 3 {
		t.Fatalf("current=%d want 3", e.curVersion())
	}
	st, _ = e.store.State()
	if st.Retained.Version != 2 || versionsOnDevice(st) != 2 {
		t.Fatalf("post-recovery retained=%d count=%d", st.Retained.Version, versionsOnDevice(st))
	}

	// Reopen once more: reconciliation is idempotent across repeated boots.
	e.reopen()
	st, _ = e.store.State()
	if st.Committed.Version != 3 {
		t.Fatalf("final current=%d want 3", st.Committed.Version)
	}
}
