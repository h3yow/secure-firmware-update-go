package update

import (
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/verify"
)

// TestConcurrentInstallsAcrossEngineInstances models two entry points (e.g. two
// nearly-simultaneous CLI invocations, or library vs CLI) each holding their own
// Store over the same device directory. The in-process gate cannot serialize
// them; the device file lock must, so exactly one install wins and the other
// receives the same stable update_busy conclusion it would get in-process.
func TestConcurrentInstallsAcrossEngineInstances(t *testing.T) {
	e := setup(t)
	defer e.close()

	// First process begins an install and holds it open (file lock taken).
	entered := make(chan struct{})
	release := make(chan struct{})
	e.eng.verifier = verify.New(e.root, blockingClockWithSignal(entered, release))
	winnerRes := make(chan Outcome, 1)
	go func() { winnerRes <- e.eng.Install(e.pkg(2, nil)) }()
	<-entered

	// Second process: independent Store + Engine over the same directory.
	st2, err := device.Open(e.dir, "dev1")
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	eng2 := New(st2, verify.New(e.root, func() time.Time { return now }), func() time.Time { return now })
	lose := eng2.Install(e.pkg(2, nil))
	assertCode(t, "cross-instance-loser", lose, OutcomeRejected, "second Store/Engine while first install holds device lock")
	if lose.Reason.Policy != PolicyUpdateBusy {
		t.Fatalf("want update_busy across instances, got %+v", lose.Reason)
	}
	if lose.CurrentAfter != 1 {
		t.Fatalf("loser changed version to %d", lose.CurrentAfter)
	}

	close(release)
	win := <-winnerRes
	assertCode(t, "cross-instance-winner", win, OutcomeInstalled, "first process install")
	if win.CurrentAfter != 2 {
		t.Fatalf("winner current=%d want 2", win.CurrentAfter)
	}
}
