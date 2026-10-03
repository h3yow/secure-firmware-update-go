package update

import (
	"sync"
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/verify"
)

// blockingClockWithSignal returns a verification clock that blocks on its
// first invocation (while the winner holds the engine gate but no store mutex)
// until release is closed. This lets losers provably overlap the winner's
// transaction without a store-lock deadlock; later calls return the fixed time.
func blockingClockWithSignal(entered chan<- struct{}, release <-chan struct{}) func() time.Time {
	var once sync.Once
	return func() time.Time {
		once.Do(func() {
			close(entered)
			<-release
		})
		return now
	}
}

// TestConcurrentInstallsSingleWinner fires many install requests for the same
// next version while the winner's transaction is held open inside the engine
// gate. Exactly one takes effect; every overlapping loser receives the stable
// update_busy rejection (no corruption, no second install). After the winner
// commits, a resubmitted identical update is rejected as same_version_replay.
func TestConcurrentInstallsSingleWinner(t *testing.T) {
	e := setup(t)
	defer e.close()

	const n = 16
	winnerEntered := make(chan struct{})
	releaseWinner := make(chan struct{})
	// Winner verifier blocks during trust evaluation (gate held, store lock
	// not held), giving losers a deterministic overlap window.
	e.eng.verifier = verify.New(e.root, blockingClockWithSignal(winnerEntered, releaseWinner))

	winnerRes := make(chan Outcome, 1)
	go func() {
		winnerRes <- e.eng.Install(e.pkg(2, nil))
	}()
	<-winnerEntered

	results := make([]Outcome, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = e.eng.Install(e.pkg(2, nil))
		}(i)
	}
	close(start)
	wg.Wait()

	for i, o := range results {
		if o.Code != OutcomeRejected || o.Reason.Policy != PolicyUpdateBusy {
			t.Fatalf("loser %d: want update_busy, got code=%q reason=%+v", i, o.Code, o.Reason)
		}
		if o.CurrentAfter != 1 {
			t.Fatalf("loser %d changed running version to %d", i, o.CurrentAfter)
		}
	}
	t.Logf("overlapping losers: %d/%d rejected update_busy while one install held the device", n, n)

	close(releaseWinner)
	win := <-winnerRes
	assertCode(t, "winner", win, OutcomeInstalled, "v2 transaction held open then released")
	if e.curVersion() != 2 {
		t.Fatalf("running=%d want 2", e.curVersion())
	}
	st, _ := e.store.State()
	if st.Pending == nil || st.Pending.ToVersion != 2 || versionsOnDevice(st) != 2 {
		t.Fatalf("state after concurrent storm wrong: %+v", st)
	}

	// Restore normal verifier, then: sequential duplicate after commit is the
	// stable idempotent replay rejection.
	e.eng.verifier = verify.New(e.root, func() time.Time { return now })
	dup := e.eng.Install(e.pkg(2, nil))
	assertCode(t, "dup-after-busy", dup, OutcomeRejected, "same v2 resubmitted after winner finished")
	if dup.Reason.Policy != PolicySameVersionReplay {
		t.Fatalf("want same_version_replay, got %+v", dup.Reason)
	}
	e.eng.ConfirmBoot()
}

// TestConcurrentMixedOpsStayCoherent mixes boot/confirm/rollback/install across
// goroutines: the gate serializes them and the device always ends coherent
// (a present running version and at most two versions on device).
func TestConcurrentMixedOpsStayCoherent(t *testing.T) {
	e := setup(t)
	defer e.close()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for k := 0; k < 10; k++ {
				e.eng.Boot()
				e.eng.ConfirmBoot()
				e.eng.Rollback()
				if id == 0 && k == 0 {
					// Only one goroutine attempts the upgrade; it either
					// installs or loses to the gate, both are coherent.
					e.eng.Install(e.pkg(2, nil))
				}
			}
		}(g)
	}
	wg.Wait()
	st, _ := e.store.State()
	if !st.Committed.Present || st.Committed.Version == 0 {
		t.Fatalf("state corrupted by mixed storm: %+v", st)
	}
	if n := versionsOnDevice(st); n > 2 {
		t.Fatalf("device accumulated %d versions, want <= 2", n)
	}
	t.Logf("post-storm coherent: current=%d retained=%d pending=%v versions=%d",
		st.Committed.Version, st.Retained.Version, st.Pending != nil, versionsOnDevice(st))
}
