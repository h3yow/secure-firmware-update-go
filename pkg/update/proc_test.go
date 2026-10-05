package update

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
)

// procResult is the single JSON line a child install process prints.
type procResult struct {
	PID       int     `json:"pid"`
	Version   uint64  `json:"version"`
	Outcome   Outcome `json:"outcome"`
	OutcomeOK bool    `json:"outcome_ok"`
}

// runInstallChild is the child-process entry point. It opens the same device
// directory independently (its own Engine, its own process), waits on a
// barrier file so all children start at the same instant, then installs the
// requested package version. This is a REAL second OS process, not a
// goroutine, so it exercises the flock-based arbitration end to end.
func TestInstallChild(t *testing.T) {
	dir := os.Getenv("SFW_TEST_DEVICE_DIR")
	verStr := os.Getenv("SFW_TEST_VERSION")
	barrier := os.Getenv("SFW_TEST_BARRIER")
	if dir == "" || verStr == "" {
		t.Skip("child mode env not set")
	}
	var ver uint64
	if _, err := fmt.Sscanf(verStr, "%d", &ver); err != nil {
		t.Fatal(err)
	}

	st, err := device.Open(dir, "dev1")
	if err != nil {
		emit(procResult{Version: ver, OutcomeOK: false}, err)
		return
	}
	defer st.Close()
	root := childRoot()
	v := newChildVerifier(root)
	eng := New(st, v, func() time.Time { return now })

	// Spin until the parent removes the barrier (all processes are parked).
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(barrier); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			emit(procResult{Version: ver, OutcomeOK: false}, fmt.Errorf("barrier timeout"))
			return
		}
		time.Sleep(time.Millisecond)
	}

	key := childSigner(t)
	p, err := firmware.NewBuilder().Build("dev1", "app", ver,
		[]byte(fmt.Sprintf("body-v%d", ver)), "k", now.Add(-time.Hour), key.Sign)
	if err != nil {
		t.Fatal(err)
	}
	o := eng.Install(p)
	emit(procResult{PID: os.Getpid(), Version: ver, Outcome: o, OutcomeOK: true}, nil)
}

func emit(r procResult, err error) {
	if err != nil {
		r.Outcome = failedSafe(0, r.Version, err.Error())
	}
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

// startInstallProcess spawns a real OS process that installs version ver.
func startInstallProcess(t *testing.T, dir string, ver uint64) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestInstallChild$", "-test.v")
	cmd.Env = append(os.Environ(),
		"SFW_TEST_DEVICE_DIR="+dir,
		fmt.Sprintf("SFW_TEST_VERSION=%d", ver),
		"SFW_TEST_BARRIER="+filepath.Join(dir, "..", "barrier"),
	)
	cmd.Stderr = nil // child's testing logs go to stderr; keep parent output clean
	return cmd
}

// collectChildResult parses the single JSON result line from child stdout.
func collectChildResult(t *testing.T, out []byte) procResult {
	t.Helper()
	var last procResult
	for _, line := range splitLines(string(out)) {
		var r procResult
		if err := json.Unmarshal([]byte(line), &r); err == nil {
			last = r
		}
	}
	if !last.OutcomeOK && last.Outcome.Code == "" {
		t.Fatalf("child produced no result; stdout=%q", string(out))
	}
	return last
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// spawnTwoInstallers starts two child processes (optionally with the same
// version) on a freshly factory-initialized device, parks them behind the
// barrier, releases the barrier and waits for both results.
func spawnTwoInstallers(t *testing.T, versions ...uint64) ([]procResult, string) {
	e := setup(t)
	t.Cleanup(func() { _ = e.store.Close() })
	return spawnTwoInstallersOn(t, e, versions...)
}

// spawnTwoInstallersOn is like spawnTwoInstallers but runs against an
// already initialized environment (e.g. a device advanced by earlier rounds).
func spawnTwoInstallersOn(t *testing.T, e *env, versions ...uint64) ([]procResult, string) {
	t.Helper()
	dir := e.dir

	barrier := filepath.Join(filepath.Dir(dir), "barrier")
	if err := os.WriteFile(barrier, []byte("hold"), 0o644); err != nil {
		t.Fatal(err)
	}

	var cmds []*exec.Cmd
	var outs [][]byte
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ver := range versions {
		cmd := startInstallProcess(t, dir, ver)
		b, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, cmd)
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 0, 4096)
			tmp := make([]byte, 4096)
			for {
				n, err := b.Read(tmp)
				if n > 0 {
					mu.Lock()
					buf = append(buf, tmp[:n]...)
					mu.Unlock()
				}
				if err != nil {
					break
				}
			}
			mu.Lock()
			outs = append(outs, buf)
			mu.Unlock()
		}()
	}

	// Give the children a moment to park on the barrier, then fire.
	time.Sleep(300 * time.Millisecond)
	if err := os.Remove(barrier); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Logf("child wait: %v", err)
		}
	}
	wg.Wait()

	results := make([]procResult, 0, len(outs))
	for _, o := range outs {
		results = append(results, collectChildResult(t, o))
	}
	return results, dir
}

// TestCrossProcessDistinctUpdatesSingleWinner is the real-process version
// of the concurrency requirement: two DIFFERENT updates installed from two
// simultaneously launched OS processes — exactly one may succeed, the other
// must receive the stable update_in_progress rejection. The device state
// afterwards must be readable and internally coherent.
func TestCrossProcessDistinctUpdatesSingleWinner(t *testing.T) {
	results, dir := spawnTwoInstallers(t, 2, 3)

	var installed, rejected int
	winner := uint64(0)
	for _, r := range results {
		o := r.Outcome
		switch {
		case o.Code == OutcomeInstalled:
			installed++
			winner = r.Version
		case o.Code == OutcomeRejected && o.Reason.Policy == PolicyUpdateInProgress:
			rejected++
		default:
			t.Fatalf("child v%d unexpected outcome: %+v", r.Version, o)
		}
		t.Logf("scenario=cross-process-distinct input=v%d code=%q %d->%d current=%d policy=%q basis=%s",
			r.Version, o.Code, o.FromVersion, o.ToVersion, o.CurrentAfter, o.Reason.Policy, o.Reason.Detail)
	}
	if installed != 1 || rejected != 1 {
		t.Fatalf("want exactly 1 installed + 1 update_in_progress, got %d/%d", installed, rejected)
	}

	// The device state file must be intact and agree with the winner.
	e := reopenFor(t, dir)
	defer e.store.Close()
	st, err := e.store.State()
	if err != nil {
		t.Fatalf("device state must remain readable after concurrent processes: %v", err)
	}
	if st.Pending == nil || st.Pending.ToVersion != winner {
		t.Fatalf("pending trial must belong to winner v%d, got %+v", winner, st.Pending)
	}
	if st.Committed.Version != winner {
		t.Fatalf("running version=%d must match winner v%d", st.Committed.Version, winner)
	}
	if o := e.eng.ConfirmBoot(); o.Code != OutcomeConfirmed || o.CurrentAfter != winner {
		t.Fatalf("winner must be confirmable after the race, got %+v", o)
	}
	t.Logf("result winner=v%d loser=update_in_progress confirmed_current=%d", winner, e.curVersion())
}

// TestCrossProcessDuplicateSubmissionIdempotent is the real-process version
// of the idempotency requirement: the SAME package submitted from two
// simultaneously launched OS processes behaves exactly like a single
// submission — both see "installed", the version lands exactly once, and
// the state is never corrupted.
func TestCrossProcessDuplicateSubmissionIdempotent(t *testing.T) {
	results, dir := spawnTwoInstallers(t, 2, 2)

	for _, r := range results {
		o := r.Outcome
		if o.Code != OutcomeInstalled || o.CurrentAfter != 2 {
			t.Fatalf("duplicate child must see installed v2, got %+v", o)
		}
		t.Logf("scenario=cross-process-duplicate input=v2 pid=%d code=%q 1->%d current=%d", r.PID, o.Code, o.ToVersion, o.CurrentAfter)
	}

	e := reopenFor(t, dir)
	defer e.store.Close()
	st, err := e.store.State()
	if err != nil {
		t.Fatalf("duplicate concurrent installs must not corrupt state: %v", err)
	}
	if st.Committed.Version != 2 {
		t.Fatalf("duplicate installs must land v2 exactly once, got current=%d", st.Committed.Version)
	}
	if st.Pending == nil || st.Pending.FromVersion != 1 || st.Pending.ToVersion != 2 {
		t.Fatalf("pending range wrong after duplicate install: %+v", st.Pending)
	}
	if o := e.eng.ConfirmBoot(); o.Code != OutcomeConfirmed {
		t.Fatalf("duplicate-installed v2 must be confirmable, got %+v", o)
	}
	// Submitting again after confirm is the stable same_version_replay.
	o := e.eng.Install(e.pkg(2, nil))
	if o.Code != OutcomeRejected || o.Reason.Policy != PolicySameVersionReplay {
		t.Fatalf("post-confirm duplicate must be same_version_replay, got %+v", o)
	}
	t.Logf("result both=installed current=2 post_confirm_replay=same_version_replay")
}

// TestCrossProcessMixedRoundsRepeated repeats the real-process arbitration
// across several rounds, mixing distinct-update races and duplicate races
// with intermediate confirm/rollback, to show the conclusion is stable and
// the device stays coherent no matter how the processes interleave.
func TestCrossProcessMixedRoundsRepeated(t *testing.T) {
	base := setup(t)
	dir := base.dir
	t.Cleanup(func() { _ = base.store.Close() })

	current := uint64(1)
	for round := 0; round < 4; round++ {
		next := current + 1
		// Phase A: two processes submit the SAME next version concurrently.
		dup, _ := spawnTwoInstallersOn(t, base, next, next)
		for _, r := range dup {
			if r.Outcome.Code != OutcomeInstalled || r.Outcome.CurrentAfter != next {
				t.Fatalf("round %d duplicate child: %+v", round, r.Outcome)
			}
		}
		// Parent reopens to see the children's committed state, then confirms.
		_ = base.store.Close()
		e := reopenFor(t, dir)
		if c := e.eng.ConfirmBoot(); c.Code != OutcomeConfirmed {
			t.Fatalf("round %d confirm: %+v", round, c)
		}
		t.Logf("scenario=cross-process-mixed round=%d phase=duplicate input=v%d both=installed confirmed=%d",
			round, next, e.curVersion())
		_ = e.store.Close()
		current = next

		// Phase B: two processes submit DIFFERENT higher versions concurrently.
		base2 := reopenFor(t, dir)
		results, _ := spawnTwoInstallersOn(t, base2, current+1, current+2)
		var installed, blocked int
		for _, r := range results {
			if r.Outcome.Code == OutcomeInstalled {
				installed++
			} else if r.Outcome.Reason.Policy == PolicyUpdateInProgress {
				blocked++
			} else {
				t.Fatalf("round %d distinct child: %+v", round, r.Outcome)
			}
		}
		if installed != 1 || blocked != 1 {
			t.Fatalf("round %d want 1 installed/1 blocked, got %d/%d", round, installed, blocked)
		}
		_ = base2.store.Close()
		e2 := reopenFor(t, dir)
		if c := e2.eng.ConfirmBoot(); c.Code != OutcomeConfirmed {
			t.Fatalf("round %d confirm winner: %+v", round, c)
		}
		winner := e2.curVersion()
		t.Logf("scenario=cross-process-mixed round=%d phase=distinct input=v%d,v%d installed=1 blocked=1 confirmed=%d",
			round, current+1, current+2, winner)
		_ = e2.store.Close()
		current = winner

		// Re-point base at the now-advanced device for the next round.
		base = reopenFor(t, dir)
	}
}
