package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/update"
)

// buildCLI compiles the real fwupdate binary so concurrency tests spawn
// genuine OS processes (not goroutines sharing one engine mutex).
func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fwupdate")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}
	return bin
}

// runCLI runs one CLI invocation as its own process against home.
func runCLI(t *testing.T, bin, home string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "SFW_HOME="+home)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustCLI(t *testing.T, bin, home string, args ...string) string {
	t.Helper()
	out, err := runCLI(t, bin, home, args...)
	if err != nil {
		t.Fatalf("fwupdate %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// parseOutcome extracts the engine Outcome a mutating CLI command printed.
func parseOutcome(t *testing.T, out string) update.Outcome {
	t.Helper()
	i := strings.Index(out, "{")
	if i < 0 {
		t.Fatalf("no JSON outcome in output:\n%s", out)
	}
	var o update.Outcome
	if err := json.Unmarshal([]byte(out[i:]), &o); err != nil {
		t.Fatalf("parse outcome: %v\n%s", err, out)
	}
	return o
}

// committedVersion reads `fwupdate status` and returns the committed version,
// proving the state file is readable and consistent after the experiment.
func committedVersion(t *testing.T, bin, home string) uint64 {
	t.Helper()
	out := mustCLI(t, bin, home, "status")
	var st device.State
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &st); err != nil {
		t.Fatalf("status is not a readable state: %v\n%s", err, out)
	}
	return st.Committed.Version
}

// freshDevice creates a home with an initialized device (factory v1) and the
// requested packages built with the currently valid key k2.
func freshDevice(t *testing.T, bin, base, name string, versions ...uint64) string {
	t.Helper()
	home := filepath.Join(base, name)
	mustCLI(t, bin, home, "init")
	for _, v := range versions {
		mustCLI(t, bin, home, "build", pkgFile(v), itoa(v))
	}
	return home
}

func pkgFile(v uint64) string { return "v" + itoa(v) + ".sfw" }

// TestCrossProcessDistinctUpdatesSingleWinner starts two independent OS
// processes installing DIFFERENT updates (v2 and v3) at the same time on the
// same device. Exactly one may take effect; the loser must get the stable
// update_in_progress rejection, and the device must end on the winner's
// version with a readable, consistent state.
func TestCrossProcessDistinctUpdatesSingleWinner(t *testing.T) {
	bin := buildCLI(t)
	base := t.TempDir()

	const rounds = 5
	for i := 0; i < rounds; i++ {
		home := freshDevice(t, bin, base, fmt.Sprintf("round%d", i), 2, 3)

		type result struct {
			out string
			err error
		}
		ch := make(chan result, 2)
		for _, v := range []uint64{2, 3} {
			go func(v uint64) {
				out, err := runCLI(t, bin, home, "install", pkgFile(v))
				ch <- result{out, err}
			}(v)
		}
		outcomes := map[uint64]update.Outcome{}
		for range []uint64{2, 3} {
			r := <-ch
			if r.err != nil {
				t.Fatalf("round %d: install process failed: %v\n%s", i, r.err, r.out)
			}
			o := parseOutcome(t, r.out)
			// Results arrive in completion order; ToVersion identifies which
			// package this outcome belongs to.
			outcomes[o.ToVersion] = o
		}

		var winner uint64
		for _, v := range []uint64{2, 3} {
			o := outcomes[v]
			t.Logf("scenario=cross-process-distinct round=%d input=install-v%d code=%q policy=%q %d->%d",
				i, v, o.Code, o.Reason.Policy, o.FromVersion, o.ToVersion)
			switch {
			case o.Code == update.OutcomeInstalled:
				if winner != 0 {
					t.Fatalf("round %d: both v%d and v%d report installed", i, winner, v)
				}
				winner = v
			case o.Code == update.OutcomeRejected && o.Reason.Policy == update.PolicyUpdateInProgress:
				// expected loser outcome
			default:
				t.Fatalf("round %d: install v%d: unexpected outcome %+v", i, v, o)
			}
		}
		if winner == 0 {
			t.Fatalf("round %d: no update took effect", i)
		}
		if got := committedVersion(t, bin, home); got != winner {
			t.Fatalf("round %d: committed=%d, want winner v%d (state must agree with the reported success)", i, got, winner)
		}
		// The winner's trial is confirmable; the device ends on the winner.
		c := parseOutcome(t, mustCLI(t, bin, home, "confirm"))
		if c.Code != update.OutcomeConfirmed {
			t.Fatalf("round %d: confirm after race: %+v", i, c)
		}
		if got := committedVersion(t, bin, home); got != winner {
			t.Fatalf("round %d: after confirm committed=%d want %d", i, got, winner)
		}
		t.Logf("round=%d winner=v%d confirmed committed=%d", i, winner, winner)
	}
}

// TestCrossProcessDuplicateSubmissionIdempotent starts three independent OS
// processes installing the SAME package at the same time. Every process must
// observe the single-submission result (installed), no process may see a
// spurious failure, and the device state must stay readable and consistent
// afterwards.
func TestCrossProcessDuplicateSubmissionIdempotent(t *testing.T) {
	bin := buildCLI(t)
	base := t.TempDir()

	const rounds, procs = 5, 3
	for i := 0; i < rounds; i++ {
		home := freshDevice(t, bin, base, fmt.Sprintf("round%d", i), 2)

		type result struct {
			out string
			err error
		}
		ch := make(chan result, procs)
		for p := 0; p < procs; p++ {
			go func() {
				out, err := runCLI(t, bin, home, "install", pkgFile(2))
				ch <- result{out, err}
			}()
		}
		for p := 0; p < procs; p++ {
			r := <-ch
			if r.err != nil {
				t.Fatalf("round %d proc %d: install process failed: %v\n%s", i, p, r.err, r.out)
			}
			o := parseOutcome(t, r.out)
			t.Logf("scenario=cross-process-duplicate round=%d proc=%d input=install-v2 code=%q policy=%q",
				i, p, o.Code, o.Reason.Policy)
			if o.Code != update.OutcomeInstalled {
				t.Fatalf("round %d proc %d: duplicate submission must be idempotent, got %+v", i, p, o)
			}
		}
		if got := committedVersion(t, bin, home); got != 2 {
			t.Fatalf("round %d: committed=%d want 2", i, got)
		}
		c := parseOutcome(t, mustCLI(t, bin, home, "confirm"))
		if c.Code != update.OutcomeConfirmed {
			t.Fatalf("round %d: confirm after duplicate installs: %+v", i, c)
		}
		if got := committedVersion(t, bin, home); got != 2 {
			t.Fatalf("round %d: after confirm committed=%d want 2", i, got)
		}
		t.Logf("round=%d all %d processes installed idempotently, confirmed v2", i, procs)
	}
}
