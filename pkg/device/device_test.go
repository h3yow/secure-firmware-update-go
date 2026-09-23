package device

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
)

func mustVer(t *testing.T, s string) firmware.Version {
	t.Helper()
	v, err := firmware.ParseVersion(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func imageFor(ver string) []byte {
	return []byte("IMAGE-" + ver + "-" + ver)
}

func openFresh(t *testing.T) *Device {
	t.Helper()
	d, err := Open(t.TempDir(), "box-100")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func assertActive(t *testing.T, d *Device, slot, ver string) {
	t.Helper()
	s := d.Snapshot()
	if s.ActiveSlot != slot {
		t.Fatalf("active slot=%s want %s; state=%+v", s.ActiveSlot, slot, s)
	}
	if s.Slots[slot].Version != ver {
		t.Fatalf("active version=%s want %s", s.Slots[slot].Version, ver)
	}
	if _, err := d.imageMatches(slot, s.Slots[slot].SHA256); err != nil {
		t.Fatalf("active slot image not bootable: %v", err)
	}
}

func TestFactoryBootable(t *testing.T) {
	d := openFresh(t)
	assertActive(t, d, SlotA, "0.0.1")
	if d.ActiveVersion().Compare(mustVer(t, "0.0.1")) != 0 {
		t.Fatal("factory version mismatch")
	}
}

func TestStageActivateHappyPath(t *testing.T) {
	d := openFresh(t)
	img := imageFor("1.0.0")
	sha := firmware.PayloadSHA256Hex(img)
	if err := d.Stage(mustVer(t, "1.0.0"), "box-100", sha, img); err != nil {
		t.Fatal(err)
	}
	// Still active on factory until activate.
	assertActive(t, d, SlotA, "0.0.1")
	if !d.HasStaged() {
		t.Fatal("staged flag expected")
	}
	if err := d.Activate(); err != nil {
		t.Fatal(err)
	}
	assertActive(t, d, SlotB, "1.0.0")
}

func TestStageWriteInterruptionLeavesKnownGood(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir, "box-100")
	if err != nil {
		t.Fatal(err)
	}
	img := imageFor("1.0.0")
	sha := firmware.PayloadSHA256Hex(img)
	d.SetFailPoint(FailPoint{FailStageWriteAfter: 4})

	err = d.Stage(mustVer(t, "1.0.0"), "box-100", sha, img)
	if !errors.Is(err, InjectedFault) {
		t.Fatalf("expected injected fault, got %v", err)
	}
	// No staged pointer may be committed...
	if d.HasStaged() {
		t.Fatal("staging pointer committed despite interrupted write")
	}
	// ... and the device reopens on the same known-good image.
	d2, err := Open(dir, "box-100")
	if err != nil {
		t.Fatalf("reopen after interrupted stage: %v", err)
	}
	assertActive(t, d2, SlotA, "0.0.1")
	if matches, _ := filepath.Glob(filepath.Join(dir, "slots", ".slot-*.tmp")); len(matches) != 0 {
		t.Fatalf("temp files leaked: %v", matches)
	}
}

func TestActivationFailureIsPreCommit(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir, "box-100")
	if err != nil {
		t.Fatal(err)
	}
	img := imageFor("1.0.0")
	sha := firmware.PayloadSHA256Hex(img)
	if err := d.Stage(mustVer(t, "1.0.0"), "box-100", sha, img); err != nil {
		t.Fatal(err)
	}
	d.SetFailPoint(FailPoint{FailActivate: true})
	if err := d.Activate(); !errors.Is(err, InjectedFault) {
		t.Fatalf("expected activation fault, got %v", err)
	}
	assertActive(t, d, SlotA, "0.0.1")
	if !d.HasStaged() {
		t.Fatal("staged update should survive a pre-commit activation fault")
	}

	// Simulate power loss: reopen and successfully activate the staged update.
	d2, err := Open(dir, "box-100")
	if err != nil {
		t.Fatal(err)
	}
	assertActive(t, d2, SlotA, "0.0.1")
	if !d2.HasStaged() {
		t.Fatal("staged update lost across simulated power loss")
	}
	if err := d2.Activate(); err != nil {
		t.Fatalf("activate after power loss: %v", err)
	}
	assertActive(t, d2, SlotB, "1.0.0")
}

func TestStagedImageCorruptionRejectsActivate(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir, "box-100")
	if err != nil {
		t.Fatal(err)
	}
	img := imageFor("1.0.0")
	sha := firmware.PayloadSHA256Hex(img)
	if err := d.Stage(mustVer(t, "1.0.0"), "box-100", sha, img); err != nil {
		t.Fatal(err)
	}
	if err := d.CorruptSlotBytes(SlotB); err != nil {
		t.Fatal(err)
	}
	// Reopen: corrupt staged slot is dropped, device still boots factory.
	d2, err := Open(dir, "box-100")
	if err != nil {
		t.Fatal(err)
	}
	assertActive(t, d2, SlotA, "0.0.1")
	if d2.HasStaged() {
		t.Fatal("corrupt staging must be discarded on reopen")
	}
}

func TestRollbackAndReUpgrade(t *testing.T) {
	d := openFresh(t)
	for _, v := range []string{"1.0.0", "1.1.0"} {
		img := imageFor(v)
		if err := d.Stage(mustVer(t, v), "box-100", firmware.PayloadSHA256Hex(img), img); err != nil {
			t.Fatal(err)
		}
		if err := d.Activate(); err != nil {
			t.Fatal(err)
		}
	}
	assertActive(t, d, SlotA, "1.1.0") // B after 1.0.0, A after 1.1.0
	if err := d.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertActive(t, d, SlotB, "1.0.0")
	// Rollback is reversible.
	if err := d.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertActive(t, d, SlotA, "1.1.0")
}

func TestRollbackWithoutTarget(t *testing.T) {
	d := openFresh(t)
	if err := d.Rollback(); err == nil {
		t.Fatal("rollback with no target must fail")
	}
}

func TestActivateNothing(t *testing.T) {
	d := openFresh(t)
	if err := d.Activate(); err == nil {
		t.Fatal("activate without staging must fail")
	}
}

func TestStageRequiresMatchingSHA(t *testing.T) {
	d := openFresh(t)
	err := d.Stage(mustVer(t, "1.0.0"), "box-100", "deadbeef", imageFor("1.0.0"))
	if err == nil {
		t.Fatal("stage with wrong sha must fail")
	}
	if d.HasStaged() {
		t.Fatal("failed stage must not set staged flag")
	}
}

func TestPersistentAlternationAcrossReopens(t *testing.T) {
	dir := t.TempDir()
	for step, v := range []string{"1.0.0", "2.0.0", "3.0.0"} {
		d, err := Open(dir, "box-100")
		if err != nil {
			t.Fatal(err)
		}
		img := []byte(fmt.Sprintf("step-%d-image", step))
		if err := d.Stage(mustVer(t, v), "box-100", firmware.PayloadSHA256Hex(img), img); err != nil {
			t.Fatal(err)
		}
		if err := d.Activate(); err != nil {
			t.Fatal(err)
		}
		d.mu.Lock()
		got := d.state.ActiveSlot
		d.mu.Unlock()
		want := SlotB
		if step%2 == 1 {
			want = SlotA
		}
		if got != want {
			t.Fatalf("step %d active=%s want %s", step, got, want)
		}
	}
}
