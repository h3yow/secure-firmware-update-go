package update

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/security"
	"github.com/h3yow/secure-firmware-update-go/pkg/signing"
	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
	"github.com/h3yow/secure-firmware-update-go/pkg/verdict"
)

const model = "box-100"

type harness struct {
	dir     string
	root    *trust.Root
	signers map[string]*signing.Signer
	eng     *Engine
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	unix := func(s string) int64 {
		tt, _ := time.Parse(time.RFC3339, s)
		return tt.Unix()
	}
	specs := []struct {
		id, nb, na string
		purpose    trust.Purpose
	}{
		{"cur", "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z", trust.PurposeFirmware},
		{"next", "2027-01-01T00:00:00Z", "2028-12-31T00:00:00Z", trust.PurposeFirmware},
		{"old", "2024-01-01T00:00:00Z", "2025-12-31T00:00:00Z", trust.PurposeFirmware},
		{"maint", "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z", trust.PurposeOther},
	}
	h := &harness{dir: dir, signers: map[string]*signing.Signer{}}
	keys := make([]trust.Key, 0, len(specs))
	for _, sp := range specs {
		s, err := signing.GenerateKey(sp.id, "updtest:"+sp.id)
		if err != nil {
			t.Fatal(err)
		}
		h.signers[sp.id] = s
		keys = append(keys, trust.Key{
			ID: sp.id, Algorithm: trust.AlgEd25519, Public: s.Public(),
			NotBefore: unix(sp.nb), NotAfter: unix(sp.na),
			Purposes: []trust.Purpose{sp.purpose},
		})
	}
	h.root = &trust.Root{Version: 1, Keys: keys}
	if err := h.root.Save(filepath.Join(dir, "trust.json")); err != nil {
		t.Fatal(err)
	}
	dev, err := device.Open(filepath.Join(dir, "dev"), model)
	if err != nil {
		t.Fatal(err)
	}
	v := security.NewVerifier(h.root)
	v.NowFn = func() time.Time {
		tt, _ := time.Parse(time.RFC3339, "2026-09-23T00:00:00Z")
		return tt
	}
	h.eng = New(dev, v)
	return h
}

func (h *harness) pkgPath(t *testing.T, name, version, signerID, target, pkgModel string, mutate func([]byte) []byte) string {
	t.Helper()
	s := h.signers[signerID]
	if s == nil {
		t.Fatalf("no signer %q", signerID)
	}
	payload := []byte("PAYLOAD:" + name + ":" + version)
	m := firmware.Manifest{
		PackageID:  name,
		Model:      pkgModel,
		TargetSlot: target,
		Version:    version,
		PayloadKey: "rel",
		IssuedAt:   1,
	}
	path := filepath.Join(h.dir, name+".fwpkg")
	if err := s.SignPackage(m, payload, path); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		data, err := readFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = mutate(data)
		if err := writeFile(path, data); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func (h *harness) goodPkg(t *testing.T, name, version, signerID string) string {
	target := h.eng.Dev.InactiveSlot()
	return h.pkgPath(t, name, version, signerID, target, model, nil)
}

func assertOutcome(t *testing.T, o *Outcome, success bool, code verdict.Code) {
	t.Helper()
	if success {
		if !o.Success {
			t.Fatalf("expected success, got rejection code=%s reason=%s input=%s basis=%s",
				o.Failure.Code, o.Failure.Reason, o.Failure.Input, o.Failure.Basis)
		}
		return
	}
	if o.Success {
		t.Fatalf("expected rejection %q, got success", code)
	}
	if o.Failure.Code != code {
		t.Fatalf("expected code=%q got=%q\ninput=%s\nbasis=%s",
			code, o.Failure.Code, o.Failure.Input, o.Failure.Basis)
	}
}

func TestBothEntriesRejectIdentically(t *testing.T) {
	// For each rejection scenario the one-shot and staged entries must agree.
	scenarios := []struct {
		name  string
		build func(t *testing.T, h *harness) string
		code  verdict.Code
	}{
		{"tampered", func(t *testing.T, h *harness) string {
			return h.pkgPath(t, "tamper", "1.0.0", "cur", h.eng.Dev.InactiveSlot(), model,
				func(b []byte) []byte { b[len(b)-1] ^= 1; return b })
		}, verdict.CodePayloadTampered},
		{"expired-key", func(t *testing.T, h *harness) string {
			return h.pkgPath(t, "exp", "1.0.0", "old", h.eng.Dev.InactiveSlot(), model, nil)
		}, verdict.CodeKeyExpired},
		{"future-key", func(t *testing.T, h *harness) string {
			return h.pkgPath(t, "fut", "1.0.0", "next", h.eng.Dev.InactiveSlot(), model, nil)
		}, verdict.CodeKeyNotYetValid},
		{"wrong-purpose", func(t *testing.T, h *harness) string {
			return h.pkgPath(t, "maint", "1.0.0", "maint", h.eng.Dev.InactiveSlot(), model, nil)
		}, verdict.CodeKeyPurposeMismatch},
		{"downgrade", func(t *testing.T, h *harness) string {
			return h.pkgPath(t, "down", "0.0.0", "cur", h.eng.Dev.InactiveSlot(), model, nil)
		}, verdict.CodeDowngrade},
		{"replay", func(t *testing.T, h *harness) string {
			return h.pkgPath(t, "replay", "0.0.1", "cur", h.eng.Dev.InactiveSlot(), model, nil)
		}, verdict.CodeReplay},
		{"model-mismatch", func(t *testing.T, h *harness) string {
			return h.pkgPath(t, "mm", "1.0.0", "cur", h.eng.Dev.InactiveSlot(), "other-model", nil)
		}, verdict.CodeModelMismatch},
		{"target-mismatch", func(t *testing.T, h *harness) string {
			wrong := device.SlotA
			if h.eng.Dev.InactiveSlot() == device.SlotA {
				wrong = device.SlotB
			}
			return h.pkgPath(t, "tm", "1.0.0", "cur", wrong, model, nil)
		}, verdict.CodeTargetMismatch},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			h1 := newHarness(t)
			p1 := sc.build(t, h1)
			assertOutcome(t, h1.eng.Install(p1), false, sc.code)
			// Device must remain on factory after a rejected install.
			if h1.eng.Dev.ActiveVersion().String() != "0.0.1" {
				t.Fatal("rejected install moved device off factory")
			}

			h2 := newHarness(t)
			p2 := sc.build(t, h2)
			assertOutcome(t, h2.eng.Prepare(p2), false, sc.code)
			if h2.eng.Dev.HasStaged() {
				t.Fatal("rejected prepare left staged state")
			}
			if h2.eng.Dev.ActiveVersion().String() != "0.0.1" {
				t.Fatal("rejected prepare moved device off factory")
			}
		})
	}
}

func TestInstallAndPrepareActivateReachSameState(t *testing.T) {
	h1 := newHarness(t)
	p1 := h1.goodPkg(t, "a", "1.0.0", "cur")
	assertOutcome(t, h1.eng.Install(p1), true, "")
	s1 := h1.eng.Dev.Snapshot()

	h2 := newHarness(t)
	p2 := h2.goodPkg(t, "a", "1.0.0", "cur")
	assertOutcome(t, h2.eng.Prepare(p2), true, "")
	assertOutcome(t, h2.eng.Activate(), true, "")
	s2 := h2.eng.Dev.Snapshot()

	if s1.ActiveSlot != s2.ActiveSlot || s1.Slots[s1.ActiveSlot].Version != s2.Slots[s2.ActiveSlot].Version ||
		s1.Slots[s1.ActiveSlot].SHA256 != s2.Slots[s2.ActiveSlot].SHA256 {
		t.Fatalf("entries diverged:\n%+v\n%+v", s1, s2)
	}
}

func TestRepeatedInstallIsIdempotentReplayReject(t *testing.T) {
	h := newHarness(t)
	p := h.goodPkg(t, "a", "1.0.0", "cur")
	assertOutcome(t, h.eng.Install(p), true, "")
	// The exact same package file is now below active and targets a slot that
	// has rotated; version policy fires first and reports replay stably.
	o := h.eng.Install(p)
	assertOutcome(t, o, false, verdict.CodeReplay)
	// Repeating again yields the identical stable verdict.
	assertOutcome(t, h.eng.Install(p), false, verdict.CodeReplay)
}

func TestRepeatedPrepareIsIdempotent(t *testing.T) {
	h := newHarness(t)
	p := h.goodPkg(t, "a", "1.0.0", "cur")
	assertOutcome(t, h.eng.Prepare(p), true, "")
	// Same pending update prepared again is confirmed, not double-written.
	assertOutcome(t, h.eng.Prepare(p), true, "")
	assertOutcome(t, h.eng.Activate(), true, "")
	// Activating again is an explained nothing-staged, not corruption.
	assertOutcome(t, h.eng.Activate(), false, verdict.CodeNothingStaged)
}

func TestPrepareThenPowerLossActivateAfterReopen(t *testing.T) {
	dir := ""
	{
		h := newHarness(t)
		dir = h.dir
		p := h.goodPkg(t, "a", "1.0.0", "cur")
		assertOutcome(t, h.eng.Prepare(p), true, "")
		// "Power loss" before activate: drop the in-memory harness.
	}
	// Reopen the same on-disk device and trust root.
	dev, err := device.Open(filepath.Join(dir, "dev"), model)
	if err != nil {
		t.Fatal(err)
	}
	root2 := hRootFromDir(t, dir)
	v := security.NewVerifier(root2)
	eng := New(dev, v)
	if !eng.Dev.HasStaged() {
		t.Fatal("staged update did not survive power loss")
	}
	assertOutcome(t, eng.Activate(), true, "")
	if eng.Dev.ActiveVersion().String() != "1.0.0" {
		t.Fatalf("active=%s want 1.0.0", eng.Dev.ActiveVersion())
	}
}

func TestUpgradeAndRollbackEndStateConsistency(t *testing.T) {
	h := newHarness(t)
	p1 := h.goodPkg(t, "a", "1.0.0", "cur")
	assertOutcome(t, h.eng.Install(p1), true, "")
	afterUpgrade := h.eng.Dev.Snapshot()
	if afterUpgrade.ActiveSlot != device.SlotB || afterUpgrade.Slots[device.SlotB].Version != "1.0.0" {
		t.Fatalf("bad post-upgrade state %+v", afterUpgrade)
	}
	assertOutcome(t, h.eng.Rollback(), true, "")
	afterRollback := h.eng.Dev.Snapshot()
	if afterRollback.ActiveSlot != device.SlotA || afterRollback.Slots[device.SlotA].Version != "0.0.1" {
		t.Fatalf("bad post-rollback state %+v", afterRollback)
	}
	// Installing 1.0.0 again after rollback must end on the identical slot
	// content as the first upgrade.
	p2 := h.goodPkg(t, "b", "1.0.0", "cur")
	assertOutcome(t, h.eng.Install(p2), true, "")
	again := h.eng.Dev.Snapshot()
	if again.ActiveSlot != afterUpgrade.ActiveSlot ||
		again.Slots[again.ActiveSlot].SHA256 != afterUpgrade.Slots[afterUpgrade.ActiveSlot].SHA256 {
		t.Fatalf("upgrade/rollback/re-upgrade diverged:\n%+v\n%+v", again, afterUpgrade)
	}
}

func TestRollbackWithoutTarget(t *testing.T) {
	h := newHarness(t)
	assertOutcome(t, h.eng.Rollback(), false, verdict.CodeNoRollback)
}

func TestStageWriteFaultKeepsFactory(t *testing.T) {
	h := newHarness(t)
	p := h.goodPkg(t, "a", "1.0.0", "cur")
	h.eng.Dev.SetFailPoint(device.FailPoint{FailStageWriteAfter: 3})
	assertOutcome(t, h.eng.Install(p), false, verdict.CodeStagingFailure)
	if h.eng.Dev.ActiveVersion().String() != "0.0.1" {
		t.Fatal("device moved off factory despite staged write fault")
	}
	if h.eng.Dev.HasStaged() {
		t.Fatal("faulted staging left committed staged pointer")
	}
	// Removing the fault and retrying the identical update succeeds.
	h.eng.Dev.SetFailPoint(device.FailPoint{})
	assertOutcome(t, h.eng.Install(p), true, "")
}

func TestMalformedPackage(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(h.dir, "junk.fwpkg")
	if err := writeFile(path, []byte("not a package")); err != nil {
		t.Fatal(err)
	}
	assertOutcome(t, h.eng.Install(path), false, verdict.CodeMalformedPackage)
}

func TestStrictlyHigherVersionEnforced(t *testing.T) {
	h := newHarness(t)
	p := h.goodPkg(t, "a", "2.0.0", "cur")
	assertOutcome(t, h.eng.Install(p), true, "")
	// 1.99.99 < 2.0.0 numerically.
	p2 := h.goodPkg(t, "b", "1.99.99", "cur")
	assertOutcome(t, h.eng.Install(p2), false, verdict.CodeDowngrade)
}
