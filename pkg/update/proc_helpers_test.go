package update

import (
	"testing"
	"time"

	"github.com/h3yow/secure-firmware-update-go/pkg/device"
	"github.com/h3yow/secure-firmware-update-go/pkg/firmware"
	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
	"github.com/h3yow/secure-firmware-update-go/pkg/verify"
)

// childKey deterministically recreates the same "k" firmware key used by
// setup() inside a freshly spawned OS process (same seed => same key).
func childKey() trust.TestKey {
	k, err := trust.GenerateTestKey("k", "seed-k", string(firmware.PurposeFirmware),
		now.Add(-day), now.Add(day))
	if err != nil {
		panic(err)
	}
	return k
}

func childRoot() *trust.RootOfTrust {
	root := trust.NewRoot()
	k := childKey()
	if err := root.AddKey(trust.PublicKey{
		ID: k.ID, PublicKey: k.Public, Purpose: firmware.Purpose(k.Purpose),
		NotBefore: now.Add(-day), NotAfter: now.Add(day),
	}); err != nil {
		panic(err)
	}
	return root
}

func newChildVerifier(root *trust.RootOfTrust) *verify.Verifier {
	return verify.New(root, func() time.Time { return now })
}

func childSigner(t *testing.T) trust.TestKey {
	t.Helper()
	return childKey()
}

// reopenFor opens an independent engine over an existing device directory,
// exactly like a new process starting up after the race.
func reopenFor(t *testing.T, dir string) *env {
	t.Helper()
	st, err := device.Open(dir, "dev1")
	if err != nil {
		t.Fatal(err)
	}
	root := childRoot()
	v := verify.New(root, func() time.Time { return now })
	eng := New(st, v, func() time.Time { return now })
	return &env{t: t, dir: dir, store: st, root: root, signers: map[string]trust.TestKey{"k": childKey()}, eng: eng}
}
