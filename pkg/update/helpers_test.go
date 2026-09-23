package update

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/h3yow/secure-firmware-update-go/pkg/trust"
)

func readFile(path string) ([]byte, error)  { return os.ReadFile(path) }
func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o644) }

// hRootFromDir rebuilds the trust root persisted by newHarness.
func hRootFromDir(t *testing.T, dir string) *trust.Root {
	t.Helper()
	r, err := trust.Load(filepath.Join(dir, "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
