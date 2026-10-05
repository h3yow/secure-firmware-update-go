//go:build windows

package device

// dirLock on Windows is a placeholder: this local simulation is developed
// and tested on Unix, where flock-backed exclusion runs. The in-process
// mutex still protects same-process callers.
type dirLock struct{}

func openDirLock(dir string) (*dirLock, error) { return &dirLock{}, nil }

func (l *dirLock) acquire() error { return nil }

func (l *dirLock) release() error { return nil }

func (l *dirLock) close() error { return nil }
