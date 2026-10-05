//go:build !windows

package device

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// dirLock is a cross-process advisory exclusive lock backed by a single
// lock file in the device directory. flock(2) is released automatically by
// the kernel if the holding process dies, so a crashed updater can never
// permanently block the device.
type dirLock struct {
	f *os.File
}

func openDirLock(dir string) (*dirLock, error) {
	f, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("device: open lock file: %w", err)
	}
	return &dirLock{f: f}, nil
}

func (l *dirLock) acquire() error {
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("device: acquire store lock: %w", err)
	}
	return nil
}

// release drops the advisory lock but keeps the lock file handle open so
// the store can begin further transactions; the file is closed in Close.
func (l *dirLock) release() error {
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("device: release store lock: %w", err)
	}
	return nil
}

// close shuts the lock file handle. Only called from Store.Close.
func (l *dirLock) close() error {
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
