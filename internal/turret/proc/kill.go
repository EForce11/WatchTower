package proc

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/EForce11/WatchTower/internal/turret/ioc"
)

// DefaultTempDirs are the directories treated as temporary.
var DefaultTempDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// Kill sends SIGKILL to pid if it still matches expectExe and expectStart.
// The pidfd is opened before inspecting, so a recycled PID cannot be hit.
func Kill(pid int, expectExe string, expectStart uint64) error {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("proc: pidfd_open %d: %w", pid, err)
	}
	defer unix.Close(fd)
	i, err := Inspect(pid)
	if err != nil {
		return err
	}
	if Immune(i, os.Getpid()) {
		return ErrImmune
	}
	if i.Exe != expectExe || i.StartTime != expectStart {
		return ErrMismatch
	}
	return unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
}

// KillTempMalware kills pid when it runs from a temp directory and its binary
// hash is in iocs, then chmods the executable to 0600. It returns the exe path.
func KillTempMalware(pid int, iocs *ioc.Set, tempDirs []string) (string, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return "", fmt.Errorf("proc: pidfd_open %d: %w", pid, err)
	}
	defer unix.Close(fd)
	i, err := Inspect(pid)
	if err != nil {
		return "", err
	}
	if i.Memfd || i.Deleted {
		return "", ErrMemfdOrDeleted
	}
	if Immune(i, os.Getpid()) {
		return "", ErrImmune
	}
	clean := filepath.Clean(i.Exe)
	resolved, err := filepath.EvalSymlinks(i.Exe)
	if err != nil {
		return "", fmt.Errorf("proc: resolve exe: %w", err)
	}
	if !underAny(clean, tempDirs) || !underAny(resolved, tempDirs) {
		return "", ErrNotTempPath
	}
	h, err := hashProcExe(pid)
	if err != nil {
		return "", err
	}
	if !iocs.HasSHA256(h) {
		return "", ErrNotInIOC
	}
	again, err := Inspect(pid)
	if err != nil {
		return "", err
	}
	if again.StartTime != i.StartTime {
		return "", ErrMismatch
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
		return "", fmt.Errorf("proc: signal %d: %w", pid, err)
	}
	if err := os.Chmod(i.Exe, 0o600); err != nil {
		return i.Exe, fmt.Errorf("proc: chmod %s: %w", i.Exe, err)
	}
	return i.Exe, nil
}

// underAny reports whether p lies strictly beneath one of dirs, matching on
// path-component boundaries ("/tmpfoo/x" is not under "/tmp/").
func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		d = filepath.Clean(d)
		if d != "/" {
			d += "/"
		}
		if strings.HasPrefix(p, d) && len(p) > len(d) {
			return true
		}
	}
	return false
}

// hashProcExe hashes the running binary via /proc/<pid>/exe, not its path.
func hashProcExe(pid int) ([32]byte, error) {
	var out [32]byte
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return out, fmt.Errorf("proc: open exe: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return out, fmt.Errorf("proc: hash exe: %w", err)
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}
