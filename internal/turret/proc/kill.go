package proc

import (
	"crypto/sha256"
	"errors"
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

// ErrTooLarge means the executable is not a regular file or is too big to hash.
var ErrTooLarge = errors.New("proc: executable not a regular file or too large")

const maxExeSize = 512 << 20

// afterSignalHook is a test seam called between the signal and the chmod.
var afterSignalHook func(exePath string)

// KillTempMalware kills pid when it runs from a temp directory and its binary
// hash is in iocs, then chmods the executable inode to 0600. It returns the
// exe path (for reporting only).
func KillTempMalware(pid int, iocs *ioc.Set, tempDirs []string) (string, error) {
	if err := validateDirs(tempDirs); err != nil {
		return "", err
	}
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
	if err := checkTempPath(i.Exe, tempDirs); err != nil {
		return "", err
	}
	// Hold the inode that is actually running; hash and chmod through it.
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return "", fmt.Errorf("proc: open exe: %w", err)
	}
	defer f.Close()
	sum, err := hashRegular(f)
	if err != nil {
		return "", err
	}
	if !iocs.HasSHA256(sum) {
		return "", ErrNotInIOC
	}
	again, err := Inspect(pid)
	if err != nil {
		return "", err
	}
	if again.StartTime != i.StartTime || again.Exe != i.Exe {
		return "", ErrMismatch
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
		return "", fmt.Errorf("proc: signal %d: %w", pid, err)
	}
	return i.Exe, chmodInode(f, i.Exe)
}

// chmodInode fchmods the inode that ran; the path is for reporting only.
func chmodInode(f *os.File, exe string) error {
	if afterSignalHook != nil {
		afterSignalHook(exe)
	}
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("proc: chmod %s: %w", exe, err)
	}
	return nil
}

// checkTempPath requires both the cleaned and the symlink-resolved exe path
// to lie under a temp dir.
func checkTempPath(exe string, tempDirs []string) error {
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("proc: resolve exe: %w", err)
	}
	if !underAny(filepath.Clean(exe), tempDirs) || !underAny(resolved, tempDirs) {
		return ErrNotTempPath
	}
	return nil
}

// hashRegular hashes an open regular file of bounded size.
func hashRegular(f *os.File) ([32]byte, error) {
	var sum [32]byte
	st, err := f.Stat()
	if err != nil {
		return sum, fmt.Errorf("proc: stat exe: %w", err)
	}
	if !st.Mode().IsRegular() || st.Size() > maxExeSize {
		return sum, ErrTooLarge
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, fmt.Errorf("proc: hash exe: %w", err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// validateDirs rejects empty, relative or root entries.
func validateDirs(dirs []string) error {
	for _, d := range dirs {
		if !filepath.IsAbs(d) || filepath.Clean(d) == "/" {
			return fmt.Errorf("proc: invalid temp dir %q", d)
		}
	}
	return nil
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
