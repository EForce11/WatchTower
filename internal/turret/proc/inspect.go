// Package proc inspects and kills processes without falling to PID reuse.
package proc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Info describes a process as seen through /proc.
type Info struct {
	PID, PPID int
	Exe       string
	StartTime uint64
	Deleted   bool
	Memfd     bool
	Kernel    bool
}

var (
	// ErrImmune means the process is protected from being killed.
	ErrImmune = errors.New("proc: process is immune")
	// ErrMismatch means the live process does not match the expected identity.
	ErrMismatch = errors.New("proc: process identity mismatch")
	// ErrNotTempPath means the executable does not live in a temp directory.
	ErrNotTempPath = errors.New("proc: executable not in a temp directory")
	// ErrNotInIOC means the executable hash is not a known indicator.
	ErrNotInIOC = errors.New("proc: executable hash not in IOC set")
	// ErrMemfdOrDeleted means the executable is memfd-backed or deleted.
	ErrMemfdOrDeleted = errors.New("proc: executable is memfd or deleted")
)

const deletedSuffix = " (deleted)"

// Inspect reads /proc/<pid>/{exe,stat}.
func Inspect(pid int) (Info, error) {
	dir := "/proc/" + strconv.Itoa(pid)
	statRaw, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return Info{}, fmt.Errorf("proc: read stat: %w", err)
	}
	ppid, start, err := parseStat(string(statRaw))
	if err != nil {
		return Info{}, err
	}
	i := Info{PID: pid, PPID: ppid, StartTime: start}
	exe, err := os.Readlink(dir + "/exe")
	switch {
	case errors.Is(err, syscall.ENOENT):
		// stat exists but exe does not: a kernel thread (or a zombie).
		i.Kernel = true
	case err != nil:
		return Info{}, fmt.Errorf("proc: read exe: %w", err)
	default:
		if strings.HasPrefix(exe, "/memfd:") {
			i.Memfd = true
		}
		if strings.HasSuffix(exe, deletedSuffix) {
			i.Deleted = true
			exe = strings.TrimSuffix(exe, deletedSuffix)
		}
		i.Exe = exe
	}
	if pid == 2 || ppid == 2 {
		i.Kernel = true
	}
	return i, nil
}

// parseStat extracts ppid (field 4) and starttime (field 22). Parsing starts
// after the last ')' so command names with spaces or parentheses are safe.
func parseStat(s string) (ppid int, start uint64, err error) {
	end := strings.LastIndexByte(s, ')')
	if end < 0 {
		return 0, 0, errors.New("proc: malformed stat")
	}
	// Fields after the comm start at field 3 (state).
	f := strings.Fields(s[end+1:])
	if len(f) < 20 {
		return 0, 0, errors.New("proc: short stat")
	}
	ppid, err = strconv.Atoi(f[1])
	if err != nil {
		return 0, 0, fmt.Errorf("proc: parse ppid: %w", err)
	}
	start, err = strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("proc: parse starttime: %w", err)
	}
	return ppid, start, nil
}

var immuneExes = map[string]bool{
	"wt-turret": true, "wt-sentry": true, "wt-core": true,
	"wg": true, "wg-quick": true, "wireguard-go": true,
}

// Immune reports whether a process must never be killed.
func Immune(i Info, self int) bool {
	if i.PID == 1 || i.PID == self || i.PID == 2 || i.PPID == 2 || i.Kernel {
		return true
	}
	base := filepath.Base(i.Exe)
	if immuneExes[base] {
		return true
	}
	return base == "sshd" && i.PPID == 1
}
