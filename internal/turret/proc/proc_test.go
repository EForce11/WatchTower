package proc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/EForce11/WatchTower/internal/turret/ioc"
	"github.com/EForce11/WatchTower/internal/turret/verify"
	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

// start launches cmd and guarantees it is killed and reaped on cleanup.
func start(t *testing.T, path string) (*exec.Cmd, chan error) { //nolint:gocritic // two obvious results
	t.Helper()
	cmd, done, err := startE(t, path)
	if err != nil {
		t.Fatal(err)
	}
	return cmd, done
}

// helperEnv makes the test binary act as a long-sleeping child (see
// TestMain). Re-executing the test binary instead of a system tool such as
// sleep(1) keeps the tests independent of how the host's coreutils are built:
// a multicall binary dispatching on argv[0] or its location would exit at
// once when copied to a temp dir under another name.
const helperEnv = "WT_PROC_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "sleep" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func startE(t *testing.T, path string) (cmd *exec.Cmd, done chan error, err error) {
	t.Helper()
	cmd = exec.Command(path)
	cmd.Env = append(os.Environ(), helperEnv+"=sleep")
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	done = make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	return cmd, done, nil
}

// helperPath is the resolved path of the test binary, which sleeps when
// started with helperEnv set.
func helperPath(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func assertKilled(t *testing.T, done chan error) {
	t.Helper()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("wait err = %v", err)
		}
		ws, ok := ee.Sys().(syscall.WaitStatus)
		if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Fatalf("not killed by SIGKILL: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("process not killed")
	}
}

func assertAlive(t *testing.T, done chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("process died: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestInspect(t *testing.T) {
	sp := helperPath(t)
	cmd, _ := start(t, sp)
	i, err := Inspect(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if i.Exe != sp || i.StartTime == 0 || i.PID != cmd.Process.Pid || i.PPID != os.Getpid() {
		t.Fatalf("info = %+v (want exe %s)", i, sp)
	}
	if i.Deleted || i.Memfd || i.Kernel || Immune(i, os.Getpid()) {
		t.Fatalf("unexpected flags: %+v", i)
	}
}

func TestParseStat(t *testing.T) {
	ppid, st, err := parseStat("123 (a) b (c d) S 77 1 1 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 987654 1 2")
	if err != nil || ppid != 77 || st != 987654 {
		t.Fatalf("ppid=%d st=%d err=%v", ppid, st, err)
	}
	if _, _, err := parseStat("garbage"); err == nil {
		t.Fatal("expected error")
	}
}

func TestImmune(t *testing.T) {
	self := 4242
	cases := []struct {
		name string
		i    Info
		want bool
	}{
		{"init", Info{PID: 1}, true},
		{"self", Info{PID: self}, true},
		{"kthreadd", Info{PID: 2}, true},
		{"kernel child", Info{PID: 99, PPID: 2}, true},
		{"kernel flag", Info{PID: 99, Kernel: true}, true},
		{"turret", Info{PID: 99, PPID: 5, Exe: "/usr/sbin/wt-turret"}, true},
		{"wg", Info{PID: 99, PPID: 5, Exe: "/usr/bin/wg"}, true},
		{"tmp wg", Info{PID: 99, PPID: 5, Exe: "/tmp/x/wg"}, false},
		{"tmp sentry", Info{PID: 99, PPID: 5, Exe: "/tmp/x/wt-sentry"}, false},
		{"sshd ppid1", Info{PID: 99, PPID: 1, Exe: "/usr/sbin/sshd"}, true},
		{"tmp sshd ppid1", Info{PID: 99, PPID: 1, Exe: "/tmp/x/sshd"}, false},
		{"sshd ppid500", Info{PID: 99, PPID: 500, Exe: "/usr/sbin/sshd"}, false},
		{"usrfoo prefix", Info{PID: 99, PPID: 5, Exe: "/usr/binx/wg"}, false},
		{"other", Info{PID: 99, PPID: 5, Exe: "/tmp/x"}, false},
	}
	for _, c := range cases {
		if got := Immune(c.i, self); got != c.want {
			t.Errorf("%s: Immune = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestKill(t *testing.T) {
	sp := helperPath(t)
	cmd, done := start(t, sp)
	i, err := Inspect(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := Kill(cmd.Process.Pid, i.Exe, i.StartTime); err != nil {
		t.Fatal(err)
	}
	assertKilled(t, done)
}

func TestKillMismatch(t *testing.T) {
	sp := helperPath(t)
	cmd, done := start(t, sp)
	i, err := Inspect(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := Kill(cmd.Process.Pid, i.Exe, i.StartTime+1); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong start: err = %v", err)
	}
	assertAlive(t, done)
	if err := Kill(cmd.Process.Pid, "/nope/sleep", i.StartTime); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong exe: err = %v", err)
	}
	assertAlive(t, done)
}

func TestKillImmuneSelf(t *testing.T) {
	i, err := Inspect(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := Kill(os.Getpid(), i.Exe, i.StartTime); !errors.Is(err, ErrImmune) {
		t.Fatalf("err = %v", err)
	}
}

func copyBin(t *testing.T, dir string) string {
	t.Helper()
	src, err := os.Open(helperPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst := filepath.Join(dir, "evil")
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, src); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return dst
}

func hashOf(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

// iocSet builds a verified ioc.Set containing hashes.
func iocSet(t *testing.T, hashes ...[32]byte) *ioc.Set {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	autoPath := filepath.Join(dir, "auto.pub")
	if err := os.WriteFile(autoPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	adminDir := filepath.Join(dir, "admin")
	if err := os.Mkdir(adminDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ring, err := verify.LoadKeyring(autoPath, adminDir)
	if err != nil {
		t.Fatal(err)
	}
	hs := make([][]byte, 0, len(hashes))
	for _, h := range hashes {
		hs = append(hs, append([]byte(nil), h[:]...))
	}
	payload, _ := proto.Marshal(&synapsev1.IocBundle{Version: 1, Sha256: hs})
	raw, _ := proto.Marshal(&synapsev1.SignedIocBundle{Payload: payload, Signature: ed25519.Sign(priv, payload), KeyId: verify.KeyID(pub)})
	p := filepath.Join(dir, "ioc.bin")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ioc.Load(p, ring)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKillTempMalware(t *testing.T) {
	dir := t.TempDir()
	bin := copyBin(t, dir)
	cmd, done := start(t, bin)
	got, err := KillTempMalware(cmd.Process.Pid, iocSet(t, hashOf(t, bin)), []string{dir + "/"})
	if err != nil {
		t.Fatal(err)
	}
	assertKilled(t, done)
	if got != bin {
		t.Fatalf("exe = %q, want %q", got, bin)
	}
	st, err := os.Stat(bin)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", st.Mode().Perm())
	}
}

func TestKillTempMalwareNotInIOC(t *testing.T) {
	dir := t.TempDir()
	bin := copyBin(t, dir)
	cmd, done := start(t, bin)
	_, err := KillTempMalware(cmd.Process.Pid, iocSet(t, sha256.Sum256([]byte("other"))), []string{dir + "/"})
	if !errors.Is(err, ErrNotInIOC) {
		t.Fatalf("err = %v", err)
	}
	assertAlive(t, done)
}

func TestKillTempMalwareNotTempPath(t *testing.T) {
	dir := t.TempDir()
	bin := copyBin(t, dir)
	cmd, done := start(t, bin)
	other := t.TempDir()
	_, err := KillTempMalware(cmd.Process.Pid, iocSet(t, hashOf(t, bin)), []string{other + "/"})
	if !errors.Is(err, ErrNotTempPath) {
		t.Fatalf("err = %v", err)
	}
	assertAlive(t, done)
}

func TestUnderAnyBoundary(t *testing.T) {
	if !underAny("/tmp/x", []string{"/tmp/"}) || underAny("/tmpfoo/x", []string{"/tmp/"}) || underAny("/tmp", []string{"/tmp/"}) {
		t.Fatal("component-boundary check wrong")
	}
}

func TestKillTempMalwareDeleted(t *testing.T) {
	dir := t.TempDir()
	bin := copyBin(t, dir)
	cmd, done := start(t, bin)
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	_, err := KillTempMalware(cmd.Process.Pid, iocSet(t, hashOf(t, copyBin(t, t.TempDir()))), []string{dir + "/"})
	if !errors.Is(err, ErrMemfdOrDeleted) {
		t.Fatalf("err = %v", err)
	}
	assertAlive(t, done)
}

func TestKillTempMalwareChmodFollowsInodeNotPath(t *testing.T) {
	dir := t.TempDir()
	bin := copyBin(t, dir)
	keep := filepath.Join(dir, "keep")
	if err := os.Link(bin, keep); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(t.TempDir(), "decoy")
	if err := os.WriteFile(decoy, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd, done := start(t, bin)
	afterSignalHook = func(exe string) {
		_ = os.Remove(exe)
		_ = os.Symlink(decoy, exe)
	}
	t.Cleanup(func() { afterSignalHook = nil })
	if _, err := KillTempMalware(cmd.Process.Pid, iocSet(t, hashOf(t, keep)), []string{dir + "/"}); err != nil {
		t.Fatal(err)
	}
	assertKilled(t, done)
	if st, err := os.Stat(decoy); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("decoy mode changed: %v %v", st, err)
	}
	if st, err := os.Stat(keep); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("original inode mode: %v %v", st, err)
	}
}

func TestKillTempMalwareRejectsBadTempDirs(t *testing.T) {
	for _, d := range []string{"/", "tmp/", ""} {
		if _, err := KillTempMalware(os.Getpid(), iocSet(t), []string{d}); err == nil {
			t.Errorf("dir %q accepted", d)
		}
	}
}

func TestKillTempMalwareMemfd(t *testing.T) {
	fd, err := unix.MemfdCreate("evil", 0)
	if err != nil {
		t.Skipf("memfd_create: %v", err)
	}
	mf := os.NewFile(uintptr(fd), "memfd")
	t.Cleanup(func() { _ = mf.Close() })
	src, err := os.Open(helperPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := io.Copy(mf, src); err != nil {
		t.Fatal(err)
	}
	cmd, done, err := startE(t, fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd))
	if err != nil {
		t.Skipf("exec from memfd not permitted: %v", err)
	}
	if i, err := Inspect(cmd.Process.Pid); err != nil || !i.Memfd {
		t.Skipf("exe not memfd-backed: %+v %v", i, err)
	}
	if _, err := KillTempMalware(cmd.Process.Pid, iocSet(t), DefaultTempDirs); !errors.Is(err, ErrMemfdOrDeleted) {
		t.Fatalf("err = %v", err)
	}
	assertAlive(t, done)
}

func TestInspectLiveFileNamedDeleted(t *testing.T) {
	dir := t.TempDir()
	bin := copyBin(t, dir)
	named := bin + " (deleted)"
	if err := os.Rename(bin, named); err != nil {
		t.Fatal(err)
	}
	cmd, _ := start(t, named)
	i, err := Inspect(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if i.Deleted || i.Exe != named {
		t.Fatalf("misflagged: %+v", i)
	}
}
