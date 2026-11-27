package testenv

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestSkipRespectsNoSkip runs the two branches in a child test process,
// because Skip ends the calling test either way.
func TestSkipRespectsNoSkip(t *testing.T) {
	if os.Getenv("WT_TESTENV_CHILD") == "1" {
		Skip(t, "child reason")
		return
	}
	run := func(noSkip string) (string, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSkipRespectsNoSkip$", "-test.v")
		cmd.Env = append(os.Environ(), "WT_TESTENV_CHILD=1", NoSkipEnv+"="+noSkip)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := run("")
	if err != nil || !strings.Contains(out, "--- SKIP") {
		t.Fatalf("without %s: want a skip, got err=%v\n%s", NoSkipEnv, err, out)
	}
	out, err = run("1")
	if err == nil || !strings.Contains(out, "forbids skips: child reason") {
		t.Fatalf("with %s=1: want a failure, got err=%v\n%s", NoSkipEnv, err, out)
	}
}
