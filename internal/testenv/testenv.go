// Package testenv holds test helpers shared across packages.
package testenv

import (
	"os"
	"testing"
)

// NoSkipEnv is set to "1" in CI jobs whose environment is expected to support
// every test. There, an environment-dependent skip is a failure: a test that
// silently stops running must not look like a pass.
const NoSkipEnv = "WT_NO_SKIP"

// Skip skips t for an environment reason (missing kernel feature, running as
// root, …), or fails it when NoSkipEnv is "1".
func Skip(t testing.TB, reason string) {
	t.Helper()
	if os.Getenv(NoSkipEnv) == "1" {
		t.Fatalf("test would be skipped, but %s=1 forbids skips: %s", NoSkipEnv, reason)
	}
	t.Skip(reason)
}
