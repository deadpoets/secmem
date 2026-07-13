package secmem

import (
	"errors"
	"runtime"
	"testing"
)

// TestEnsureMemlockLimit_NeverLowers verifies the idempotent, never-shrink
// contract: asking for less than the current budget returns the current
// value and does not reduce it. Safe to run in-process — it only ever raises.
func TestEnsureMemlockLimit_NeverLowers(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
	default:
		if _, err := EnsureMemlockLimit(1 << 20); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("stub EnsureMemlockLimit err = %v, want ErrUnsupported", err)
		}
		return
	}

	// Raise to a modest budget (256 KiB) — above the 64 KiB Linux default,
	// within any reasonable hard limit, so this needs no privilege.
	const want = 256 * 1024
	got, err := EnsureMemlockLimit(want)
	if err != nil {
		t.Logf("EnsureMemlockLimit(%d) = %d, %v (hard limit or working-set cap reached; not a failure of contract)", want, got, err)
	}

	// Now ask for far less — must not lower what we just achieved.
	after, err := EnsureMemlockLimit(4096)
	if err != nil {
		t.Fatalf("EnsureMemlockLimit(4096): %v", err)
	}
	if after < got {
		t.Errorf("EnsureMemlockLimit lowered the budget: was %d, now %d", got, after)
	}
}

// TestDisableCoreDumps_Unsupported pins the honest error on platforms without
// a core-dump rlimit. The Linux/Darwin success path is exercised
// out-of-process (see harden_isolated_test.go) so it does not disable dumps
// for the rest of the suite.
func TestDisableCoreDumps_Unsupported(t *testing.T) {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		t.Skip("supported here — verified out-of-process in TestHelpersIsolated")
	}
	if err := DisableCoreDumps(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("DisableCoreDumps on %s = %v, want ErrUnsupported", runtime.GOOS, err)
	}
}
