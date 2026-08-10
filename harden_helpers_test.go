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

	// Ask for a budget derived from the limit actually in force, not a magic
	// number. A fixed 256 KiB request used to be "above the 64 KiB Linux
	// default", but current systemd distributions default RLIMIT_MEMLOCK to
	// 8 MiB (measured: Ubuntu 26.04/amd64 and Armbian/arm64 both 8 MiB), which
	// silently turned this into a test of the already-sufficient branch on
	// every modern box. Probe the live limit so the log says which branch ran.
	want := uint64(256 * 1024)
	if cur, err := EnsureMemlockLimit(0); err == nil && cur > 0 {
		t.Logf("RLIMIT_MEMLOCK in force: %d bytes", cur)
		if cur >= want {
			t.Logf("already >= %d — exercising the never-lower path, not the raise path", want)
		}
		want = cur + 64*4096 // ask past it so the raise path is attempted where headroom exists
	}
	got, err := EnsureMemlockLimit(want)
	if err != nil {
		t.Logf("EnsureMemlockLimit(%d) = %d, %v (soft==hard or working-set cap; not a failure of contract)", want, got, err)
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
