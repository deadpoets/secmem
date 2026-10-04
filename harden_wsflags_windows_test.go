//go:build windows

package secmem

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const wsFlagsChildEnv = "SECMEM_TEST_WSFLAGS_CHILD"

// Working-set quota flags, as Get/SetProcessWorkingSetSizeEx use them.
const (
	hardWSMinEnable  = 0x1
	hardWSMinDisable = 0x2
	hardWSMaxEnable  = 0x4
	hardWSMaxDisable = 0x8
)

// TestEnsureMemlockLimit_KeepsAHardMinimum covers an application (or its
// launcher) that made the working-set minimum hard before asking for a larger
// lock budget. EnsureMemlockLimit read the flags and then wrote both limits
// back soft, so the minimum grew while its enforcement was dropped: the rule
// is that an existing budget is never lowered, and that has to include how
// firmly it is held.
//
// The working set is process-global, so the body runs in a re-executed child.
func TestEnsureMemlockLimit_KeepsAHardMinimum(t *testing.T) {
	if os.Getenv(wsFlagsChildEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestEnsureMemlockLimit_KeepsAHardMinimum$", "-test.v")
		cmd.Env = append(os.Environ(), wsFlagsChildEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		if strings.Contains(string(out), "--- SKIP") {
			t.Skipf("child skipped:\n%s", out)
		}
		return
	}

	h := windows.CurrentProcess()
	var curMin, curMax uintptr
	var flags uint32
	windows.GetProcessWorkingSetSizeEx(h, &curMin, &curMax, &flags)
	if err := windows.SetProcessWorkingSetSizeEx(h, curMin, curMax, hardWSMinEnable|hardWSMaxDisable); err != nil {
		t.Skipf("cannot make the working-set minimum hard here: %v", err)
	}
	windows.GetProcessWorkingSetSizeEx(h, &curMin, &curMax, &flags)
	if flags&hardWSMinEnable == 0 {
		t.Skipf("the hard minimum did not take (flags %#x)", flags)
	}

	want := uint64(curMin) + 1<<20
	got, err := EnsureMemlockLimit(want)
	if err != nil {
		t.Skipf("EnsureMemlockLimit(%d): %v (achieved %d)", want, err, got)
	}

	var newMin, newMax uintptr
	var after uint32
	windows.GetProcessWorkingSetSizeEx(h, &newMin, &newMax, &after)
	if newMin <= curMin {
		t.Fatalf("minimum working set did not grow: %d -> %d", curMin, newMin)
	}
	if after&hardWSMinEnable == 0 {
		t.Errorf("the hard minimum was turned soft by EnsureMemlockLimit: flags %#x -> %#x", flags, after)
	}
	if after&hardWSMaxEnable != 0 {
		t.Errorf("EnsureMemlockLimit made the maximum hard: flags %#x -> %#x", flags, after)
	}
}
