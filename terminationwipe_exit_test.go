package secmem

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

// TestCompleteTermination_ExitsWhenReraiseImpossible pins the behaviour chosen
// after measuring the Windows one.
//
// os.Process.Signal on Windows implements only os.Kill and rejects os.Interrupt
// and SIGTERM, and the console event that triggered the handler has already been
// consumed — so there is nothing to re-deliver. Before this, the failure was
// swallowed and the process ran on with every secret wiped: reads still succeed
// and return zeros, so an application that treats the signal as "begin shutdown"
// could sign with an all-zero key and be told it worked. That is the one state
// WipeAllSecrets does not support, since its leave-mapped design is justified
// entirely by imminent termination.
//
// The hooks are injected because a test that really re-raised would kill the
// test binary and one that really exited would take the suite with it. Live
// delivery of a genuine console Ctrl-C is covered by a separate manual harness.
func TestCompleteTermination_ExitsWhenReraiseImpossible(t *testing.T) {
	t.Parallel()
	notSupported := errors.New("not supported by windows")

	cases := []struct {
		name       string
		reraiseErr error
		forceExit  bool
		wantExit   bool
	}{
		{"re-raise works: the disposition owns the exit", nil, true, false},
		{"re-raise works, NoExit: still not ours to force", nil, false, false},
		{"re-raise impossible, default: secmem exits", notSupported, true, true},
		{"re-raise impossible, NoExit: caller owns the exit", notSupported, false, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var exited bool
			var status int
			completeTermination(
				os.Interrupt,
				c.forceExit,
				func(os.Signal) error { return c.reraiseErr },
				func(code int) { exited, status = true, code },
			)
			if exited != c.wantExit {
				t.Fatalf("exit called = %v, want %v", exited, c.wantExit)
			}
			if exited && status != forcedExitStatus {
				t.Errorf("exit status = %d, want %d", status, forcedExitStatus)
			}
		})
	}
}

// TestForcedExitStatus_MatchesUninterceptedSignal pins the status itself. A
// parent, a batch file or a CI step must not be able to tell a secmem-wrapped
// process apart from an un-wrapped one by how it died — otherwise installing the
// wipe silently changes how every caller's tooling reads a cancellation.
//
// 0xC000013A is STATUS_CONTROL_C_EXIT, confirmed against a real console Ctrl-C:
// a process left to Windows' own default and a process exited by this constant
// both report 0xc000013a.
func TestForcedExitStatus_MatchesUninterceptedSignal(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "windows" {
		t.Skipf("status only has to match the OS default on Windows (GOOS=%s uses %d)", runtime.GOOS, forcedExitStatus)
	}
	// Typed, not an untyped literal: passed to Errorf an untyped 0xC000013A
	// defaults to int and overflows on 386, which is what the 32-bit jobs
	// caught. Going through a variable for the narrowing likewise, since
	// uint32(constant) of a negative constant does not compile.
	const statusControlCExit uint32 = 0xC000013A
	narrowed := int32(forcedExitStatus)
	if got := uint32(narrowed); got != statusControlCExit {
		t.Errorf("forcedExitStatus = %#x, want %#x (STATUS_CONTROL_C_EXIT)", got, statusControlCExit)
	}
}
