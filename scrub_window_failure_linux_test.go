//go:build linux

package secmem

import "testing"

// TestScrubWindow_FailedSuppressionIsReported makes the mask call fail the way
// a seccomp filter on rt_sigprocmask would. The window still runs, but without
// the suppression, and that used to be invisible: Capabilities reported a
// build-time constant, so the posture said "suppressed" about windows that
// were not.
func TestScrubWindow_FailedSuppressionIsReported(t *testing.T) {
	if !Probe().AsyncPreemptSuppressed {
		t.Fatal("precondition: suppression is reported as not in force before any failure")
	}
	failSigmaskForTest.Store(true)
	ran := false
	Scrub(func() { ran = true })
	failSigmaskForTest.Store(false)
	defer resetSuppressionFailureForTest()

	if !ran {
		t.Fatal("the window did not run fn after the mask call failed")
	}
	if Probe().AsyncPreemptSuppressed {
		t.Error("Capabilities still reports async preemption as suppressed after a window failed to block the signal")
	}

	// The pin survives the failed mask call, and restore undoes exactly it.
	failSigmaskForTest.Store(true)
	var w preemptWindow
	suppressed := suppressAsyncPreempt(&w)
	failSigmaskForTest.Store(false)
	if suppressed {
		t.Error("suppressAsyncPreempt reported success although the mask call failed")
	}
	if !w.locked || w.active {
		t.Errorf("after a failed mask call: locked=%v active=%v, want pinned and not masked", w.locked, w.active)
	}
	w.restore()
	if w.locked {
		t.Error("restore left the window marked as pinned")
	}
	w.restore() // idempotent: must not unlock a second time
}
