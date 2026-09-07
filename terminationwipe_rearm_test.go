package secmem

import (
	"errors"
	"os"
	"testing"
	"time"
)

// TestCompleteTermination_ReportsRearm pins which outcomes leave the handler
// installed. Only one does: nothing re-raised AND the process left running.
// After a successful re-raise the signal is in flight and registering again
// could catch it (see the "After the signal" section of InstallTerminationWipe);
// after a forced exit there is no process to arm.
func TestCompleteTermination_ReportsRearm(t *testing.T) {
	t.Parallel()
	notSupported := errors.New("not supported by windows")

	cases := []struct {
		name       string
		reraiseErr error
		forceExit  bool
		wantRearm  bool
	}{
		{"re-raise works: in flight, handler is done", nil, true, false},
		{"re-raise works, NoExit: in flight, handler is done", nil, false, false},
		{"re-raise impossible, default: exiting, nothing to arm", notSupported, true, false},
		{"re-raise impossible, NoExit: process runs on, re-arm", notSupported, false, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := completeTermination(
				os.Interrupt,
				c.forceExit,
				func(os.Signal) error { return c.reraiseErr },
				func(int) {},
			)
			if got != c.wantRearm {
				t.Fatalf("rearm = %v, want %v", got, c.wantRearm)
			}
		})
	}
}

// waitWiped polls buf until every byte reads as zero or the deadline passes.
// The handler wipes before it does anything else, so a buffer reading as zeros
// is the proof that a signal reached it. An access error is returned as such:
// a wiped region stays mapped and readable, so any error here is a bug.
func waitWiped(buf *SecureBuffer, timeout time.Duration) (wiped bool, err error) {
	deadline := time.Now().Add(timeout)
	for {
		wiped = true
		if err := buf.WithBytes(func(b []byte) {
			for _, x := range b {
				if x != 0 {
					wiped = false
				}
			}
		}); err != nil {
			return false, err
		}
		if wiped || time.Now().After(deadline) {
			return wiped, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}
