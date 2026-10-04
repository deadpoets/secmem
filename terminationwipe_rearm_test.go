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
		name            string
		reraiseErr      error
		forceExit       bool
		inheritedIgnore bool
		wantRearm       bool
	}{
		{"re-raise works: in flight, handler is done", nil, true, false, false},
		{"re-raise works, NoExit: in flight, handler is done", nil, false, false, false},
		{"re-raise impossible, default: exiting, nothing to arm", notSupported, true, false, false},
		{"re-raise impossible, NoExit: process runs on, re-arm", notSupported, false, false, true},
		// An inherited ignore is "re-raise impossible" by another route: the
		// kill would be accepted and dropped, so nothing is in flight.
		{"inherited ignore, default: exiting, nothing to arm", nil, true, true, false},
		{"inherited ignore, NoExit: process runs on, re-arm", nil, false, true, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := completeTermination(
				os.Interrupt,
				c.forceExit,
				c.inheritedIgnore,
				func(os.Signal) error { return c.reraiseErr },
				func(int) {},
			)
			if got != c.wantRearm {
				t.Fatalf("rearm = %v, want %v", got, c.wantRearm)
			}
		})
	}
}

// waitWiped polls buf until a borrow is refused with ErrWiped or the deadline
// passes. The handler wipes before it does anything else, so that refusal is
// the proof that a signal reached it. Any other access error is returned as
// such: nothing else in these tests makes a borrow fail.
func waitWiped(buf *SecureBuffer, timeout time.Duration) (wiped bool, err error) {
	deadline := time.Now().Add(timeout)
	for {
		err := buf.WithBytes(func([]byte) {})
		if errors.Is(err, ErrWiped) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}
