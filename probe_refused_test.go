package secmem

import (
	"errors"
	"strings"
	"testing"
)

// A refused probe allocation must read as a refusal. Before ProbeErr the
// report was indistinguishable from an allocation with no protection, and
// Warnings said secrets were on the Go heap and could reach swap, about a
// process in which no secret could be placed anywhere.
func TestProbe_RefusedAllocationIsReportedAsRefused(t *testing.T) {
	t.Parallel()
	refusal := errors.New("mlock: operation not permitted")
	c := probeWith(func(int) (secRegion, []byte, allocInfo, error) {
		return secRegion{}, nil, allocInfo{}, refusal
	})

	if !errors.Is(c.ProbeErr, refusal) {
		t.Fatalf("ProbeErr = %v, want the allocator's error", c.ProbeErr)
	}
	if c.OffHeap || c.Mlocked || c.MemfdSecret || c.NoDump || c.NoFork || c.GuardPages || c.DestroyQuarantine || c.Insecure {
		t.Errorf("a refused probe reports an allocation fact: %+v", c)
	}

	w := c.Warnings()
	if len(w) == 0 || !strings.HasPrefix(w[0], "REFUSED") || !strings.Contains(w[0], refusal.Error()) {
		t.Fatalf("Warnings does not lead with the refusal and its error: %q", w)
	}
	// Each of these describes an allocation that exists. None does.
	for _, line := range w[1:] {
		for _, untrue := range []string{"Go heap", "swap", "memfd_secret", "core dumps", "forked", "guard pages", "quarantine"} {
			if strings.Contains(line, untrue) {
				t.Errorf("Warnings describes an allocation that was never made: %q", line)
			}
		}
	}

	s := c.String()
	if !strings.Contains(s, "REFUSED("+refusal.Error()+")") {
		t.Errorf("String does not name the refusal: %s", s)
	}
	for _, name := range []string{"off-heap", "mlock ", "mlock]", "memfd_secret", "no-dump", "no-fork", "guard-pages", "destroy-quarantine"} {
		if strings.Contains(strings.TrimPrefix(s, s[:strings.Index(s, ")")+1]), name) {
			t.Errorf("String lists per-allocation field %q for an allocation that was never made: %s", name, s)
		}
	}
}

// The process-wide lines survive a refusal: they are true whether or not an
// allocation succeeds.
func TestProbe_RefusedAllocationKeepsProcessWideFacts(t *testing.T) {
	t.Parallel()
	ok := Probe()
	if ok.ProbeErr != nil {
		skipProbeRefused(t, ok.ProbeErr)
	}
	c := probeWith(func(int) (secRegion, []byte, allocInfo, error) {
		return secRegion{}, nil, allocInfo{}, errors.New("refused")
	})
	if c.FlushedWipe != ok.FlushedWipe || c.RuntimeSecret != ok.RuntimeSecret || c.FrameScrub != ok.FrameScrub ||
		c.VectorRegisterClear != ok.VectorRegisterClear || c.GPRegisterClear != ok.GPRegisterClear {
		t.Errorf("process-wide facts differ after a refusal:\n refused: %+v\n live:    %+v", c, ok)
	}
	if ok.ProbeErr == nil && !ok.RuntimeSecret {
		found := false
		for _, line := range c.Warnings() {
			found = found || strings.Contains(line, "runtime/secret")
		}
		if !found {
			t.Errorf("a refused probe dropped a process-wide warning: %q", c.Warnings())
		}
	}
}

func skipProbeRefused(t *testing.T, err error) {
	t.Helper()
	t.Skipf("the host refused the live probe allocation: %v", err)
}
