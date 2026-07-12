package secmem

import "testing"

// TestReportEnvironment is a diagnostic, not a gate: it prints what secmem
// actually provides in the current runtime environment — the resolved
// Capabilities, any warnings, and whether a live secure allocation succeeds or
// fails closed. Its value is the `-v` output, which documents behaviour under
// root, non-root, containers, and a constrained RLIMIT_MEMLOCK. It asserts only
// the one invariant that must always hold: an "insecure" report may not also
// claim protections.
//
//	go test -run TestReportEnvironment -v
func TestReportEnvironment(t *testing.T) {
	p := Probe()
	t.Logf("Probe: %s", p.String())
	for _, w := range p.Warnings() {
		t.Logf("warning: %s", w)
	}

	if p.Insecure && (p.OffHeap || p.Mlocked || p.GuardPages) {
		t.Errorf("insecure report also claims protections: %+v", p)
	}

	// A live allocation documents the real outcome for this environment.
	// Failing closed (e.g. under a zero memlock budget with no CAP_IPC_LOCK)
	// is a correct, expected result here — recorded, not asserted against.
	buf, err := NewBuffer([]byte("environment-probe"))
	if err != nil {
		t.Logf("NewBuffer: FAILED CLOSED in this environment: %v", err)
		return
	}
	defer func() { _ = buf.Destroy() }()
	t.Logf("live allocation: %s", buf.Capabilities().String())
}
