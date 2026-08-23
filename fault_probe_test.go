//go:build linux || darwin || windows

// Out-of-process guard-page fault proofs.
//
// The guard-page tests must prove that reading past a secret area FAULTS. Doing
// that in-process means recovering a deliberate hardware fault with
// debug.SetPanicOnFault — and on GitHub-hosted windows/amd64 a fault recovered
// inside the concurrent test binary can trip a bug in the Go runtime's Windows
// exception-recovery path that corrupts unrelated live memory (a saved thread
// CONTEXT, Rip=runtime.sigresume, lands on a live heap object; something later
// trips over the damage with an innocuous frame). It reproduces with zero secmem
// code — a standalone program doing only SetPanicOnFault + faults crashes a
// noticeable fraction of fresh runners — and no non-test secmem code arms
// SetPanicOnFault, so this is a test-harness hazard, not a library defect. Same
// family as golang/go#77975 and #77955.
//
// So each fault probe runs in a re-exec'd child that does nothing but the probe.
// The child never arms SetPanicOnFault: it simply performs the read and lets the
// runtime kill it, and the parent reads the outcome from the child's exit. The
// fault is therefore delivered in a quiet process with no concurrent goroutines
// or allocation, where the runtime bug does not manifest, and a genuine guard
// fault crashes only the throwaway child — exactly the signal the test wants.
//
// Remove this indirection once the upstream runtime fix lands; the in-process
// faults() helper (used only by the redact proofs, which never actually fault in
// a passing run) can come back with it.

package secmem

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// Markers the child prints on the two non-crash outcomes. Distinctive so they
// cannot be confused with anything in a runtime traceback.
const (
	faultProbeEnv     = "SECMEM_FAULT_PROBE"
	faultProbeNoFault = "SECMEM_FAULT_PROBE_NOFAULT"
	faultProbeSkip    = "SECMEM_FAULT_PROBE_SKIP"
)

// faultProbeCases are the individual reads, each in its own child. A case
// returns true when secure memory is unavailable (the child should skip), and
// false after a read that did NOT fault. A read that faults never returns — the
// process dies, which is how the "must fault" cases are proven.
//
//nolint:gochecknoglobals // test-only case registry for the re-exec dispatcher.
var faultProbeCases = map[string]func() (skip bool){
	// NewEmptyBuffer(100): the two in-bounds reads must NOT fault...
	"empty_first_byte": func() bool { return probeEmptyBuffer(func(base, end uintptr) uintptr { return base }) },
	"empty_last_byte":  func() bool { return probeEmptyBuffer(func(base, end uintptr) uintptr { return end - 1 }) },
	// ...and the two just-out-of-bounds reads MUST fault on the guard pages.
	"empty_below": func() bool { return probeEmptyBuffer(func(base, end uintptr) uintptr { return base - 1 }) },
	"empty_past":  func() bool { return probeEmptyBuffer(func(base, end uintptr) uintptr { return end }) },
	// The syscall-safe (allocMapAnon) path is guarded too: past-the-end faults.
	"syscallsafe_past": func() bool {
		buf, err := NewSyscallSafeBuffer([]byte("guarded-ingest"))
		if err != nil {
			return true
		}
		defer func() { _ = buf.Destroy() }()
		inner := buf.region.inner
		end := uintptr(unsafe.Pointer(&inner[0])) + uintptr(len(inner))
		_ = probeRead(end)
		return false
	},
}

// probeEmptyBuffer allocates NewEmptyBuffer(100) and reads the address target
// picks from its bounds. Shared by the four empty-buffer cases.
func probeEmptyBuffer(target func(base, end uintptr) uintptr) (skip bool) {
	buf, err := NewEmptyBuffer(100)
	if err != nil {
		return true // secure memory unavailable — skip, per the project convention.
	}
	defer func() { _ = buf.Destroy() }()
	inner := buf.region.inner
	base := uintptr(unsafe.Pointer(&inner[0]))
	end := base + uintptr(len(inner))
	_ = probeRead(target(base, end))
	return false
}

// init dispatches a re-exec'd child to its probe case and exits before any test
// runs. A no-fault read prints faultProbeNoFault and exits 0; an unavailable
// allocation prints faultProbeSkip and exits 42; a faulting read crashes the
// process. The parent (probeFaulted) reads the outcome from exit status + output.
//
//nolint:gochecknoinits // re-exec dispatch must run before the test binary's main.
func init() {
	name := os.Getenv(faultProbeEnv)
	if name == "" {
		return // ordinary run: not a probe child.
	}
	probe, ok := faultProbeCases[name]
	if !ok {
		os.Stderr.WriteString("secmem: unknown fault-probe case " + name + "\n")
		os.Exit(43)
	}
	if probe() {
		os.Stdout.WriteString(faultProbeSkip + "\n")
		os.Exit(42)
	}
	os.Stdout.WriteString(faultProbeNoFault + "\n")
	os.Exit(0)
}

// probeFaulted runs one fault-probe case in a fresh child and reports whether
// the probed read faulted. It skips the calling test when the child reports
// secure memory is unavailable, and fails it when the outcome is inconclusive.
func probeFaulted(t *testing.T, name string) bool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// -test.run=^$ selects no tests; init() does the work and exits first.
	// GOTRACEBACK=none keeps a guard fault from dumping a full traceback into
	// the log — the exit status is all the parent needs.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^$")
	cmd.Env = append(os.Environ(), faultProbeEnv+"="+name, "GOTRACEBACK=none")
	out, err := cmd.CombinedOutput()
	s := string(out)

	switch {
	case strings.Contains(s, faultProbeSkip):
		t.Skipf("secure memory unavailable in fault-probe child %q", name)
	case err == nil && strings.Contains(s, faultProbeNoFault):
		return false // clean exit after the read: it did not fault.
	case err != nil && !strings.Contains(s, faultProbeNoFault):
		return true // the child died on the read: it faulted.
	}
	t.Fatalf("fault-probe %q inconclusive: err=%v output=%q", name, err, s)
	return false
}
