//go:build linux || darwin || windows

// Out-of-process guard-page fault proofs.
//
// Proving that a read past the secret area faults means taking a deliberate
// hardware fault. Recovering one in-process with debug.SetPanicOnFault trips a
// Go runtime bug on windows/amd64 with AMX-capable CPUs: the OS exception frame
// overruns the 4 KiB the runtime reserves below a goroutine stack and corrupts
// the heap beneath it (golang/go#81238; see "Go runtime fault-recovery bug" in
// WINDOWS.md). Nothing outside _test.go files arms SetPanicOnFault, so this is
// a test-harness hazard, not a library one.
//
// So each probe runs in a re-exec'd child that does nothing else: it announces
// the address it is about to read, performs the read, and lets the runtime kill
// it. The parent judges the outcome from the child's exit status AND output. A
// "must fault" case passes only when the child died the way an unrecovered Go
// fault dies — exit status 2 with the runtime's "unexpected fault address"
// line naming the announced address — never merely because the child died.
// The two control cases at the bottom pin that distinction.
//
// Nothing here arms SetPanicOnFault. Fold the probes back in-process once the
// upstream fix is in the Go release CI pins.

package secmem

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// Markers the child prints. Distinctive so they cannot be confused with
// anything in a runtime traceback.
const (
	faultProbeEnv     = "SECMEM_FAULT_PROBE"
	faultProbeAddr    = "SECMEM_FAULT_PROBE_ADDR " // followed by the hex address, printed before the read
	faultProbeNoFault = "SECMEM_FAULT_PROBE_NOFAULT"
	faultProbeSkip    = "SECMEM_FAULT_PROBE_SKIP"

	faultProbeExitSkip    = 42
	faultProbeExitUnknown = 43
	// runtimeThrowExit is the status the Go runtime exits with on an
	// unrecovered fault (runtime.fatalthrow → exit(2)), on every OS.
	runtimeThrowExit = 2
)

// faultProbeCases are the individual probes, each run in its own child. A case
// returns skip=true when secure memory is unavailable. Otherwise it announces
// the address and reads it; a read that faults never returns — the process
// dies, which is how the "must fault" cases are proven — and a read that does
// not fault returns so the child can report a clean outcome.
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
		announceAndRead(end)
		return false
	},

	// Controls for the harness itself: deaths that are NOT a fault at the
	// announced address, which the parent must report as inconclusive rather
	// than as a passing guard-page proof.
	"control_exit": func() bool {
		os.Stdout.WriteString(faultProbeAddr + "0x0\n")
		os.Exit(7)
		return false
	},
	"control_nil_deref": func() bool {
		os.Stdout.WriteString(faultProbeAddr + "0x0\n")
		var p *int
		fmt.Fprintln(os.Stderr, *p) // nil-dereference panic: exit 2 too, but no "unexpected fault address"
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
	announceAndRead(target(base, end))
	return false
}

// announceAndRead prints the address the child is about to read, so the parent
// can match it against the runtime's fault report, then reads it.
func announceAndRead(addr uintptr) {
	os.Stdout.WriteString(faultProbeAddr + "0x" + strconv.FormatUint(uint64(addr), 16) + "\n")
	_ = probeRead(addr)
}

// init dispatches a re-exec'd child to its probe case and exits before any test
// runs. A no-fault read prints faultProbeNoFault and exits 0; an unavailable
// allocation prints faultProbeSkip and exits 42; a faulting read crashes the
// process. The parent (runFaultProbe) reads the outcome from exit status + output.
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
		os.Exit(faultProbeExitUnknown)
	}
	if probe() {
		os.Stdout.WriteString(faultProbeSkip + "\n")
		os.Exit(faultProbeExitSkip)
	}
	os.Stdout.WriteString(faultProbeNoFault + "\n")
	os.Exit(0)
}

// faultProbeOutcome is what the parent concluded from one child.
type faultProbeOutcome int

const (
	probeOutcomeFaulted faultProbeOutcome = iota // died as an unrecovered Go fault at the announced address
	probeOutcomeNoFault                          // read completed, clean exit
	probeOutcomeSkip                             // secure memory unavailable in the child
)

// errProbeInconclusive is returned when the child's death or output does not
// match any outcome the harness recognises — including a death that was NOT the
// announced fault, which must never count as a passing proof.
var errProbeInconclusive = errors.New("fault-probe inconclusive")

// runFaultProbe runs one case in a fresh child and classifies the result.
func runFaultProbe(name string) (faultProbeOutcome, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// -test.run=^$ selects no tests; init() does the work and exits first.
	// GOTRACEBACK=none keeps the goroutine dump out of the log; the runtime's
	// "unexpected fault address" and "fatal error" lines print regardless,
	// and they are what the parent matches on.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^$")
	cmd.Env = append(os.Environ(), faultProbeEnv+"="+name, "GOTRACEBACK=none")
	out, err := cmd.CombinedOutput()
	s := string(out)

	if strings.Contains(s, faultProbeSkip) {
		return probeOutcomeSkip, nil
	}
	if err == nil {
		if strings.Contains(s, faultProbeNoFault) {
			return probeOutcomeNoFault, nil
		}
		return 0, fmt.Errorf("%w: child exited 0 without a marker; output=%q", errProbeInconclusive, s)
	}

	// The child died. Only an unrecovered Go fault at the announced address
	// counts: exit status 2 (runtime throw) plus the runtime's report naming
	// that address. Anything else — a different exit, a panic, a fault
	// somewhere else — is inconclusive, not a pass.
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return 0, fmt.Errorf("%w: could not run child: %w; output=%q", errProbeInconclusive, err, s)
	}
	if exitErr.ExitCode() != runtimeThrowExit {
		return 0, fmt.Errorf("%w: child exit status %d, want %d (runtime throw); output=%q",
			errProbeInconclusive, exitErr.ExitCode(), runtimeThrowExit, s)
	}
	addr, ok := announcedAddr(s)
	if !ok {
		return 0, fmt.Errorf("%w: child died before announcing an address; output=%q", errProbeInconclusive, s)
	}
	if !strings.Contains(s, "unexpected fault address "+addr) {
		return 0, fmt.Errorf("%w: child died but not from a fault at %s; output=%q", errProbeInconclusive, addr, s)
	}
	return probeOutcomeFaulted, nil
}

// announcedAddr extracts the "0x…" the child printed before its read.
func announcedAddr(out string) (string, bool) {
	i := strings.Index(out, faultProbeAddr)
	if i < 0 {
		return "", false
	}
	rest := out[i+len(faultProbeAddr):]
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	rest = strings.TrimSpace(rest)
	return rest, strings.HasPrefix(rest, "0x")
}

// probeFaulted runs one fault-probe case and reports whether the probed read
// faulted. It skips the calling test when the child reports secure memory is
// unavailable, and fails it when the outcome is inconclusive.
func probeFaulted(t *testing.T, name string) bool {
	t.Helper()
	outcome, err := runFaultProbe(name)
	if err != nil {
		t.Fatalf("fault-probe %q: %v", name, err)
	}
	switch outcome {
	case probeOutcomeSkip:
		t.Skipf("secure memory unavailable in fault-probe child %q", name)
	case probeOutcomeFaulted:
		return true
	case probeOutcomeNoFault:
		return false
	}
	t.Fatalf("fault-probe %q: unknown outcome %d", name, outcome)
	return false
}

// TestFaultProbe_OnlyTheAnnouncedFaultCounts pins the harness's own discipline:
// a child that dies some other way is inconclusive, never a passing proof. Both
// controls print an address and then die without faulting at it — one by a
// plain non-zero exit, one by a nil-dereference panic, which also exits 2 but
// does not produce the "unexpected fault address" report.
func TestFaultProbe_OnlyTheAnnouncedFaultCounts(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"control_exit", "control_nil_deref"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			outcome, err := runFaultProbe(name)
			if err == nil {
				t.Fatalf("control %q classified as outcome %d; want inconclusive", name, outcome)
			}
			if !errors.Is(err, errProbeInconclusive) {
				t.Fatalf("control %q: unexpected error %v", name, err)
			}
		})
	}
}
