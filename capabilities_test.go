package secmem

import (
	"runtime"
	"strings"
	"testing"
)

// TestProbe_BuildIdentity verifies Probe stamps the report with the running
// build's GOOS/GOARCH and that the process-wide facts match their sources.
func TestProbe_BuildIdentity(t *testing.T) {
	t.Parallel()
	c := Probe()
	if c.GOOS != runtime.GOOS || c.GOARCH != runtime.GOARCH {
		t.Fatalf("Probe identity = %s/%s, want %s/%s", c.GOOS, c.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	if c.RegisterScrub != RuntimeSecretActive() {
		t.Errorf("Probe().RegisterScrub = %v, want RuntimeSecretActive() = %v", c.RegisterScrub, RuntimeSecretActive())
	}
	if c.GuardPages {
		t.Error("Probe().GuardPages = true, but guard pages are not implemented yet")
	}
}

// TestProbe_SupportedPlatform pins the floor on linux/darwin/windows: the
// probe allocation must be off-heap, locked, and not the insecure fallback.
func TestProbe_SupportedPlatform(t *testing.T) {
	t.Parallel()
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
	default:
		t.Skipf("stub platform %s: no off-heap guarantee to pin", runtime.GOOS)
	}
	c := Probe()
	if !c.OffHeap {
		t.Error("Probe().OffHeap = false on a supported platform")
	}
	if !c.Mlocked {
		t.Error("Probe().Mlocked = false on a supported platform")
	}
	if c.Insecure {
		t.Error("Probe().Insecure = true on a supported platform")
	}
	if runtime.GOOS != "linux" && c.MemfdSecret {
		t.Errorf("Probe().MemfdSecret = true on %s — memfd_secret is Linux-only", runtime.GOOS)
	}
}

// TestBufferCapabilities_MatchesAllocation verifies the per-buffer report:
// a real buffer reports its actual backing, and the process-wide fields agree
// with Probe.
func TestBufferCapabilities_MatchesAllocation(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte("capability-probe-secret"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	c := buf.Capabilities()
	p := Probe()
	if c.GOOS != p.GOOS || c.GOARCH != p.GOARCH {
		t.Errorf("buffer identity %s/%s != probe identity %s/%s", c.GOOS, c.GOARCH, p.GOOS, p.GOARCH)
	}
	if c.OffHeap != p.OffHeap || c.Mlocked != p.Mlocked || c.Insecure != p.Insecure {
		t.Errorf("buffer backing (offheap=%v mlock=%v insecure=%v) diverges from probe (offheap=%v mlock=%v insecure=%v)",
			c.OffHeap, c.Mlocked, c.Insecure, p.OffHeap, p.Mlocked, p.Insecure)
	}
	if c.GuaranteedWipe != p.GuaranteedWipe || c.RegisterScrub != p.RegisterScrub {
		t.Error("process-wide fields differ between buffer report and probe")
	}
}

// TestBufferCapabilities_SurvivesDestroy verifies the report describes how the
// buffer WAS backed — it does not change when the buffer is destroyed.
func TestBufferCapabilities_SurvivesDestroy(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte("destroyed-caps"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	before := buf.Capabilities()
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if after := buf.Capabilities(); after != before {
		t.Errorf("Capabilities changed across Destroy: before %+v, after %+v", before, after)
	}
}

// TestCapabilities_NilReceivers verifies the no-panic rule: nil buffer and
// arena receivers report a fully degraded posture instead of panicking.
func TestCapabilities_NilReceivers(t *testing.T) {
	t.Parallel()
	var buf *SecureBuffer
	var arena *SecureArena
	for _, c := range []Capabilities{buf.Capabilities(), arena.Capabilities()} {
		if c.OffHeap || c.Mlocked || c.MemfdSecret || c.NoDump || c.NoFork {
			t.Errorf("nil receiver reported protections in force: %+v", c)
		}
		if c.GOOS != runtime.GOOS {
			t.Errorf("nil receiver lost build identity: %q", c.GOOS)
		}
	}
}

// TestSyscallSafeBuffer_NeverMemfd pins NewSyscallSafeBuffer's contract: it
// allocates via MAP_ANON only, so its capabilities must never claim
// memfd_secret isolation.
func TestSyscallSafeBuffer_NeverMemfd(t *testing.T) {
	t.Parallel()
	buf, err := NewSyscallSafeBuffer([]byte("syscall-safe"))
	if err != nil {
		t.Fatalf("NewSyscallSafeBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()
	if buf.Capabilities().MemfdSecret {
		t.Error("NewSyscallSafeBuffer reported MemfdSecret = true; it must allocate via MAP_ANON only")
	}
}

// TestArenaCapabilities_MatchesBuffer verifies the arena's slab reports the
// same class of backing as a buffer allocated the same way.
func TestArenaCapabilities_MatchesBuffer(t *testing.T) {
	t.Parallel()
	arena, err := NewArena(64, 4)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = arena.Destroy() }()

	c := arena.Capabilities()
	if c.GOOS != runtime.GOOS || c.GOARCH != runtime.GOARCH {
		t.Errorf("arena identity = %s/%s, want %s/%s", c.GOOS, c.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		if !c.OffHeap || !c.Mlocked || c.Insecure {
			t.Errorf("arena slab not reported as protected on a supported platform: %+v", c)
		}
	}
}

// TestCapabilities_Warnings verifies the degradation report: a fully degraded
// posture warns about everything (led by the insecure heap), and a fully
// protected posture warns about nothing.
func TestCapabilities_Warnings(t *testing.T) {
	t.Parallel()

	degraded := Capabilities{GOOS: "plan9", GOARCH: "mips", Insecure: true}
	w := degraded.Warnings()
	if len(w) == 0 {
		t.Fatal("fully degraded Capabilities produced no warnings")
	}
	if !strings.Contains(w[0], "INSECURE") {
		t.Errorf("first warning must lead with the insecure heap fallback, got %q", w[0])
	}

	full := Capabilities{
		GOOS: "linux", GOARCH: "amd64",
		OffHeap: true, Mlocked: true, MemfdSecret: true,
		NoDump: true, NoFork: true,
		GuaranteedWipe: true, RegisterScrub: true, GuardPages: true,
	}
	if w := full.Warnings(); len(w) != 0 {
		t.Errorf("fully protected Capabilities still warned: %q", w)
	}
}

// TestCapabilities_String verifies the one-line summary carries the build
// identity, the in-force list, and the missing list.
func TestCapabilities_String(t *testing.T) {
	t.Parallel()
	c := Capabilities{GOOS: "linux", GOARCH: "amd64", OffHeap: true, Mlocked: true}
	s := c.String()
	for _, want := range []string{"linux/amd64", "off-heap", "mlock", "missing:"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
	if strings.Contains(s, "INSECURE") {
		t.Errorf("String() = %q claims INSECURE for an off-heap report", s)
	}

	insecure := Capabilities{GOOS: "plan9", GOARCH: "mips", Insecure: true}
	if s := insecure.String(); !strings.Contains(s, "INSECURE") {
		t.Errorf("String() = %q must flag the insecure fallback", s)
	}
}
