// capabilities.go implements honest capability reporting: the Capabilities
// struct, the Probe() startup preflight, and the per-allocation plumbing that
// feeds SecureBuffer.Capabilities() and SecureArena.Capabilities().
//
// Probe() reports what THIS platform can do; the per-object methods report
// what a specific allocation ACTUALLY got. The two can differ: memfd_secret
// can fail per-call (ENOSYS, EPERM under kernel lockdown, RLIMIT) and fall
// through to mmap+mlock, so the per-buffer value is the honest one.

package secmem

import (
	"runtime"
	"strings"
)

// Capabilities describes which memory protections are in force, either for
// the platform as a whole ([Probe]) or for one specific allocation
// ([SecureBuffer.Capabilities], [SecureArena.Capabilities]).
//
// Every field is stated per the platform guarantee matrix in the package
// documentation. A false field is not an error — it is the truth about what
// this build, kernel, and allocation provide. Use [Capabilities.Warnings] to
// enumerate the protections NOT in force.
type Capabilities struct {
	// GOOS and GOARCH identify the build this report describes.
	GOOS, GOARCH string

	// OffHeap reports that the memory lives outside the Go heap (mmap or
	// VirtualAlloc, not make([]byte)) — the GC never scans, moves, or copies it.
	OffHeap bool

	// Mlocked reports that the pages are excluded from swap (mlock /
	// VirtualLock, or memfd_secret's kernel-enforced equivalent).
	Mlocked bool

	// MemfdSecret reports kernel isolation: the pages are invisible to
	// /proc/<pid>/mem, ptrace, and other readers of process memory.
	// Linux amd64 with kernel 5.14+ only, and can fail per-allocation.
	MemfdSecret bool

	// NoDump reports the allocation is excluded from crash dumps: on Linux,
	// MADV_DONTDUMP took effect or the memory is memfd_secret-backed; on
	// Windows, WerRegisterExcludedMemoryBlock succeeded — which covers
	// WER-generated dumps only (a debugger-driven dump still captures the
	// pages; Seal's cipher covers the dormant window there). Process-wide
	// exclusion ([HardenProcess], [DisableCoreDumps]) is NOT reflected here.
	NoDump bool

	// NoFork reports MADV_DONTFORK took effect: forked children do not
	// inherit the mapping.
	NoFork bool

	// FlushedWipe reports the destroy-time wipe is architecture assembly
	// with a cache-line flush (amd64 CLFLUSH/CLFLUSHOPT, arm64 DC CIVAC).
	// When false the wipe is a constant-time store loop only — the zeros are
	// written, but lines may linger in cache.
	FlushedWipe bool

	// RegisterScrub reports runtime/secret erasure is active
	// (GOEXPERIMENT=runtimesecret on a supported platform): [Scrub] erases
	// the registers, stack, and heap of its callback's entire call tree.
	// When false, Scrub is a best-effort stack-frame wipe.
	RegisterScrub bool

	// GuardPages reports PROT_NONE guard pages bracket the mapping so a
	// linear over/under-flow traps (SIGSEGV / access violation) instead of
	// silently touching adjacent memory. A memory-safety bug-catcher, not a
	// secrecy mechanism. False only on the insecure heap fallback.
	GuardPages bool

	// Insecure reports the memory is plain heap — NO protection is in force.
	// True only on platforms with no lockable off-heap memory.
	Insecure bool
}

// allocInfo records which protections one specific allocation actually
// received. Platform allocSecretMem/allocMapAnon implementations fill it at
// allocation time; constructors store it for Capabilities().
type allocInfo struct {
	offHeap     bool
	mlocked     bool
	memfdSecret bool
	noDump      bool
	noFork      bool
	guardPages  bool
	insecure    bool
}

// capsFromAlloc composes a Capabilities report from a specific allocation's
// facts plus the process-wide facts (build identity, wipe class, scrub layer).
func capsFromAlloc(info allocInfo) Capabilities {
	return Capabilities{
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		OffHeap:       info.offHeap,
		Mlocked:       info.mlocked,
		MemfdSecret:   info.memfdSecret,
		NoDump:        info.noDump,
		NoFork:        info.noFork,
		FlushedWipe:   archWipeFlushed,
		RegisterScrub: RuntimeSecretActive(),
		GuardPages:    info.guardPages,
		Insecure:      info.insecure,
	}
}

// Probe reports what this platform can do, by performing one real one-byte
// allocation through the same path the constructors use and reporting what it
// received. Call it once at startup to log or gate on the protections in
// force; per-allocation truth is [SecureBuffer.Capabilities].
//
// Probe is not cached: it reflects the kernel and limits at the moment of the
// call. If even the probe allocation fails, the report is fully degraded
// (every protection false) — treat that as this platform providing nothing.
func Probe() Capabilities {
	region, _, info, err := allocSecretMem(1)
	if err != nil {
		return capsFromAlloc(allocInfo{})
	}
	secureWipeSlice(region.inner)
	_ = freeSecretMem(region)
	return capsFromAlloc(info)
}

// Warnings returns a human-readable line for every protection NOT in force,
// most severe first. An empty slice means every protection this library can
// provide is active. Intended for startup logging:
//
//	for _, w := range secmem.Probe().Warnings() {
//	    slog.Warn("secmem", "degradation", w)
//	}
func (c Capabilities) Warnings() []string {
	var w []string
	if c.Insecure {
		w = append(w, "INSECURE: plain heap fallback — no memory protection is in force at all")
	}
	if !c.OffHeap && !c.Insecure {
		w = append(w, "memory is on the Go heap — the GC may copy secrets during collection")
	}
	if !c.Mlocked {
		w = append(w, "pages are not locked — secrets may be written to the swap device")
	}
	if !c.MemfdSecret {
		w = append(w, "no kernel isolation (memfd_secret) — a sufficiently privileged process or debugger can read the memory")
	}
	if !c.NoDump {
		w = append(w, "not excluded from core dumps")
	}
	if !c.NoFork {
		w = append(w, "mapping is inherited by forked children (no MADV_DONTFORK)")
	}
	if !c.FlushedWipe {
		w = append(w, "wipe is a constant-time store only — no cache-line flush on this architecture")
	}
	if !c.RegisterScrub {
		w = append(w, "runtime/secret erasure inactive — Scrub is a best-effort stack-frame wipe")
	}
	if !c.GuardPages {
		w = append(w, "no guard pages — buffer overflows are not trapped")
	}
	return w
}

// String returns a compact one-line summary: the build identity, the
// protections in force, and the protections missing. It never prints secret
// material — Capabilities holds none.
func (c Capabilities) String() string {
	var have, miss []string
	flag := func(name string, on bool) {
		if on {
			have = append(have, name)
		} else {
			miss = append(miss, name)
		}
	}
	flag("off-heap", c.OffHeap)
	flag("mlock", c.Mlocked)
	flag("memfd_secret", c.MemfdSecret)
	flag("no-dump", c.NoDump)
	flag("no-fork", c.NoFork)
	flag("wipe+flush", c.FlushedWipe)
	flag("register-scrub", c.RegisterScrub)
	flag("guard-pages", c.GuardPages)

	var b strings.Builder
	b.WriteString(c.GOOS)
	b.WriteByte('/')
	b.WriteString(c.GOARCH)
	if c.Insecure {
		b.WriteString(" INSECURE(heap)")
	}
	if len(have) > 0 {
		b.WriteString(" [")
		b.WriteString(strings.Join(have, " "))
		b.WriteByte(']')
	}
	if len(miss) > 0 {
		b.WriteString(" missing:[")
		b.WriteString(strings.Join(miss, " "))
		b.WriteByte(']')
	}
	return b.String()
}

// Capabilities reports how THIS buffer's allocation is actually backed —
// the honest per-allocation counterpart to [Probe] (memfd_secret can fail
// per-call and fall through to mmap+mlock; this reflects what happened).
//
// The report is fixed at construction and remains valid after Destroy.
// A nil receiver reports a fully degraded posture.
func (s *SecureBuffer) Capabilities() Capabilities {
	if s == nil {
		return capsFromAlloc(allocInfo{})
	}
	return capsFromAlloc(s.backing)
}

// Capabilities reports how this arena's slab is actually backed. Every slot
// shares the slab's single allocation, so one report covers them all.
//
// The report is fixed at construction and remains valid after Destroy.
// A nil receiver reports a fully degraded posture.
func (a *SecureArena) Capabilities() Capabilities {
	if a == nil {
		return capsFromAlloc(allocInfo{})
	}
	return capsFromAlloc(a.backing)
}
