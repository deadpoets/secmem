// AMD64 CPU feature detection and high-level wipe helpers.
// Separated from wipe_amd64.go to keep assembly prototypes minimal.
package secmem

import "unsafe"

// supportsCLFLUSHOPT caches the CPUID result for HasCLFLUSHOPT queries.
// The assembly GLOBL ·hasCLFLUSHOPT is set in parallel so the wipe loop
// can read it without a CGo/unsafe boundary.
var supportsCLFLUSHOPT bool //nolint:gochecknoglobals // CPU feature flag — set once during init, read-only thereafter.

func init() { //nolint:gochecknoinits // CPU feature detection must run before any secureWipe call.
	supportsCLFLUSHOPT = detectCLFLUSHOPT(cpuid)

	if supportsCLFLUSHOPT {
		setCLFLUSHOPTFlag(1)
	} else {
		setCLFLUSHOPTFlag(0)
	}
}

// cpuidFunc is the signature of the CPUID wrapper (cpuid in wipe_amd64.go).
// detectCLFLUSHOPT takes one as a parameter so the detection logic can be run
// against a processor other than the one executing the test.
type cpuidFunc func(eax, ecx uint32) (a, b, c, d uint32)

// detectCLFLUSHOPT reports whether the processor answering query supports
// CLFLUSHOPT: CPUID leaf 7, sub-leaf 0, EBX bit 23.
// Reference: Intel SDM Vol. 2A §3-141, Table 3-8.
//
// Leaf 7 is queried only after leaf 0 has confirmed the processor implements
// it. CPUID with EAX above the maximum basic leaf (CPUID.(EAX=0):EAX) neither
// faults nor returns zeros: it returns the data of the highest basic leaf the
// processor does implement (SDM Vol. 2A §3-191, CPUID, "input EAX larger than
// the maximum"). A processor whose maximum basic leaf is below 7 — AMD K8 and
// K10 report 1 and 5, and both are valid GOAMD64=v1 targets — would therefore
// answer an unguarded leaf-7 query with leaf 1's or leaf 5's EBX, in which bit
// 23 is a byte of the logical-processor count or of the MONITOR line size, and
// a 1 there would send secureWipe down the CLFLUSHOPT path on a processor that
// has no such instruction. Absent leaf, absent feature: the strictly-ordered
// CLFLUSH the whole amd64 baseline guarantees is the correct fallback.
func detectCLFLUSHOPT(query cpuidFunc) bool {
	maxLeaf, _, _, _ := query(0, 0)
	if maxLeaf < 7 {
		return false
	}
	_, ebx, _, _ := query(7, 0)
	return (ebx>>23)&1 != 0
}

// HasCLFLUSHOPT reports whether the CPU supports the CLFLUSHOPT instruction.
// Detected once via CPUID at package init; cached for the process lifetime.
// When true, secureWipe uses pipelined CLFLUSHOPT (Intel Skylake+ / AMD Zen+).
// When false, it falls back to strictly-ordered CLFLUSH (universally supported).
func HasCLFLUSHOPT() bool { return supportsCLFLUSHOPT }

// secureWipeSlice zeroes all bytes in b using the full architectural wipe:
// LFENCE → REP STOSB → SFENCE → CLFLUSH[OPT] loop → SFENCE+LFENCE.
func secureWipeSlice(b []byte) {
	if len(b) == 0 {
		return
	}
	//nolint:gosec // G103: passing the slice base to the asm wipe routine; the only way to reach it.
	secureWipe(unsafe.Pointer(&b[0]), uintptr(len(b)))
}
