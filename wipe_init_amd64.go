// AMD64 CPU feature detection and high-level wipe helpers.
// Separated from wipe_amd64.go to keep assembly prototypes minimal.
package secmem

import "unsafe"

// supportsCLFLUSHOPT caches the CPUID result for HasCLFLUSHOPT queries.
// The assembly GLOBL ·hasCLFLUSHOPT is set in parallel so the wipe loop
// can read it without a CGo/unsafe boundary.
var supportsCLFLUSHOPT bool //nolint:gochecknoglobals // CPU feature flag — set once during init, read-only thereafter.

func init() { //nolint:gochecknoinits // CPU feature detection must run before any secureWipe call.
	// CPUID leaf 7, sub-leaf 0, EBX bit 23 signals CLFLUSHOPT support.
	// Reference: Intel SDM Vol. 2A §3-141, Table 3-8.
	_, ebx, _, _ := cpuid(7, 0)
	supportsCLFLUSHOPT = (ebx>>23)&1 != 0

	if supportsCLFLUSHOPT {
		setCLFLUSHOPTFlag(1)
	} else {
		setCLFLUSHOPTFlag(0)
	}
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
