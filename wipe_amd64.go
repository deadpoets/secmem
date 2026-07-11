// Assembly prototypes for AMD64 cryptographic memory wipe routines.
// Implementations live in wipe_amd64.s.
package secmem

import "unsafe"

// cpuid executes the CPUID instruction and returns all four output registers.
// Called once during init() for CPU feature detection.
//
//go:noescape
func cpuid(eax, ecx uint32) (a, b, c, d uint32)

// setCLFLUSHOPTFlag writes a byte (0 or 1) into the assembly GLOBL ·hasCLFLUSHOPT.
// The wipe loop reads this byte to choose between CLFLUSH and CLFLUSHOPT paths.
//
//go:noescape
func setCLFLUSHOPTFlag(v byte)

// secureWipe zeroes length bytes at ptr, then evicts all cache lines.
// The 5-step sequence: LFENCE → REP STOSB → SFENCE → CLFLUSH[OPT] loop → SFENCE+LFENCE.
// NOSPLIT in the assembly prevents stack growth that could copy secret data.
//
//go:noescape
func secureWipe(ptr unsafe.Pointer, length uintptr)

// archWipeGuaranteed: the amd64 wipe is assembly with a cache-line flush
// (LFENCE → REP STOSB → SFENCE → CLFLUSH[OPT] → SFENCE+LFENCE).
const archWipeGuaranteed = true
