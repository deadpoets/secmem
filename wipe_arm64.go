// Assembly prototypes for ARM64 cryptographic memory wipe routines.
// Implementations live in wipe_arm64.s.
//
// The _arm64.go filename suffix constrains this file to arm64 builds only.
package secmem

import "unsafe"

// secureWipe zeroes length bytes at ptr, then evicts all cache lines via DC CIVAC.
// The 5-step sequence: DMB ISHST → zero loop → DMB ISH → DC CIVAC loop → DSB ISH + ISB.
// NOSPLIT in the assembly prevents stack growth that could copy secret data.
//
//go:noescape
func secureWipe(ptr unsafe.Pointer, length uintptr)

// HasCLFLUSHOPT always returns false on arm64.
// Cache eviction is performed unconditionally via DC CIVAC in secureWipe.
func HasCLFLUSHOPT() bool { return false }

// setCLFLUSHOPTFlag is a no-op on arm64.
func setCLFLUSHOPTFlag(_ byte) {}

// cpuid is not available on arm64; returns zero values.
func cpuid(_, _ uint32) (uint32, uint32, uint32, uint32) { return 0, 0, 0, 0 }

// secureWipeSlice zeroes all bytes in b using the full ARM64 wipe:
// DMB ISHST → zero loop → DMB ISH → DC CIVAC loop → DSB ISH + ISB.
func secureWipeSlice(b []byte) {
	if len(b) == 0 {
		return
	}
	secureWipe(unsafe.Pointer(&b[0]), uintptr(len(b)))
}

// archWipeFlushed: the arm64 wipe is assembly with cache eviction
// (DMB ISHST → zero → DMB ISH → DC CIVAC → DSB ISH + ISB).
const archWipeFlushed = true
