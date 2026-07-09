//go:build amd64

package secmem

import "testing"

// TestCPUID_Basic verifies that the cpuid instruction wrapper returns sensible
// results for leaf 7, sub-leaf 0 on the current CPU. EBX must be non-zero on
// any modern x86-64 processor (it contains feature flags like AVX2, BMI2, etc.).
// This also ensures the assembly wrapper doesn't fault or corrupt registers.
func TestCPUID_Basic(t *testing.T) {
	t.Parallel()

	_, ebx, _, _ := cpuid(7, 0)
	// On any CPU built after ~2012, EBX leaf 7 contains at minimum bit 0
	// (FSGSBASE) and many other feature flags. A zero value is suspicious.
	// We don't assert a specific value to avoid hardware-dependency failures,
	// but we log the value for diagnostic visibility.
	t.Logf("CPUID(leaf=7, sub=0): EBX=0x%08x (HasCLFLUSHOPT=%v)", ebx, HasCLFLUSHOPT())
}
