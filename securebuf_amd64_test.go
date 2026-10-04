//go:build amd64

package secmem

import (
	"testing"

	"golang.org/x/sys/cpu"
)

// TestCPUID_Basic checks the cpuid assembly wrapper against an independent
// reader of the same instruction. Leaf 7, sub-leaf 0 is the leaf the wipe's
// CLFLUSHOPT detection reads, and golang.org/x/sys/cpu reports four of its EBX
// bits without filtering them through OS support: BMI1 (3), BMI2 (8), ERMS (9)
// and ADX (19). A wrapper that returned zeros, or its registers in the wrong
// order, would send the wipe down the CLFLUSH path on every processor and
// nothing else would notice.
func TestCPUID_Basic(t *testing.T) {
	t.Parallel()

	maxLeaf, _, _, _ := cpuid(0, 0)
	if maxLeaf < 7 {
		t.Skipf("CPUID maximum basic leaf is %d: this processor has no leaf 7 to compare", maxLeaf)
	}
	_, ebx, _, _ := cpuid(7, 0)
	t.Logf("CPUID(leaf=7, sub=0): EBX=0x%08x (HasCLFLUSHOPT=%v)", ebx, HasCLFLUSHOPT())

	for _, f := range []struct {
		name string
		bit  uint
		want bool
	}{
		{"BMI1", 3, cpu.X86.HasBMI1},
		{"BMI2", 8, cpu.X86.HasBMI2},
		{"ERMS", 9, cpu.X86.HasERMS},
		{"ADX", 19, cpu.X86.HasADX},
	} {
		if got := ebx>>f.bit&1 == 1; got != f.want {
			t.Errorf("CPUID.7.0:EBX bit %d (%s) = %v, but x/sys/cpu reports %v", f.bit, f.name, got, f.want)
		}
	}
	if got, want := HasCLFLUSHOPT(), ebx>>23&1 == 1; got != want {
		t.Errorf("HasCLFLUSHOPT() = %v, but CPUID.7.0:EBX bit 23 = %v", got, want)
	}
}
