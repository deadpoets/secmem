//go:build linux

// Proof test for the THP/KSM opt-outs: instead of trusting that madvise
// returned 0, read the kernel's own record of the VMA flags from
// /proc/self/smaps and require "nh" (no-hugepage) on the secret area.

package secmem

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"
)

// vmFlagsFor returns the VmFlags line of the /proc/self/smaps entry whose
// range starts at addr, or an error if the mapping is not found.
func vmFlagsFor(addr uintptr) (string, error) {
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	prefix := fmt.Sprintf("%x-", addr)
	inTarget := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, " ") && strings.Contains(line, "-") {
			inTarget = strings.HasPrefix(line, prefix)
		}
		if inTarget && strings.HasPrefix(line, "VmFlags:") {
			return line, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("mapping at %x not found in smaps", addr)
}

// TestMadvise_NoHugepageInForce verifies the kernel recorded MADV_NOHUGEPAGE
// on the anon secret area — khugepaged will not copy-collapse these pages.
func TestMadvise_NoHugepageInForce(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/mm/transparent_hugepage"); err != nil {
		t.Skip("kernel built without THP — the opt-out is unnecessary and unrecorded")
	}

	// allocMapAnon path: always anonymous memory (never memfd), where THP
	// collapse is the live threat.
	buf, err := NewSyscallSafeBuffer([]byte("no-thp-copies-of-me"))
	if err != nil {
		t.Fatalf("NewSyscallSafeBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	flags, err := vmFlagsFor(uintptr(unsafe.Pointer(&buf.region.inner[0])))
	if err != nil {
		t.Fatalf("reading smaps: %v", err)
	}
	if !strings.Contains(flags, " nh") {
		t.Errorf("VmFlags missing 'nh' (no-hugepage): %q — MADV_NOHUGEPAGE not in force", flags)
	}
	// The locked flag should be present too — cheap cross-check that we are
	// looking at the right VMA.
	if !strings.Contains(flags, " lo") {
		t.Errorf("VmFlags missing 'lo' (locked): %q — wrong VMA or mlock not in force", flags)
	}
}
