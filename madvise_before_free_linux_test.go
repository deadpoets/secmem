//go:build linux

// Proof tests for the frame-release step of Destroy. madviseBeforeFree runs
// while the secret area is still mlocked, where plain MADV_DONTNEED is refused
// with EINVAL, so a test that merely called it and moved on would keep passing
// after the step silently died — which is how it stayed dead until a review
// caught it. These assert the kernel's own record instead: the advice must be
// accepted, and /proc/self/smaps must show the resident frames gone.

package secmem

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// rssKBFor returns the Rss of the /proc/self/smaps entry starting at addr, in
// kB, exactly as the kernel accounts it.
func rssKBFor(t *testing.T, addr uintptr) int {
	t.Helper()
	line, err := smapsLineFor(addr, "Rss:")
	if err != nil {
		t.Fatalf("reading smaps: %v", err)
	}
	fields := strings.Fields(line) // "Rss:", "16", "kB"
	if len(fields) != 3 || fields[2] != "kB" {
		t.Fatalf("unexpected smaps line %q", line)
	}
	kb, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("parsing %q: %v", line, err)
	}
	return kb
}

// kernelAtLeast reports whether the running kernel is at least major.minor.
// It answers true when the release string cannot be read, so an unparseable
// kernel gets the assertion rather than a skip.
func kernelAtLeast(major, minor int) bool {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return true
	}
	var maj, min int
	if _, err := fmt.Sscanf(unix.ByteSliceToString(u.Release[:]), "%d.%d", &maj, &min); err != nil {
		return true
	}
	return maj > major || (maj == major && min >= minor)
}

// requireAdviceTaken asserts madviseBeforeFree succeeded, or skips on a kernel
// too old to know MADV_DONTNEED_LOCKED, where the step is documented as
// unavailable rather than broken.
func requireAdviceTaken(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if errors.Is(err, unix.EINVAL) && !kernelAtLeast(5, 18) {
		t.Skipf("kernel predates MADV_DONTNEED_LOCKED (5.18): %v", err)
	}
	t.Fatalf("madviseBeforeFree on the still-locked area: %v — the frame-release step is inert", err)
}

// TestMadviseBeforeFree_DiscardsLockedAnonFrames pins the anon (L3) tier: the
// advice is accepted on the locked area, the kernel drops every resident frame,
// and a later touch refaults a zero page rather than the old contents.
func TestMadviseBeforeFree_DiscardsLockedAnonFrames(t *testing.T) {
	region, _, info, err := allocMapAnon(4 * unix.Getpagesize())
	if err != nil {
		t.Skipf("allocMapAnon: %v (an mlock refusal is an environment condition)", err)
	}
	defer func() { _ = freeSecretMem(region) }()
	if !info.mlocked {
		t.Fatalf("allocMapAnon did not lock the area; the test would not be exercising the locked path")
	}

	for i := range region.inner {
		region.inner[i] = 0xAB
	}
	addr := uintptr(unsafe.Pointer(&region.inner[0]))
	if got, want := rssKBFor(t, addr), len(region.inner)/1024; got != want {
		t.Fatalf("before advice: Rss = %d kB, want %d kB (mlock should have faulted every page in)", got, want)
	}

	requireAdviceTaken(t, madviseBeforeFree(region))

	if got := rssKBFor(t, addr); got != 0 {
		t.Errorf("after advice: Rss = %d kB, want 0 — the frames were not released", got)
	}
	if !bytes.Equal(region.inner, make([]byte, len(region.inner))) {
		t.Errorf("after advice: area still reads the old contents — the frames were not discarded")
	}
}

// TestMadviseBeforeFree_MemfdSecretZapsOnlyPageTables pins what the same
// advice is worth on the memfd_secret (L4) tier, so the comments in
// madviseBeforeFree and wipeAndFree cannot drift from the kernel: the advice is
// accepted and the page tables are zapped, but the mapping is MAP_SHARED, so
// the folios stay in the secretmem inode and the contents survive — the
// kernel's zeroing at munmap, not this call, is the backstop there.
func TestMadviseBeforeFree_MemfdSecretZapsOnlyPageTables(t *testing.T) {
	region, _, info, err := allocSecretMem(4 * unix.Getpagesize())
	if err != nil {
		t.Skipf("allocSecretMem: %v (an mlock refusal is an environment condition)", err)
	}
	defer func() { _ = freeSecretMem(region) }()
	if !info.memfdSecret {
		t.Skip("memfd_secret unavailable — nothing to pin on this kernel")
	}

	for i := range region.inner {
		region.inner[i] = 0xAB
	}
	addr := uintptr(unsafe.Pointer(&region.inner[0]))
	if got, want := rssKBFor(t, addr), len(region.inner)/1024; got != want {
		t.Fatalf("before advice: Rss = %d kB, want %d kB", got, want)
	}

	requireAdviceTaken(t, madviseBeforeFree(region))

	if got := rssKBFor(t, addr); got != 0 {
		t.Errorf("after advice: Rss = %d kB, want 0 — the page tables were not zapped", got)
	}
	if region.inner[0] != 0xAB {
		t.Errorf("after advice: area reads %#x, want 0xAB — the kernel now discards secretmem folios on advice; update the per-tier comments", region.inner[0])
	}
}
