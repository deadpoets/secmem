//go:build linux

// Proof test for the DESIGN mandate: "the memfd isolation still holds after
// the MAP_FIXED placement." memfd_secret's whole point is that the kernel
// removes the pages from its direct map and refuses gup-based access — a
// privileged reader going through /proc/<pid>/mem gets an error, not the
// secret. If the MAP_FIXED re-placement into the guard reservation broke
// that (e.g. by accidentally mapping ordinary anon memory), this test fails.

package secmem

import (
	"bytes"
	"os"
	"testing"
	"unsafe"
)

// TestMemfdIsolation_HoldsAfterMapFixed reads the buffer's address range via
// /proc/self/mem. On a secretmem-backed mapping the read MUST fail; a control
// read of ordinary heap memory through the same mechanism MUST succeed, so a
// pass cannot come from /proc being unreadable.
func TestMemfdIsolation_HoldsAfterMapFixed(t *testing.T) {
	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if !buf.Capabilities().MemfdSecret {
		t.Skip("memfd_secret not in force on this kernel — nothing to prove")
	}

	// Put a known pattern in the secret so a successful read would be
	// unambiguous.
	pattern := bytes.Repeat([]byte{0x5A}, 64)
	if err := buf.WithBytes(func(b []byte) { copy(b, pattern) }); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}

	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Fatalf("open /proc/self/mem: %v", err)
	}
	defer func() { _ = mem.Close() }()

	// Control: ordinary heap memory IS readable through /proc/self/mem (the
	// kernel allows self-ptrace access). This proves the mechanism works.
	control := []byte("control-heap-value")
	got := make([]byte, len(control))
	if _, err := mem.ReadAt(got, int64(uintptr(unsafe.Pointer(&control[0])))); err != nil {
		t.Skipf("control read of heap via /proc/self/mem failed (%v) — cannot prove anything on this kernel", err)
	}
	if !bytes.Equal(got, control) {
		t.Skip("control read returned wrong bytes — /proc/self/mem semantics unexpected; skipping")
	}

	// The actual proof: the same read against the secretmem-backed mapping
	// must FAIL. A successful read means MAP_FIXED replaced the secretmem
	// mapping with something ordinary — isolation lost.
	leak := make([]byte, 64)
	addr := int64(uintptr(unsafe.Pointer(&buf.region.inner[0])))
	n, err := mem.ReadAt(leak, addr)
	if err == nil && n > 0 {
		t.Fatalf("read %d bytes of a memfd_secret mapping via /proc/self/mem — kernel isolation is NOT in force after MAP_FIXED", n)
	}
	if bytes.Contains(leak[:n], pattern[:8]) {
		t.Fatal("secret pattern visible through /proc/self/mem — isolation lost")
	}
}
