package secmem

import (
	"bytes"
	"testing"
)

// fuzzWipeMaxSize bounds the region under test so the lock budget of a
// hosted runner (and Windows' default minimum working set) stays in reach;
// larger inputs are cut to it rather than skipped so the mutator keeps its
// coverage.
const fuzzWipeMaxSize = 32 << 10

// firstNonZero returns the index of the first non-zero byte, or -1.
func firstNonZero(b []byte) int {
	for i, x := range b {
		if x != 0 {
			return i
		}
	}
	return -1
}

// FuzzWipe_RegionReadsBackZero fuzzes the wipe itself — not the constructor's
// input hygiene, which FuzzNewBuffer_RoundTrip covers. For arbitrary sizes
// and contents it drives the three wipes whose target stays mapped and
// readable afterwards, and reads the region back through the API:
//
//  1. Truncate's tail wipe: the bytes above the new length must be zero,
//     read through WithBytes over the slice's full capacity, and the kept
//     head must be untouched.
//  2. The emergency in-place wipe (WipeAllSecrets): the buffer stays mapped,
//     and the whole secret area — data, and the canary slack behind it —
//     must read as zero.
//  3. The arena's release wipe: every slot filled, released and re-acquired
//     must read back zero.
//
// Destroy's own wipe cannot be read back by construction (the munmap follows
// it — TESTING.md, "Deliberately not proven"), which is why the arena's
// release path stands in for it, as in TestArena_ReleaseWipesSlot. An
// allocation failure is an environment condition and skips, loudly — never
// a silent return that would leave the target looking exercised.
func FuzzWipe_RegionReadsBackZero(f *testing.F) {
	f.Add([]byte("seed"), uint16(2), uint8(1))
	f.Add([]byte{0xFF}, uint16(0), uint8(2))
	f.Add(bytes.Repeat([]byte{0xA5}, 4096), uint16(4095), uint8(3))
	f.Add(bytes.Repeat([]byte{0x5A}, 4097), uint16(1), uint8(1)) // crosses a page boundary
	f.Add(bytes.Repeat([]byte{0x01}, fuzzWipeMaxSize), uint16(fuzzWipeMaxSize-1), uint8(1))

	// Raise the lock budget once so a refusal reflects the host, not the
	// default; the return is deliberately ignored — a refusal to raise is
	// reported by the skip below with the allocator's own error.
	_, _ = EnsureMemlockLimit(8 << 20)

	f.Fuzz(func(t *testing.T, content []byte, cut uint16, slots uint8) {
		if len(content) == 0 {
			return // a zero-length buffer is a documented constructor error
		}
		if len(content) > fuzzWipeMaxSize {
			content = content[:fuzzWipeMaxSize]
		}
		n := int(cut) % (len(content) + 1) // new length in [0, len]

		// 1. Truncate's tail wipe.
		buf, err := NewBuffer(append([]byte(nil), content...))
		if err != nil {
			t.Skipf("NewBuffer(%d bytes): %v (an mlock refusal is an environment condition)", len(content), err)
		}
		defer func() { _ = buf.Destroy() }()
		if err := buf.Truncate(n); err != nil {
			t.Fatalf("Truncate(%d) of %d: %v", n, len(content), err)
		}
		if err := buf.WithBytes(func(b []byte) {
			if len(b) != n || cap(b) != len(content) {
				t.Fatalf("after Truncate(%d): len %d cap %d, want len %d cap %d", n, len(b), cap(b), n, len(content))
			}
			full := b[:cap(b)]
			if !bytes.Equal(full[:n], content[:n]) {
				t.Fatal("Truncate changed the kept head")
			}
			if i := firstNonZero(full[n:]); i >= 0 {
				t.Fatalf("Truncate left byte %d of the wiped tail non-zero (%#x)", n+i, full[n+i]) //nolint:secmem-lint // diagnostic on failure only; reports the one non-zero byte of a wiped region
			}
		}); err != nil {
			t.Fatalf("WithBytes after Truncate: %v", err)
		}

		// 2. The emergency in-place wipe. The region stays mapped, so the
		// wipe's result is readable — over the data and the slack behind it.
		live, err := NewBuffer(append([]byte(nil), content...))
		if err != nil {
			t.Skipf("NewBuffer(%d bytes): %v (an mlock refusal is an environment condition)", len(content), err)
		}
		defer func() { _ = live.Destroy() }()
		if err := WipeAllSecrets(); err != nil {
			t.Fatalf("WipeAllSecrets: %v", err)
		}
		for name, b := range map[string]*SecureBuffer{"live": live, "truncated": buf} {
			if err := b.WithBytes(func(data []byte) {
				if i := firstNonZero(data[:cap(data)]); i >= 0 {
					t.Fatalf("WipeAllSecrets left byte %d of the %s buffer non-zero (%#x)", i, name, data[i]) //nolint:secmem-lint // diagnostic on failure only; reports the one non-zero byte of a wiped region
				}
				// Whole secret area, canary slack included: the in-place
				// wipe must not stop at the data's end. Read under the
				// borrow's lock, as the region cannot move or unmap here.
				if i := firstNonZero(b.region.inner); i >= 0 {
					t.Fatalf("WipeAllSecrets left byte %d of the %s buffer's %d-byte secret area non-zero (%#x)", i, name, len(b.region.inner), b.region.inner[i])
				}
			}); err != nil {
				t.Fatalf("WithBytes after WipeAllSecrets (%s): %v", name, err)
			}
		}

		// 3. The arena's release wipe, over every slot.
		count := int(slots)%3 + 1
		a, err := NewArena(len(content), count)
		if err != nil {
			t.Skipf("NewArena(%d, %d): %v (an mlock refusal is an environment condition)", len(content), count, err)
		}
		defer func() { _ = a.Destroy() }()
		held := make([]*ArenaSlot, 0, count)
		for i := 0; i < count; i++ {
			s, err := a.Acquire()
			if err != nil {
				t.Fatalf("Acquire %d: %v", i, err)
			}
			if err := s.WithBytes(func(b []byte) { copy(b, content) }); err != nil {
				t.Fatalf("fill slot %d: %v", i, err)
			}
			held = append(held, s)
		}
		for i, s := range held {
			if err := s.Release(); err != nil {
				t.Fatalf("Release slot %d: %v", i, err)
			}
		}
		// count == Cap, so re-acquiring count slots visits every index.
		for i := 0; i < count; i++ {
			s, err := a.Acquire()
			if err != nil {
				t.Fatalf("re-Acquire %d: %v", i, err)
			}
			if err := s.WithBytes(func(b []byte) {
				if j := firstNonZero(b); j >= 0 {
					t.Fatalf("slot %d byte %d reads %#x after Release; the release wipe missed it", s.Index(), j, b[j]) //nolint:secmem-lint // diagnostic on failure only; reports the one non-zero byte of a wiped region
				}
			}); err != nil {
				t.Fatalf("read re-acquired slot %d: %v", i, err)
			}
			if err := s.Release(); err != nil {
				t.Fatalf("Release re-acquired slot %d: %v", i, err)
			}
		}
	})
}
