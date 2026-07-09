package secmem

import "testing"

// TestSecureWipe_UnalignedSubSlices is the regression guard for the amd64
// cache-flush alignment fix (SB-1). secureWipe is called on many non-page-
// aligned heap/stack slices (digests, derived keys, arena slots), so the wipe
// must:
//   - zero EXACTLY the target range for every start offset and length, and
//   - never touch bytes outside the range, even though the cache-flush loop
//     now rounds the flush start DOWN to a 64-byte boundary (which may sit
//     before the slice start) and runs to ptr+length.
//
// The flush itself is not observable from Go, but exercising every alignment
// and a range of lengths that cross cache-line boundaries confirms the loop
// terminates, never faults, and the zeroing bounds are exact.
func TestSecureWipe_UnalignedSubSlices(t *testing.T) {
	t.Parallel()

	const (
		guard = 0xAB // sentinel for bytes that must remain untouched
		fill  = 0x5C // sentinel for bytes that must be zeroed
		// Large enough to span several cache lines plus partial head/tail.
		backing = 512
	)

	// Cover every byte offset within two cache lines and a spread of lengths
	// that straddle 64-byte boundaries.
	for start := range 128 {
		for _, length := range []int{1, 7, 31, 33, 63, 64, 65, 127, 129, 200} {
			if start+length > backing {
				continue
			}

			buf := make([]byte, backing)
			for i := range buf {
				buf[i] = guard
			}
			for i := start; i < start+length; i++ {
				buf[i] = fill
			}

			SecureWipe(buf[start : start+length])

			for i := range backing {
				inRange := i >= start && i < start+length
				switch {
				case inRange && buf[i] != 0:
					t.Fatalf("start=%d len=%d: byte %d not zeroed (got %#x)", start, length, i, buf[i])
				case !inRange && buf[i] != guard:
					t.Fatalf("start=%d len=%d: out-of-range byte %d clobbered (got %#x)", start, length, i, buf[i])
				}
			}
		}
	}
}
