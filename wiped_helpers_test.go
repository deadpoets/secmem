package secmem

import (
	"errors"
	"testing"
)

// A borrow on an emergency-wiped buffer or arena returns ErrWiped, so a test
// cannot ask WithBytes what the wipe left behind. These helpers read the
// mapping itself, under the region's read lock, which is the only way left to
// observe the zeros the wipe promises.

// bufRegionIsZero reports whether every usable byte of buf's region is zero.
// The region must still be mapped: a destroyed buffer fails the test.
func bufRegionIsZero(t *testing.T, buf *SecureBuffer) bool {
	t.Helper()
	buf.mu.rLock()
	defer buf.mu.rUnlock()
	if buf.data == nil {
		t.Fatal("bufRegionIsZero: buffer is destroyed, nothing mapped to read")
	}
	return firstNonZero(buf.data) < 0
}

// slotRegionIsZero is bufRegionIsZero for one arena slot's usable bytes.
func slotRegionIsZero(t *testing.T, s *ArenaSlot) bool {
	t.Helper()
	a := s.arena
	a.mu.rLock()
	defer a.mu.rUnlock()
	if a.region.inner == nil {
		t.Fatal("slotRegionIsZero: arena is destroyed, nothing mapped to read")
	}
	start := int(s.idx) * a.stride
	return firstNonZero(a.region.inner[start:start+a.slotSize]) < 0
}

// requireWiped fails unless err is ErrWiped, and checks the ErrDestroyed
// wrapping that keeps errors.Is(err, ErrDestroyed) callers working.
func requireWiped(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrWiped) {
		t.Errorf("%s after the emergency wipe = %v, want ErrWiped", what, err)
	}
	if !errors.Is(err, ErrDestroyed) {
		t.Errorf("%s error does not satisfy errors.Is(err, ErrDestroyed): %v", what, err)
	}
}
