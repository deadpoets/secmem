// canary.go implements the overflow canary: the page-rounded slack between a
// buffer's usable bytes and its mapping boundary (and the inter-slot strips
// of a SecureArena) is filled with a random pattern that is verified before
// the memory is wiped. An overflow that stays INSIDE the mapping — too short
// to reach the guard page — corrupts the pattern and is reported as
// ErrCanaryViolation instead of passing silently.
//
// HONESTY: the canary is a memory-safety bug-catcher, NOT a confidentiality
// control. It detects accidental overwrites by the process itself; it does
// nothing against an attacker who can read process memory (that is
// memfd_secret's job), and an in-process attacker who can read the pattern
// can forge it. The pattern is process-global, generated once from
// crypto/rand — the same design as OpenBSD malloc and glibc stack canaries.

package secmem

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"sync"
)

// canaryLen is the length of the repeating canary pattern. 16 bytes makes an
// accidental match of an overwritten strip 2^-128 per block — negligible —
// while keeping arena inter-slot strips cheap.
const canaryLen = 16

var (
	canaryOnce    sync.Once
	canaryPattern [canaryLen]byte
	canaryInitErr error
)

// canaryInit generates the process-global pattern on first use. A crypto/rand
// failure is returned (and allocation fails closed) rather than falling back
// to a predictable pattern: a canary that can be guessed by accident is a
// canary that lies.
func canaryInit() error {
	canaryOnce.Do(func() {
		if _, err := rand.Read(canaryPattern[:]); err != nil {
			canaryInitErr = fmt.Errorf("secmem: canary init: %w", err)
		}
	})
	return canaryInitErr
}

// fillCanary writes the repeating pattern over b (the slack or strip to arm).
// An empty b is a no-op.
func fillCanary(b []byte) error {
	if err := canaryInit(); err != nil {
		return err
	}
	for i := range b {
		b[i] = canaryPattern[i%canaryLen]
	}
	return nil
}

// canaryLayout enumerates the [start,end) ranges of a region's inner bytes that
// fillCanary armed — WITHOUT materializing them.
//
// It is a descriptor rather than a [][2]int because an arena's zones used to
// cost more memory than the secrets they guard. A SecureArena arms one strip
// per slot plus a page-rounding tail, so the materialized form was 16 bytes of
// ordinary, swappable, GC-visible Go heap per slot — for a 32-byte slot, a third
// of the per-slot heap bookkeeping and comfortably larger than the strip it
// described. The layout is perfectly regular, so a descriptor regenerates it in
// O(1) space.
//
// A SecureBuffer has exactly one zone (the page slack past its usable bytes)
// and uses tail alone.
//
// Pointer-free by construction: no slice header, nothing for the GC to trace,
// and nothing that has to stay alive on the janitor's behalf after the owning
// wrapper is gone.
type canaryLayout struct {
	// stride, slotSize and count describe an arena's inter-slot strips: zone i
	// is [i*stride+slotSize, (i+1)*stride) for 0 <= i < count. All zero for a
	// buffer, which has no strips.
	stride, slotSize, count int

	// tail is the single trailing zone — a buffer's page slack, or an arena's
	// page-rounding remainder past the last strip. Empty when tail[1] <= tail[0],
	// which is the exact-fit case and is normal, not an error.
	tail [2]int
}

// bufferCanary describes a buffer's single slack zone: everything between its
// usable bytes and the end of the mapping. Empty when the allocation happens to
// land exactly on the boundary.
func bufferCanary(usable, innerLen int) canaryLayout {
	if usable >= innerLen {
		return canaryLayout{}
	}
	return canaryLayout{tail: [2]int{usable, innerLen}}
}

// arenaCanary describes an arena's per-slot strips plus its page-rounding tail.
func arenaCanary(stride, slotSize, count, innerLen int) canaryLayout {
	l := canaryLayout{stride: stride, slotSize: slotSize, count: count}
	if used := count * stride; used < innerLen {
		l.tail = [2]int{used, innerLen}
	}
	return l
}

// forEachZone calls fn with every armed [lo,hi) range, in ascending order,
// stopping early if fn returns false.
func (c canaryLayout) forEachZone(fn func(lo, hi int) bool) {
	for i := 0; i < c.count; i++ {
		lo, hi := i*c.stride+c.slotSize, (i+1)*c.stride
		if lo >= hi {
			continue
		}
		if !fn(lo, hi) {
			return
		}
	}
	if c.tail[0] < c.tail[1] {
		fn(c.tail[0], c.tail[1])
	}
}

// arm fills every zone of the layout with the canary pattern.
//
// Arming and verifying are driven by the SAME descriptor, which is the point of
// having one: a strip that is armed but not checked (or checked but never
// armed) is a canary that lies, and keeping the two loops in separate files is
// how that happens.
func (c canaryLayout) arm(inner []byte) error {
	var err error
	c.forEachZone(func(lo, hi int) bool {
		if !inBounds(lo, hi, len(inner)) {
			return true
		}
		if e := fillCanary(inner[lo:hi]); e != nil {
			err = e
			return false
		}
		return true
	})
	return err
}

// intact reports whether every zone still holds the pattern arm wrote. Like the
// loop it replaces it stops at the first violated zone: which zone was hit is
// already reported to the caller as a single boolean, and the per-zone
// comparison remains constant-time (see canaryIntact).
func (c canaryLayout) intact(inner []byte) bool {
	ok := true
	c.forEachZone(func(lo, hi int) bool {
		if !inBounds(lo, hi, len(inner)) {
			return true
		}
		if !canaryIntact(inner[lo:hi]) {
			ok = false
			return false
		}
		return true
	})
	return ok
}

// inBounds guards the slice expressions above. By construction every generated
// zone lies inside the mapping — allocSecretMem rounds the region UP past
// count*stride — so this never fires. It is here anyway because these two
// methods run on the emergency-wipe path, which executes during process
// termination and possibly from a signal handler: a bounds panic there would
// abandon every secret the pass had not reached yet. Skipping a malformed zone
// degrades one check; panicking loses the wipe.
func inBounds(lo, hi, length int) bool {
	return lo >= 0 && lo < hi && hi <= length
}

// canaryIntact reports whether b still holds the exact pattern fillCanary
// wrote. The comparison is constant-time in len(b) — it does not short-circuit
// at the first mismatch, so the check's timing reveals nothing about where a
// corruption sits. An empty b is vacuously intact. If the canary was never
// initialized (allocation would have failed), b cannot have been filled and
// the answer is false.
func canaryIntact(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if canaryInit() != nil {
		return false
	}
	acc := byte(0)
	for i := range b {
		acc |= b[i] ^ canaryPattern[i%canaryLen]
	}
	return subtle.ConstantTimeByteEq(acc, 0) == 1
}
