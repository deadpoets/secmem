package secmem

import (
	"strconv"
	"sync"
)

// The quarantine keeps the address range of a destroyed region reserved and
// inaccessible for a while instead of returning it to the OS at once.
//
// Without it, Destroy unmaps the region and the very next allocation is
// likely to be given the same addresses. A slice that a caller wrongly kept
// from a WithBytes callback then points into a DIFFERENT live buffer: reads
// through it return another secret and writes corrupt it, with no fault and no
// error. With it, the range stays a no-access reservation with nothing behind
// it, so such a slice faults, and no later buffer can be placed there.
//
// A quarantined region holds no secret (it was wiped, and its frames are
// gone), no locked memory and no lock-budget charge: it costs address space
// and, on Linux, at most one VMA. It is in neither of the janitor's sets and
// WipeAllSecrets never looks at it.
//
// The quarantine is a bounded FIFO. The guarantee above therefore holds for a
// region while it is among the most recently destroyed ones, and lapses when
// it is evicted and finally unmapped; see [QuarantineLimits].

// QuarantineLimits bounds the destroy-time quarantine.
type QuarantineLimits struct {
	// Regions is the most destroyed regions held at once. Zero disables the
	// quarantine: Destroy unmaps immediately, as it did before it existed.
	Regions int

	// Bytes is the most address space the held regions may reserve together,
	// guard pages included. A single region larger than this is not held at
	// all. Zero disables the quarantine.
	Bytes uint64
}

// DefaultQuarantineLimits returns the limits in force at start-up. They are
// small on 32-bit platforms, where address space is the scarce resource: 64
// regions and 16 MiB, against 4096 regions and 4 GiB on 64-bit ones.
func DefaultQuarantineLimits() QuarantineLimits {
	if strconv.IntSize < 64 {
		return QuarantineLimits{Regions: 64, Bytes: 16 << 20}
	}
	return QuarantineLimits{Regions: 4096, Bytes: 4 << 30}
}

// SetQuarantineLimits replaces the quarantine's limits and returns the
// previous ones. Regions held beyond the new limits are unmapped, oldest
// first, before it returns. It is process-wide, like the quarantine, and safe
// to call at any time; call it once at start-up if the defaults do not suit.
//
// While a destroyed region is held, a slice retained from one of its
// callbacks faults instead of reading or writing whatever was allocated at
// that address next. A larger limit holds regions longer. It has no effect on
// platforms where the quarantine is not implemented (see
// [Capabilities.DestroyQuarantine]).
func SetQuarantineLimits(l QuarantineLimits) (previous QuarantineLimits) {
	if l.Regions < 0 {
		l.Regions = 0
	}
	destroyQuarantine.mu.Lock()
	previous = destroyQuarantine.limits
	destroyQuarantine.limits = l
	evicted := destroyQuarantine.trimLocked()
	destroyQuarantine.mu.Unlock()
	_ = releaseAll(evicted)
	return previous
}

// quarantine is the FIFO of retired reservations. Only the outer range is
// kept: it is the unmap target, and nothing else is ever done to the region.
type quarantine struct {
	mu     sync.Mutex
	limits QuarantineLimits
	held   [][]byte // oldest first
	bytes  uint64
}

//nolint:gochecknoglobals // process-wide, like the janitor it sits behind.
var destroyQuarantine = &quarantine{limits: DefaultQuarantineLimits()}

// quarantineInForce reports whether a destroyed region would be held now.
func quarantineInForce() bool {
	if !quarantineSupported {
		return false
	}
	destroyQuarantine.mu.Lock()
	defer destroyQuarantine.mu.Unlock()
	return destroyQuarantine.limits.Regions > 0 && destroyQuarantine.limits.Bytes > 0
}

// retireSecretMem ends the life of a region whose contents have been wiped:
// it is turned into a no-access reservation and queued, or, where that is not
// possible or not wanted, unmapped as freeSecretMem always did.
//
// The caller holds the region's exclusive lock and no other. The quarantine
// lock nests inside nothing else, so there is no ordering to get wrong.
func retireSecretMem(region secRegion) error {
	if !quarantineSupported || len(region.outer) == 0 {
		return freeSecretMem(region)
	}
	q := destroyQuarantine
	size := uint64(len(region.outer))

	q.mu.Lock()
	admit := q.limits.Regions > 0 && size <= q.limits.Bytes
	q.mu.Unlock()
	if !admit {
		return freeSecretMem(region)
	}
	if err := quarantineSecretMem(region); err != nil {
		// The reservation could not be converted (the VMA limit, say).
		// Nothing may be left mapped and readable, so fall back to the unmap.
		return freeSecretMem(region)
	}

	q.mu.Lock()
	q.held = append(q.held, region.outer)
	q.bytes += size
	evicted := q.trimLocked()
	q.mu.Unlock()
	return releaseAll(evicted)
}

// trimLocked removes the oldest reservations until the limits hold and returns
// them for the caller to unmap after it has dropped the lock.
func (q *quarantine) trimLocked() (evicted [][]byte) {
	n := 0
	for n < len(q.held) && (len(q.held)-n > q.limits.Regions || q.bytes > q.limits.Bytes) {
		q.bytes -= uint64(len(q.held[n]))
		n++
	}
	if n == 0 {
		return nil
	}
	evicted = append(evicted, q.held[:n]...)
	// Copy down rather than re-slice, so the backing array does not keep
	// every range it ever held reachable.
	rest := copy(q.held, q.held[n:])
	clear(q.held[rest:])
	q.held = q.held[:rest]
	return evicted
}

// releaseAll unmaps evicted reservations and returns the first failure.
func releaseAll(evicted [][]byte) error {
	var first error
	for _, outer := range evicted {
		if err := releaseQuarantined(outer); err != nil && first == nil {
			first = err
		}
	}
	return first
}
