// buflock.go implements a reader-writer lock with an atomic read fast path
// and sync.Cond-based blocking, compatible with testing/synctest.
//
// # Why not sync.RWMutex?
//
// Go 1.26 synctest classifies sync.RWMutex.Lock as "not durably blocked" —
// synctest.Wait() never returns while a goroutine is blocked on it. This is a
// permanent design decision: mutexes can be unlocked from outside a bubble.
//
// sync.Cond.Wait IS durably blocked in synctest. Every path in this lock that
// BLOCKS therefore blocks in cond.Wait — which is all synctest needs, because
// synctest observes blocking states, and a fast path that succeeds never
// blocks. That distinction is what allows the hybrid below.
//
// # Why there is a fast path
//
// The first version of this lock took its mutex on every rLock and rUnlock, to
// move a reader count. Measured under contention (see TESTING.md, "What the
// contention benchmarks found"), that made the lock ~85% of the cost of an
// arena borrow at 16 cores — goroutines borrowing entirely disjoint secrets
// serialized on the two mutex round trips per borrow, and aggregate throughput
// FELL as cores were added. For a lock whose read side sits under every
// SecureBuffer access and every ArenaSlot borrow, the read path is the hot
// path, and a mutex on it is the wrong primitive.
//
// The read path is now a single atomic Add in each direction and takes no
// mutex at all unless a writer is involved. Writers (Destroy, ReadOnly /
// ReadWrite, Seal, the emergency wipe) stay on the mutex+cond slow path —
// they are rare lifecycle events, and they are exactly the operations whose
// blocking must be observable under synctest.
//
// # Locking protocol
//
// readers holds the active-reader count, biased by -bufMaxReaders whenever a
// writer is active or waiting. One atomic word carries both facts, so a reader
// can test-and-enroll in one Add:
//
//   - rLock fast path: Add(1) > 0 means "no writer active or waiting, and I am
//     now counted". Done — no mutex, no blocking.
//   - rLock slow path (result <= 0): a writer is in play. Undo the optimistic
//     increment under mu — waking the writer if that undo was the drain it was
//     waiting for — then cond.Wait until no writer is active or waiting, then
//     enroll for real (safe under mu: installing the bias requires mu, so no
//     writer can slip in).
//   - rUnlock fast path: Add(-1) >= 0 means no writer is waiting; done.
//     If the result is exactly -bufMaxReaders, this was the LAST active reader
//     a waiting writer needed to drain: take mu and broadcast.
//   - lock: under mu, the first arriving writer installs the bias
//     (Add(-bufMaxReaders)), which makes every subsequent fast-path rLock
//     bounce to the slow path; then cond.Wait until no writer is active and
//     the count shows zero active readers (== -bufMaxReaders exactly).
//   - unlock: under mu, clear writerActive; if no further writer is waiting,
//     lift the bias (Add(+bufMaxReaders)) so fast-path readers flow again;
//     broadcast either way.
//   - tryLock: under mu, refuse if a writer is active or waiting; otherwise
//     claim readers with a single CompareAndSwap(0, -bufMaxReaders), which
//     atomically excludes fast-path readers. A CAS beaten by a transient
//     reader reports false, which is within tryLock's best-effort contract.
//
// Writer preference is unchanged from the original: the bias is installed the
// moment the FIRST writer starts waiting and is not lifted until the LAST
// writer finishes, so new readers cannot starve Destroy.
//
// # Why the missed-wakeup argument holds
//
// Every transition that can satisfy a waiter's predicate happens under mu and
// broadcasts: the last-reader drain (from rUnlock's slow tail or a slow-path
// reader's undo), writerActive clearing, and the bias lift. Fast-path
// transitions never satisfy anyone's predicate — a fast rLock/rUnlock with no
// writer in play changes state no waiter is watching — so they need no
// broadcast. A reader's transient +1/-1 while a writer waits is benign: the
// undo happens under mu and re-broadcasts if it produced the drained state.
//
// # Memory model
//
// sync/atomic operations are sequentially consistent in the Go memory model.
// A writer enters its critical section only after loading readers ==
// -bufMaxReaders, which happens-after every prior reader's Add(-1) — so the
// writer's munmap/mprotect cannot race a borrow that was still reading. A
// reader enters only after an Add(1) that observed the bias lifted, which
// happens-after the writer's entire critical section. The mu acquire/release
// pairs cover the slow-path flags as before.
//
// This type is internal to the secmem package — all methods are unexported.

package secmem

import (
	"sync"
	"sync/atomic"
)

// bufMaxReaders is the writer bias. Any real reader count is far below it, so
// a biased word is always negative and Add(1)'s sign alone tells a reader
// whether a writer is in play.
const bufMaxReaders = 1 << 30

// bufferRWLock is a reader-writer lock whose read side is a single atomic Add
// per acquire/release, and whose blocking states are all sync.Cond waits so
// they are durably blocked under testing/synctest.
//
// Zero value is NOT usable; use newBufferRWLock.
type bufferRWLock struct {
	mu   sync.Mutex
	cond *sync.Cond

	// readers = active-reader count, minus bufMaxReaders while a writer is
	// active or waiting. The ONLY state the fast paths touch.
	readers atomic.Int32

	// writersWaiting counts writers blocked in lock(); writerActive is true
	// while one holds the lock. Guarded by mu.
	writersWaiting int
	writerActive   bool
}

// newBufferRWLock constructs a ready-to-use bufferRWLock.
func newBufferRWLock() *bufferRWLock {
	l := &bufferRWLock{}
	l.cond = sync.NewCond(&l.mu)
	return l
}

// rLock acquires shared (reader) access. Blocks while a writer is active or
// waiting (writer preference). Multiple readers may hold rLock concurrently.
func (l *bufferRWLock) rLock() {
	if l.readers.Add(1) > 0 {
		return // fast path: no writer active or waiting; we are counted
	}
	l.rLockSlow()
}

// rLockSlow parks the reader until no writer is active or waiting, then
// enrolls it. Split out so rLock's fast path stays inlinable.
func (l *bufferRWLock) rLockSlow() {
	l.mu.Lock()
	// Undo the optimistic increment. If the undo produced exactly the bias,
	// this phantom was the last thing keeping a waiting writer's drain check
	// false — wake it.
	if l.readers.Add(-1) == -bufMaxReaders {
		l.cond.Broadcast()
	}
	for l.writerActive || l.writersWaiting > 0 {
		l.cond.Wait() // durably blocked under synctest
	}
	// No writer active or waiting, and none can arrive while mu is held (both
	// installing the bias and setting the flags require mu) — so the bias is
	// off and this Add enrolls a real reader.
	l.readers.Add(1)
	l.mu.Unlock()
}

// rUnlock releases shared (reader) access. If this was the last active reader
// a waiting writer needed to drain, wakes it.
func (l *bufferRWLock) rUnlock() {
	if r := l.readers.Add(-1); r < 0 && r == -bufMaxReaders {
		// A writer is waiting and this was the last active reader: hand off.
		// The broadcast is taken under mu so it cannot slip between the
		// writer's predicate check and its cond.Wait.
		l.mu.Lock()
		l.cond.Broadcast()
		l.mu.Unlock()
	}
}

// lock acquires exclusive (writer) access. The first waiting writer installs
// the bias, bouncing new readers to the slow path (writer preference); it then
// waits via cond.Wait until no writer is active and every already-enrolled
// reader has released. The caller MUST call unlock when done.
func (l *bufferRWLock) lock() {
	l.mu.Lock()
	l.writersWaiting++
	if l.writersWaiting == 1 && !l.writerActive {
		// First writer in: install the bias. Later writers find it already
		// installed (by this writer or by the one currently active, which
		// keeps it until the last writer leaves).
		l.readers.Add(-bufMaxReaders)
	}
	for l.writerActive || l.readers.Load() != -bufMaxReaders {
		l.cond.Wait() // durably blocked under synctest
	}
	l.writersWaiting--
	l.writerActive = true
	l.mu.Unlock()
}

// tryLock attempts to acquire exclusive (writer) access without blocking. It
// reports whether the lock was taken; on true the caller MUST call unlock.
//
// It fails rather than waits when a reader or writer holds the lock — and also
// when another writer is merely WAITING, so a tryLock caller can never barge
// ahead of a blocked Destroy. Used by the emergency-wipe path to wipe every
// region it can take immediately before blocking on the ones still borrowed.
func (l *bufferRWLock) tryLock() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.writerActive || l.writersWaiting > 0 {
		return false
	}
	// No writer in play, so the bias is off. Claim the lock only if there are
	// also no active readers — one CAS does both atomically. A fast-path
	// reader mid-flight makes the CAS fail, which reports false: within
	// contract, since tryLock's caller treats false as "come back with the
	// blocking path".
	if !l.readers.CompareAndSwap(0, -bufMaxReaders) {
		return false
	}
	l.writerActive = true
	return true
}

// unlock releases exclusive (writer) access. If no further writer is waiting,
// lifts the bias so fast-path readers flow again; wakes everyone either way.
func (l *bufferRWLock) unlock() {
	l.mu.Lock()
	l.writerActive = false
	if l.writersWaiting == 0 {
		// Last writer out: lift the bias. If more writers are queued the bias
		// stays, preserving writer preference across the whole convoy.
		l.readers.Add(bufMaxReaders)
	}
	l.cond.Broadcast()
	l.mu.Unlock()
}
