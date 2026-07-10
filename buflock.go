// buflock.go implements a sync.Cond-based reader-writer lock
// that is compatible with testing/synctest.
//
// # Why not sync.RWMutex?
//
// Go 1.26 synctest classifies sync.RWMutex.Lock as "not durably blocked" —
// synctest.Wait() never returns while a goroutine is blocked on it. This is a
// permanent design decision: mutexes can be unlocked from outside a bubble.
//
// sync.Cond.Wait IS durably blocked in synctest. By building the reader-writer
// lock on top of sync.Cond, all blocking states are observable by synctest.Wait().
//
// # Locking protocol
//
//   - rLock: blocks (via cond.Wait) while writerActive or writersWaiting > 0; increments readers.
//   - rUnlock: decrements readers; broadcasts if readers reach zero.
//   - lock: increments writersWaiting; blocks (via cond.Wait) while writerActive or readers > 0;
//     sets writerActive=true; releases mu. Exclusive access is enforced by the writerActive flag.
//   - unlock: clears writerActive; broadcasts.
//
// Writer preference: readers block while writersWaiting > 0, preventing Destroy
// from being starved by concurrent readers.
//
// Memory safety: mu is held only briefly for state transitions. Between lock()
// and unlock(), exclusive access is enforced by the writerActive flag — no other
// goroutine can enter rLock() or lock() while writerActive is true. The mu
// acquire/release pairs in lock() and unlock() provide the necessary
// happens-before edges for memory visibility of data accessed between them.
//
// This type is internal to the secmem package — all methods are unexported.

package secmem

import "sync"

// bufferRWLock is a sync.Cond-based reader-writer lock designed for
// SecureBuffer. It provides the same exclusion guarantees as sync.RWMutex
// but all blocking states are durably blocked under testing/synctest.
//
// Zero value is NOT usable; use newBufferRWLock.
type bufferRWLock struct {
	mu             sync.Mutex
	readers        int
	writerActive   bool // true while a writer holds the lock
	writersWaiting int  // number of writers waiting (for writer preference)
	cond           *sync.Cond
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
	l.mu.Lock()
	for l.writerActive || l.writersWaiting > 0 {
		l.cond.Wait() // durably blocked under synctest
	}
	l.readers++
	l.mu.Unlock()
}

// rUnlock releases shared (reader) access. If this was the last reader,
// broadcasts to wake any waiting writer.
func (l *bufferRWLock) rUnlock() {
	l.mu.Lock()
	l.readers--
	if l.readers == 0 {
		l.cond.Broadcast()
	}
	l.mu.Unlock()
}

// lock acquires exclusive (writer) access. Increments writersWaiting to block
// new readers (writer preference), then blocks via cond.Wait until no writer
// is active and all existing readers have released. On success, sets
// writerActive=true and releases mu. The caller MUST call unlock when done.
func (l *bufferRWLock) lock() {
	l.mu.Lock()
	l.writersWaiting++
	for l.writerActive || l.readers > 0 {
		l.cond.Wait() // durably blocked under synctest
	}
	l.writersWaiting--
	l.writerActive = true
	l.mu.Unlock()
}

// unlock releases exclusive (writer) access. Clears writerActive and
// broadcasts to wake blocked readers and/or writers.
func (l *bufferRWLock) unlock() {
	l.mu.Lock()
	l.writerActive = false
	l.cond.Broadcast()
	l.mu.Unlock()
}
