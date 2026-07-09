package secmem

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// TestBufferRWLock_ConcurrentReaders verifies that multiple goroutines can
// acquire rLock simultaneously without blocking each other.
func TestBufferRWLock_ConcurrentReaders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newBufferRWLock()
		const N = 8
		entered := make(chan struct{}, N)

		for range N {
			go func() {
				l.rLock()
				entered <- struct{}{}
				// hold the lock — will be released after test observes entry
			}()
		}

		synctest.Wait()

		// All N goroutines should have entered.
		if got := len(entered); got != N {
			t.Fatalf("entered = %d, want %d", got, N)
		}

		// Clean up: release all reader locks.
		for range N {
			l.rUnlock()
		}
	})
}

// TestBufferRWLock_WriterBlocksUntilReadersDrain verifies that lock() blocks
// (via cond.Wait) until all readers have called rUnlock, and that
// synctest.Wait() correctly observes this as durably blocked.
func TestBufferRWLock_WriterBlocksUntilReadersDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newBufferRWLock()
		release := make(chan struct{})

		// Goroutine 1: hold rLock until channel fires.
		go func() {
			l.rLock()
			<-release
			l.rUnlock()
		}()

		synctest.Wait() // goroutine 1 is blocked on <-release, holding rLock

		// Goroutine 2: attempt writer lock — must block on cond.Wait.
		writerDone := make(chan struct{})
		go func() {
			l.lock()
			l.unlock()
			close(writerDone)
		}()

		synctest.Wait() // goroutine 2 is durably blocked on cond.Wait

		// Writer must NOT have completed yet.
		select {
		case <-writerDone:
			t.Fatal("writer completed before reader released")
		default:
			// correct
		}

		// Release reader → writer should proceed.
		close(release)
		synctest.Wait()

		select {
		case <-writerDone:
			// correct — writer completed
		default:
			t.Fatal("writer did not complete after reader released")
		}
	})
}

// TestBufferRWLock_WriterPreference verifies that new readers block while a
// writer is waiting. This prevents reader starvation of Destroy.
func TestBufferRWLock_WriterPreference(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newBufferRWLock()

		// Hold an initial reader lock.
		releaseInitial := make(chan struct{})
		go func() {
			l.rLock()
			<-releaseInitial
			l.rUnlock()
		}()
		synctest.Wait()

		// Start a writer — it will set writerWaiting and block on cond.Wait.
		writerDone := make(chan struct{})
		go func() {
			l.lock()
			l.unlock()
			close(writerDone)
		}()
		synctest.Wait()

		// Now try a new reader — it should block because writerWaiting is true.
		var newReaderEntered atomic.Bool
		go func() {
			l.rLock()
			newReaderEntered.Store(true)
			l.rUnlock()
		}()
		synctest.Wait()

		if newReaderEntered.Load() {
			t.Fatal("new reader entered while writer was waiting")
		}

		// Release initial reader → writer proceeds → then new reader can enter.
		close(releaseInitial)
		synctest.Wait()

		select {
		case <-writerDone:
			// correct
		default:
			t.Fatal("writer did not complete after initial reader released")
		}

		synctest.Wait()

		if !newReaderEntered.Load() {
			t.Fatal("new reader never entered after writer completed")
		}
	})
}

// TestBufferRWLock_Mutex_Semantics verifies that a writer excludes other
// writers and all readers.
func TestBufferRWLock_Mutex_Semantics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newBufferRWLock()

		// Writer 1: acquire and hold the lock.
		releaseWriter1 := make(chan struct{})
		go func() {
			l.lock()
			<-releaseWriter1
			l.unlock()
		}()
		synctest.Wait()

		// Writer 2: should block.
		writer2Done := make(chan struct{})
		go func() {
			l.lock()
			l.unlock()
			close(writer2Done)
		}()
		synctest.Wait()

		select {
		case <-writer2Done:
			t.Fatal("writer 2 acquired lock while writer 1 held it")
		default:
			// correct
		}

		// Reader should also block while writer holds the lock.
		var readerEntered atomic.Bool
		go func() {
			l.rLock()
			readerEntered.Store(true)
			l.rUnlock()
		}()
		synctest.Wait()

		if readerEntered.Load() {
			t.Fatal("reader entered while writer held the lock")
		}

		// Release writer 1 → writer 2 and reader should proceed.
		close(releaseWriter1)
		synctest.Wait()

		// Writer 2 should have completed (it was next in line).
		select {
		case <-writer2Done:
			// correct
		default:
			t.Fatal("writer 2 did not complete after writer 1 released")
		}

		synctest.Wait()

		if !readerEntered.Load() {
			t.Fatal("reader never entered after all writers completed")
		}
	})
}
