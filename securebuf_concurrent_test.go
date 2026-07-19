package secmem

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"sync"
	"testing"
	"testing/synctest"
)

// TestConcurrentProtectionTransitions stresses the state machine the read-only
// fault lived in: many goroutines issue random access and mutate calls while
// others flip ReadOnly/ReadWrite/Seal/Unseal on the SAME buffer. The contract
// under test is the one the fault violated — every call must return (success or
// a sentinel), never fault the process. Run under -race (the CI test jobs do)
// for the data-race half of the guarantee: the flag checks and the mprotect
// must be consistent to every locked observer, and ReadFrom/WriteTo must re-
// check protection after dropping the lock for their I/O.
func TestConcurrentProtectionTransitions(t *testing.T) {
	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	const (
		goroutines = 8
		iters      = 3000
	)
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(g)+1, 0x9e3779b9))
			src := []byte{1, 2, 3, 4}
			dst := make([]byte, 4)
			for range iters {
				switch r.IntN(11) {
				case 0:
					_ = buf.ReadOnly()
				case 1:
					_ = buf.ReadWrite()
				case 2:
					_ = buf.Seal()
				case 3:
					_ = buf.Unseal()
				case 4:
					_, _ = buf.CopyIn(src, 0)
				case 5:
					_ = buf.SetByteAt(0, 0xAA)
				case 6:
					_, _ = buf.CopyOut(dst, 0)
				case 7:
					_, _ = buf.ByteAt(0)
				case 8:
					_, _ = buf.ReadFrom(bytes.NewReader(src))
				case 9:
					_, _ = buf.WriteTo(io.Discard)
				case 10:
					_ = buf.Len()
					_ = buf.IsSealed()
				}
			}
		}(g)
	}
	wg.Wait()

	// The buffer must remain usable after the storm — no state was corrupted.
	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal after stress: %v", err)
	}
	if err := buf.ReadWrite(); err != nil {
		t.Fatalf("ReadWrite after stress: %v", err)
	}
	if _, err := buf.CopyIn([]byte{9}, 0); err != nil {
		t.Fatalf("CopyIn after stress: %v", err)
	}
}

// TestConcurrentAccess verifies that multiple goroutines may call WithBytesErr
// simultaneously without data races or panics. Uses testing/synctest for
// deterministic goroutine scheduling (Go 1.26).
func TestConcurrentAccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		original := []byte("concurrent-access-data")
		want := make([]byte, len(original))
		copy(want, original)

		buf, err := NewBuffer(original) // NewBuffer wipes original after copying
		if err != nil {
			t.Fatalf("NewBuffer: %v", err)
		}
		defer func() { _ = buf.Destroy() }()

		const N = 8
		errCh := make(chan error, N)

		for range N {
			go func() {
				errCh <- buf.WithBytesErr(func(got []byte) error {
					if len(got) != len(want) {
						return fmt.Errorf("len mismatch: got %d, want %d", len(got), len(want))
					}
					for i, b := range got {
						if b != want[i] {
							return fmt.Errorf("byte[%d] = %d, want %d", i, b, want[i])
						}
					}
					return nil
				})
			}()
		}

		synctest.Wait() // wait until all goroutines have finished or are durably blocked

		for range N {
			if err := <-errCh; err != nil {
				t.Errorf("concurrent WithBytesErr: %v", err)
			}
		}
	})
}

// TestDestroyBlocksUntilAccessDrains verifies that Destroy (which takes an
// exclusive lock) blocks until all in-flight WithBytesErr calls (which hold
// shared read locks) complete.
//
// This uses testing/synctest because the underlying bufferRWLock is built on
// sync.Cond, whose Wait is classified as durably blocked by the synctest
// runtime. No timing heuristics needed.
func TestDestroyBlocksUntilAccessDrains(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf, err := NewEmptyBuffer(8)
		if err != nil {
			t.Fatalf("NewEmptyBuffer: %v", err)
		}

		release := make(chan struct{})

		// Goroutine 1: hold rLock via WithBytesErr until channel fires.
		go func() {
			_ = buf.WithBytesErr(func(_ []byte) error {
				<-release // durably blocked on channel — keeps rLock active
				return nil
			})
		}()

		// Wait until goroutine 1 is blocked in the callback (holding rLock).
		synctest.Wait()

		// Goroutine 2: Destroy — blocks on cond.Wait (durably blocked)
		// waiting for readers to drain.
		destroyErr := make(chan error, 1)
		go func() {
			destroyErr <- buf.Destroy()
		}()

		// synctest.Wait returns — goroutine 2 is durably blocked on cond.Wait.
		// This is the assertion: Destroy has NOT completed.
		synctest.Wait()

		select {
		case <-destroyErr:
			t.Fatal("Destroy completed before rLock was released")
		default:
			// correct — Destroy is blocked waiting for readers to drain
		}

		// Release goroutine 1 → rLock drains → cond.Broadcast → Destroy proceeds.
		close(release)
		synctest.Wait()

		// Destroy must have completed.
		select {
		case err := <-destroyErr:
			if err != nil {
				t.Errorf("Destroy returned error: %v", err)
			}
		default:
			t.Fatal("Destroy did not complete after rLock release")
		}

		if !buf.IsDestroyed() {
			t.Error("IsDestroyed() = false after Destroy")
		}
	})
}

// channelBlockWriter blocks inside Write until unblock is closed, then writes p.
// Implements io.Writer. Used in lock-scope tests.
type channelBlockWriter struct {
	unblock <-chan struct{}
}

func (w *channelBlockWriter) Write(p []byte) (int, error) {
	<-w.unblock // durably blocked under synctest
	return len(p), nil
}

// channelBlockReader blocks on the first Read call until unblock is closed,
// then returns data. Implements io.Reader. Used in lock-scope tests.
type channelBlockReader struct {
	unblock <-chan struct{}
	data    []byte
	pos     int
}

func (r *channelBlockReader) Read(p []byte) (int, error) {
	<-r.unblock // durably blocked under synctest
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// TestWriteToReleasesLockBeforeWrite verifies that WriteTo copies data under
// the read lock and then releases it before calling w.Write. A stalled writer
// must not prevent Destroy from proceeding.
//
// With the old implementation (holding rLock during w.Write), both goroutines
// would be durably blocked — Destroy waiting for the rLock that WriteTo holds,
// WriteTo waiting for the channel — and synctest would deadlock. With the fix,
// Destroy completes before WriteTo's Write call returns.
func TestWriteToReleasesLockBeforeWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		data := []byte("write-lock-test-data")
		buf, err := NewBuffer(data)
		if err != nil {
			t.Fatalf("NewBuffer: %v", err)
		}

		unblock := make(chan struct{})
		sw := &channelBlockWriter{unblock: unblock}

		writeErrCh := make(chan error, 1)
		go func() {
			_, err := buf.WriteTo(sw)
			writeErrCh <- err
		}()

		// WriteTo copies data under rLock, releases rLock, then blocks in sw.Write.
		synctest.Wait()

		// Destroy — should proceed immediately since WriteTo no longer holds rLock.
		destroyErrCh := make(chan error, 1)
		go func() {
			destroyErrCh <- buf.Destroy()
		}()

		synctest.Wait()

		select {
		case err := <-destroyErrCh:
			if err != nil {
				t.Errorf("Destroy: %v", err)
			}
		default:
			t.Fatal("Destroy must complete without waiting for WriteTo to unblock")
		}

		// Unblock WriteTo — it should complete and the temp copy is wiped.
		close(unblock)
		synctest.Wait()

		select {
		case <-writeErrCh:
			// WriteTo completed (success or error both acceptable).
		default:
			t.Fatal("WriteTo must complete after unblocking")
		}
	})
}

// TestReadFromReleasesLockDuringRead verifies that ReadFrom does not hold the
// exclusive lock during io.ReadFull, allowing Destroy to proceed concurrently
// with a stalled reader.
//
// With the old implementation (holding xLock during io.ReadFull), Destroy would
// block trying to acquire the same lock. With the fix, Destroy completes first.
func TestReadFromReleasesLockDuringRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const size = 16
		buf, err := NewEmptyBuffer(size)
		if err != nil {
			t.Fatalf("NewEmptyBuffer: %v", err)
		}

		unblock := make(chan struct{})
		sr := &channelBlockReader{
			unblock: unblock,
			data:    []byte("read-lock-test-16"),
		}

		readErrCh := make(chan error, 1)
		go func() {
			_, err := buf.ReadFrom(sr)
			readErrCh <- err
		}()

		// ReadFrom reads size, releases any lock, then blocks in sr.Read.
		synctest.Wait()

		// Destroy — should proceed immediately since ReadFrom holds no lock.
		destroyErrCh := make(chan error, 1)
		go func() {
			destroyErrCh <- buf.Destroy()
		}()

		synctest.Wait()

		select {
		case err := <-destroyErrCh:
			if err != nil {
				t.Errorf("Destroy: %v", err)
			}
		default:
			t.Fatal("Destroy must complete without waiting for ReadFrom to unblock")
		}

		// Unblock ReadFrom. It sees s.data == nil and returns ErrDestroyed.
		close(unblock)
		synctest.Wait()

		select {
		case <-readErrCh:
			// ReadFrom completed (ErrDestroyed is expected).
		default:
			t.Fatal("ReadFrom must complete after unblocking")
		}
	})
}
