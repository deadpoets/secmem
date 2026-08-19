package secmemcrypto

import (
	"bytes"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/curve25519"

	"github.com/deadpoets/secmem"
)

// bufAddr is the ordering key ConstantTimeEqual uses. Kept in one place so the
// test cannot drift from the implementation by ordering a different way.
func bufAddr(b *secmem.SecureBuffer) uintptr {
	return uintptr(unsafe.Pointer(b))
}

// newLockOrderKey builds a key whose scalar buffer this test manipulates
// directly. Allocation failure is an environment condition, not a defect.
func newLockOrderKey(t *testing.T, fill byte) *X25519Key {
	t.Helper()
	buf, err := secmem.NewBuffer(bytes.Repeat([]byte{fill}, curve25519.ScalarSize))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	k, err := NewX25519Key(buf)
	if err != nil {
		_ = buf.Destroy()
		t.Fatalf("NewX25519Key: %v", err)
	}
	return k
}

// readsPark reports whether a fresh read acquire on buf fails to complete
// within d. From outside the core module that is the only way to observe that
// a queued writer has enrolled and writer preference is in effect — the lock
// itself is unexported. A probe that parks stays parked until the writer
// finishes, so wg tracks it for cleanup.
func readsPark(buf *secmem.SecureBuffer, d time.Duration, wg *sync.WaitGroup) bool {
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		_ = buf.WithBytes(func([]byte) {})
	}()
	select {
	case <-done:
		return false
	case <-time.After(d):
		return true
	}
}

// TestX25519Key_ConstantTimeEqual_AcquiresInAddressOrder pins the acquisition
// ORDER, which is the property that makes the ABBA deadlock impossible.
//
// Taking the two read locks in argument order deadlocks:
// a.ConstantTimeEqual(b) and b.ConstantTimeEqual(a) running concurrently take
// them in opposite directions. Read locks are shared, so the cycle needs a
// writer queued on each buffer — which secmem's writer-preferring lock makes
// routine, since a Destroy or an emergency wipe is enough.
//
// The deadlock itself is not what is asserted here. Reproducing it needs both
// goroutines paused BETWEEN their two acquires, and there is no hook to pause
// them; the equivalent stress test in the core module passed just as happily
// against the unfixed code, which is what makes it worthless. The order is
// directly observable instead, and it is the actual fix.
//
// This module builds against a RELEASED core tag, so it cannot reach the
// core's internals the way core's own version of this test does. It rigs the
// buffers through exported API instead:
//
//   - the HIGHER-addressed buffer gets a held reader plus a queued writer, so
//     every new read acquire on it parks (writer preference);
//   - the LOWER-addressed buffer is sealed, so a read acquire on it returns
//     ErrSealed immediately and never runs the nested callback.
//
// Then ConstantTimeEqual is called with the HIGHER-addressed key as the
// RECEIVER, so argument order and address order disagree:
//
//   - ordered (fixed): the lower-addressed buffer is taken first, fails fast on
//     ErrSealed, and the higher-addressed buffer is never touched — the call
//     returns.
//   - argument order (unfixed): the receiver is read-locked first, which parks
//     behind the queued writer — the call never returns.
//
// So "the call returns at all" is exactly the fixed ordering.
func TestX25519Key_ConstantTimeEqual_AcquiresInAddressOrder(t *testing.T) {
	k1 := newLockOrderKey(t, 0x11)
	k2 := newLockOrderKey(t, 0x22)

	lo, hi := k1, k2
	if bufAddr(lo.scalarBuf) > bufAddr(hi.scalarBuf) {
		lo, hi = hi, lo
	}

	// Hold a reader on the higher-addressed buffer, then queue a writer behind
	// it. The writer cannot proceed until the reader leaves, and while it waits
	// the lock's writer preference parks every new reader.
	var probes sync.WaitGroup
	readerHeld := make(chan struct{})
	releaseReader := make(chan struct{})
	readerReturned := make(chan struct{})
	go func() {
		defer close(readerReturned)
		_ = hi.scalarBuf.WithBytesErr(func([]byte) error {
			close(readerHeld)
			<-releaseReader
			return nil
		})
	}()
	<-readerHeld

	writerReturned := make(chan error, 1)
	go func() { writerReturned <- hi.scalarBuf.ReadOnly() }()

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			close(releaseReader)
			<-readerReturned
			werr := <-writerReturned
			probes.Wait()
			if werr == nil {
				// Documented contract: ReadWrite before Destroy.
				if err := hi.scalarBuf.ReadWrite(); err != nil {
					t.Errorf("ReadWrite: %v", err)
				}
			}
		})
	}
	defer func() {
		cleanup()
		_ = hi.Destroy()
		_ = lo.Destroy()
	}()

	// Wait for the writer to enroll. Until it has, reads on hi still succeed
	// and the rig would prove nothing.
	deadline := time.Now().Add(5 * time.Second)
	for !readsPark(hi.scalarBuf, 50*time.Millisecond, &probes) {
		if time.Now().After(deadline) {
			t.Fatal("queued writer never took effect: reads on the higher-addressed buffer still complete")
		}
	}

	if err := lo.scalarBuf.Seal(); err != nil {
		t.Skipf("Seal (needed to make the lower-addressed acquire fail fast): %v", err)
	}

	returned := make(chan bool, 1)
	go func() { returned <- hi.ConstantTimeEqual(lo) }() // receiver is the HIGHER address

	select {
	case equal := <-returned:
		if equal {
			t.Error("ConstantTimeEqual returned true for two different, one sealed, keys")
		}
	case <-time.After(5 * time.Second):
		cleanup() // unwedge before failing, so the deferred Destroy cannot hang
		<-returned
		t.Fatal("ConstantTimeEqual blocked on the higher-addressed buffer: it acquires in " +
			"argument order, so a concurrent reversed comparison deadlocks (ABBA)")
	}
}
