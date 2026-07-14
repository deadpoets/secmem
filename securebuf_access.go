// securebuf_access.go implements the controlled access API for SecureBuffer.
//
// The borrowing accessors hold the lock for the whole operation, so Destroy
// (which takes the write lock) cannot race an in-flight access. The copy-out
// methods (ExposeString, WriteTo, ReadFrom) are the deliberate exception: they
// snapshot the contents under the lock and release it before returning or
// streaming the copy, so a slow reader/writer cannot block Destroy, including
// the signal-wipe path.
//
// Locking protocol:
//
//	rLock — held by the read accessors for the full operation; concurrent
//	        reads are safe.
//	lock  — held by Destroy and the mutating methods; blocks until rLocks drain.
//
// This eliminates the classic TOCTOU race of lock → copy pointer → unlock →
// use pointer: between the unlock and the use, Destroy could Munmap the
// region, causing a SIGSEGV.

package secmem

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

// WithBytes calls fn with the underlying byte slice. The slice is valid ONLY
// for the duration of fn — it MUST NOT be stored or referenced after fn returns.
//
// The RLock is held for the entire callback, so Destroy blocks until fn returns.
// This is the preferred access pattern; use WithBytesErr when fn returns an error.
//
// NOT REENTRANT: fn MUST NOT call any access method on the SAME buffer
// (WithBytes, WithBytesErr, CopyOut, ConstantTimeEqual, …). The lock is writer-
// preferring, so if another goroutine calls Destroy/CopyIn/Seal/ReadOnly while
// fn holds the read lock, a nested same-buffer read lock would block on the
// waiting writer while that writer blocks on fn's outstanding read lock —
// a deadlock. Nesting access to a DIFFERENT buffer (e.g. the decrypt-into
// pattern: key.WithBytesErr → out.WithBytesErr) is safe and expected.
//
// Returns ErrDestroyed if the buffer has been destroyed.
func (s *SecureBuffer) WithBytes(fn func([]byte)) error {
	if fn == nil {
		return errors.New("secmem.SecureBuffer.WithBytes: nil fn")
	}
	if s == nil {
		return ErrDestroyed
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	if s.data == nil {
		return ErrDestroyed
	}
	if s.sealed {
		return ErrSealed
	}
	fn(s.data)
	return nil
}

// WithBytesErr is like WithBytes but fn may return an error, which is propagated.
// Returns ErrDestroyed if the buffer has been destroyed; fn is not called in that case.
//
// NOT REENTRANT: as with [SecureBuffer.WithBytes], fn must not call another
// access method on the same buffer (deadlock risk under a concurrent writer);
// nesting onto a different buffer is safe.
func (s *SecureBuffer) WithBytesErr(fn func([]byte) error) error {
	if fn == nil {
		return errors.New("secmem.SecureBuffer.WithBytesErr: nil fn")
	}
	if s == nil {
		return ErrDestroyed
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	if s.data == nil {
		return ErrDestroyed
	}
	if s.sealed {
		return ErrSealed
	}
	return fn(s.data)
}

// ExposeString returns the buffer contents as a Go string, for third-party
// APIs that accept only strings. It is the weakest accessor in the package;
// prefer [SecureBuffer.WithBytes] or [SecureBuffer.WithBytesErr] whenever the
// consumer can take a []byte.
//
// Because Go strings are immutable, the returned string is a copy of the secret
// that secmem can neither lock, exclude from core dumps, nor wipe. A fresh copy
// is made on every call. It is unaffected by Destroy and lives until the
// garbage collector reclaims it — and the GC does not zero reclaimed memory, so
// the bytes may linger until that memory is reused.
//
// Keeping the returned string is safe — connection pools, loggers, and caches
// routinely do — but it extends the secret's lifetime beyond secmem's control.
// Do not use ExposeString for material whose exposure must end at Destroy.
//
// The copy is taken under the read lock. On GOEXPERIMENT=runtimesecret builds
// it is a garbage-collector-tracked allocation, erased once nothing references
// it — best-effort timing, never a guarantee; a string you keep is never
// erased.
//
// Returns ErrDestroyed if the buffer has been destroyed and ErrSealed if it is
// sealed.
func (s *SecureBuffer) ExposeString() (string, error) {
	var str string
	if err := s.WithBytesErr(func(b []byte) error {
		// Snapshot the secret as a string under the read lock. Do NOT try to
		// wipe str afterwards: for len(b)==1 the runtime returns a string
		// aliasing its global staticuint64s table (no copy is made), and
		// mutating a string a caller may have retained violates Go's
		// immutability contract and races readers invisibly to the race
		// detector. On runtimesecret builds Scrub makes the copy a
		// GC-tracked allocation that is erased once nothing references it.
		Scrub(func() { str = string(b) }) //nolint:secmem-lint
		return nil
	}); err != nil {
		return "", err
	}
	return str, nil
}

// CopyOut copies bytes from the buffer into dst, starting at srcOffset.
// Returns the number of bytes copied (min of len(dst) and available bytes).
//
// It is a random-access copy, not an [io.Reader]; the streaming counterpart is
// [SecureBuffer.WriteTo]. The RLock is held for the entire copy. If dst is
// itself an off-heap region, no heap copy occurs. If dst is heap-allocated,
// the caller is responsible for wiping it.
func (s *SecureBuffer) CopyOut(dst []byte, srcOffset int) (int, error) {
	if s == nil {
		return 0, ErrDestroyed
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	if s.data == nil {
		return 0, ErrDestroyed
	}
	if s.sealed {
		return 0, ErrSealed
	}
	if srcOffset < 0 || srcOffset >= len(s.data) {
		return 0, fmt.Errorf("secmem.SecureBuffer.CopyOut: srcOffset %d out of range [0, %d)", srcOffset, len(s.data))
	}
	return copy(dst, s.data[srcOffset:]), nil
}

// CopyIn copies bytes from src into the buffer, starting at dstOffset.
// Returns the number of bytes written (min of len(src) and available space).
//
// It is a random-access copy, not an [io.Writer]; the streaming counterpart is
// [SecureBuffer.ReadFrom]. The exclusive lock is held for the copy,
// serializing all concurrent writes and preventing races with
// ReadOnly/ReadWrite page-protection changes.
func (s *SecureBuffer) CopyIn(src []byte, dstOffset int) (int, error) {
	if s == nil {
		return 0, ErrDestroyed
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.data == nil {
		return 0, ErrDestroyed
	}
	if s.sealed {
		return 0, ErrSealed
	}
	if dstOffset < 0 || dstOffset >= len(s.data) {
		return 0, fmt.Errorf("secmem.SecureBuffer.CopyIn: dstOffset %d out of range [0, %d)", dstOffset, len(s.data))
	}
	return copy(s.data[dstOffset:], src), nil
}

// ByteAt returns the byte at index i.
// Returns an error if i is out of range or the buffer has been destroyed.
//
// Design note: a conventional implementation panics on a bad index; secmem
// returns an error instead, honoring the library's "no panics in library
// code" policy.
func (s *SecureBuffer) ByteAt(i int) (byte, error) {
	if s == nil {
		return 0, ErrDestroyed
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	if s.data == nil {
		return 0, ErrDestroyed
	}
	if s.sealed {
		return 0, ErrSealed
	}
	if i < 0 || i >= len(s.data) {
		return 0, fmt.Errorf("secmem.SecureBuffer.ByteAt: index %d out of range [0, %d)", i, len(s.data))
	}
	return s.data[i], nil
}

// SetByteAt sets the byte at index i to v.
// Returns an error if i is out of range or the buffer has been destroyed.
//
// The exclusive lock is held to prevent races with ReadOnly/ReadWrite and
// concurrent Write calls.
func (s *SecureBuffer) SetByteAt(i int, v byte) error {
	if s == nil {
		return ErrDestroyed
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.data == nil {
		return ErrDestroyed
	}
	if s.sealed {
		return ErrSealed
	}
	if i < 0 || i >= len(s.data) {
		return fmt.Errorf("secmem.SecureBuffer.SetByteAt: index %d out of range [0, %d)", i, len(s.data))
	}
	s.data[i] = v
	return nil
}

// ConstantTimeEqual performs a constant-time comparison of the buffer contents
// against other. Returns (false, nil) when lengths differ.
// Returns (false, ErrDestroyed) if the buffer has been destroyed.
func (s *SecureBuffer) ConstantTimeEqual(other []byte) (bool, error) {
	if s == nil {
		return false, ErrDestroyed
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	if s.data == nil {
		return false, ErrDestroyed
	}
	if s.sealed {
		return false, ErrSealed
	}
	if len(s.data) != len(other) {
		return false, nil
	}
	return subtle.ConstantTimeCompare(s.data, other) == 1, nil
}

// WriteTo implements io.WriterTo. Copies the buffer contents into a temporary
// heap slice under the read lock, releases the lock, then writes the copy to w.
//
// This decouples Destroy from any I/O latency: a stalled network peer or slow
// pipe no longer prevents Destroy (including the signal wipe path) from
// proceeding. The temporary copy is wiped via secureWipeSlice after the write.
//
// NOTE: For network or pipe targets, wrap w with a write deadline before
// calling WriteTo to bound the lifetime of the in-flight copy.
func (s *SecureBuffer) WriteTo(w io.Writer) (int64, error) {
	if s == nil {
		return 0, ErrDestroyed
	}
	s.mu.rLock()
	if s.data == nil {
		s.mu.rUnlock()
		return 0, ErrDestroyed
	}
	if s.sealed {
		s.mu.rUnlock()
		return 0, ErrSealed
	}
	// Copy under rLock so the snapshot is consistent; release before blocking I/O.
	tmp := make([]byte, len(s.data))
	copy(tmp, s.data)
	s.mu.rUnlock()

	// Deferred so the heap copy is wiped on every outcome — including a
	// panicking io.Writer, which would otherwise unwind past an inline wipe.
	defer secureWipeSlice(tmp)
	n, err := w.Write(tmp)
	return int64(n), err
}

// ReadFrom implements io.ReaderFrom. Reads up to Len() bytes from r into the
// buffer. The exclusive lock is NOT held during io.ReadFull: data is read into
// a temporary heap slice first, then copied into secure memory under the lock.
//
// This prevents a stalled network peer or slow pipe from blocking Destroy
// (including the signal wipe path). The temporary slice is wiped via
// secureWipeSlice after the copy regardless of outcome.
func (s *SecureBuffer) ReadFrom(r io.Reader) (int64, error) {
	if s == nil {
		return 0, ErrDestroyed
	}
	// Determine buffer size under rLock (brief, non-blocking).
	s.mu.rLock()
	if s.data == nil {
		s.mu.rUnlock()
		return 0, ErrDestroyed
	}
	if s.sealed {
		s.mu.rUnlock()
		return 0, ErrSealed
	}
	size := len(s.data)
	s.mu.rUnlock()

	// Read into a temporary heap buffer without holding any lock. Deferred wipe
	// so the copy is erased on every outcome — including a panicking io.Reader.
	tmp := make([]byte, size)
	defer secureWipeSlice(tmp)
	n, err := io.ReadFull(r, tmp)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		// Reader had fewer bytes than buffer — partial fill is acceptable.
		err = nil
	}
	if err != nil {
		return int64(n), err
	}

	// Copy into secure memory under the exclusive lock.
	s.mu.lock()
	if s.data == nil {
		s.mu.unlock()
		return 0, ErrDestroyed
	}
	if s.sealed {
		s.mu.unlock()
		return 0, ErrSealed
	}
	copy(s.data, tmp[:n])
	s.mu.unlock()
	return int64(n), nil
}

// NewBufferFromReader allocates a SecureBuffer of size bytes and fills it from r.
// The returned buffer may be partially filled if r returns fewer than size bytes;
// the returned count reports how many bytes were read.
func NewBufferFromReader(r io.Reader, size int, opts ...Option) (*SecureBuffer, int64, error) {
	buf, err := NewEmptyBuffer(size, opts...)
	if err != nil {
		return nil, 0, err
	}
	n, err := buf.ReadFrom(r)
	if err != nil {
		_ = buf.Destroy()
		return nil, n, err
	}
	return buf, n, nil
}
