package secmem

import (
	"crypto/subtle"
	"fmt"
)

// WithClosedAtRest makes a [SecureBuffer] inaccessible except while it is
// being used: its pages are no-access (PROT_NONE / PAGE_NOACCESS) at rest,
// opened for the duration of a borrowing callback or an access method, and
// closed again when the last concurrent one ends.
//
// What it buys is that nothing in the process can read or write the secret
// between uses, by accident or by a stray pointer: an out-of-bounds read
// elsewhere, and a slice wrongly kept from an earlier callback, fault instead
// of reaching it. That is the property [SecureBuffer.Seal] gives a dormant
// buffer, applied automatically around every use.
//
// It is opt-in and is not, and will not become, the default. What it costs is
// two page-protection system calls per use that finds the buffer closed
// (three on Windows, which has to lock the pages again), and the TLB
// shootdown that goes with them, which interrupts every core the process is
// running on. Measured, a borrow goes from about 13 ns to about 2 µs.
// Concurrent borrows share one open. That is nothing next to an RSA
// signature or a password hash, a few percent of an Ed25519 signature, and
// several times the cost of a short HMAC or a comparison. Use it for a
// long-lived, high-value key that is used at a low rate (a CA key, a master
// key), not for per-request or per-session keys.
//
// On Windows, prefer [SecureBuffer.Seal] for a dormant key. A no-access page
// there is not locked: VirtualLock does not survive PAGE_NOACCESS, so while a
// closed-at-rest buffer is closed its PLAINTEXT is in pageable memory and can
// be written to the pagefile. Seal encrypts the contents for that reason; this
// option does not, which makes it a trade on Windows (inaccessible between
// uses, but no longer locked) where on Linux and macOS, whose lock is
// unaffected, it only adds protection.
//
// The option applies to SecureBuffer constructors. [NewArena] refuses it: an
// arena's slots share pages, so one borrow would open all of them.
func WithClosedAtRest() Option {
	return func(c *config) { c.closedAtRest = true }
}

// restProtection is the page protection the buffer has when nobody is using
// it: none for a closed-at-rest buffer, read-only or read-write otherwise.
// Caller holds s.mu.
func (s *bufferState) restProtection() int {
	switch {
	case s.closedAtRest:
		return 0 /*PROT_NONE*/
	case s.readOnly:
		return 1 /*PROT_READ*/
	default:
		return 3 /*PROT_READ|PROT_WRITE*/
	}
}

// open makes a closed-at-rest buffer accessible for one use and counts the
// use; every successful open is paired with a close. A no-op for an ordinary
// buffer. The caller holds s.mu, shared or exclusive, and has already
// established that the buffer is live, not wiped and not sealed.
//
// Concurrent borrows hold the shared lock together, so the count has its own
// mutex: the first opener changes the protection, the rest find it open.
func (s *bufferState) open() error {
	if !s.closedAtRest {
		return nil
	}
	s.openMu.Lock()
	defer s.openMu.Unlock()
	if s.openers == 0 {
		prot := 3 /*PROT_READ|PROT_WRITE*/
		if s.readOnly {
			prot = 1 /*PROT_READ*/
		}
		if err := mprotectSecretMem(s.region, prot); err != nil {
			return fmt.Errorf("secmem: opening a closed-at-rest buffer: %w", err)
		}
		// Windows dropped the page lock when the page became no-access. Lock
		// again before anyone reads: if that is refused, close and fail
		// rather than hand out a secret in an unlocked page.
		if err := relockSecretMem(s.region); err != nil {
			_ = mprotectSecretMem(s.region, 0 /*PROT_NONE*/)
			return fmt.Errorf("secmem: opening a closed-at-rest buffer: restoring the page lock: %w", err)
		}
	}
	s.openers++
	return nil
}

// close ends one use, and makes the buffer inaccessible again when it was the
// last. It returns the protection call's error, which no real environment
// produces for a mapping the process owns; a buffer that could not be closed
// stays open, which is the state every ordinary buffer is always in.
func (s *bufferState) close() error {
	if !s.closedAtRest {
		return nil
	}
	s.openMu.Lock()
	defer s.openMu.Unlock()
	s.openers--
	if s.openers > 0 {
		return nil
	}
	if err := mprotectSecretMem(s.region, 0 /*PROT_NONE*/); err != nil {
		return fmt.Errorf("secmem: closing a closed-at-rest buffer: %w", err)
	}
	return nil
}

// borrowClosed is the borrow path of a closed-at-rest buffer: open, run the
// callback, close. Exactly one of fn and fnErr is set. It is a separate
// function so that an ordinary buffer's WithBytes carries none of it: the
// deferred close, which has to run when the callback panics too, is not free.
// The caller holds s.mu shared and has checked the buffer's state.
func (s *bufferState) borrowClosed(fn func([]byte), fnErr func([]byte) error) (retErr error) {
	if err := s.open(); err != nil {
		return err
	}
	// The close error is reported only if the callback had none.
	defer func() {
		if cerr := s.close(); retErr == nil {
			retErr = cerr
		}
	}()
	if fnErr != nil {
		return fnErr(s.data)
	}
	fn(s.data)
	return nil
}

// copyClosed and equalClosed are the closed-at-rest forms of the access
// methods that touch the region on a single line: open, do it, close. They
// are separate functions for the reason borrowClosed is, and for a second
// one: every extra return statement in a method that defers counts against
// the compiler's limit for open-coded defers, and going over it would slow
// those methods down for ordinary buffers. One of dst and src lies in the
// region. The caller holds s.mu and has checked the buffer's state and bounds.
func (s *bufferState) copyClosed(dst, src []byte) (int, error) {
	if err := s.open(); err != nil {
		return 0, err
	}
	n := copy(dst, src)
	return n, s.close()
}

func (s *bufferState) equalClosed(other []byte) (bool, error) {
	if err := s.open(); err != nil {
		return false, err
	}
	equal := subtle.ConstantTimeCompare(s.data, other) == 1
	return equal, s.close()
}

// store copies src into dst, which lies in the region, opening a closed-at-rest
// buffer around the copy. The mutating methods end in this one call rather
// than in a branch of their own: they already return once more than the
// readers do (ErrReadOnly), and one further return statement would put them
// over the open-coded-defer limit described above.
func (s *bufferState) store(dst, src []byte) (int, error) {
	if s.closedAtRest {
		return s.copyClosed(dst, src)
	}
	return copy(dst, src), nil
}
