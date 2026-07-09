// Package security — securebuf_scope.go provides deterministic lifetime
// management for SecureBuffer via Scope and ScopeWith.
//
// # Design Decision
//
// Scope and ScopeWith are unconditionally available (no build tags) because
// deterministic lifetime management is valuable regardless of whether
// runtime/secret is active. They work with any SecureBuffer constructor.
//
// Destroy() errors are propagated via named return + errors.Join, not discarded.
// A failed Munmap means secret memory is still mapped — callers can detect this
// and react (e.g., trigger a security alert, terminate an SSH connection).
package secmem

import "errors"

// Scope creates a zero-filled SecureBuffer of the given size, calls fn,
// then destroys the buffer deterministically.
//
// Destroy() errors are joined to fn's return value via errors.Join:
//
//   - fn error only → returned as-is
//   - Destroy error only → returned as-is
//   - Both errors → errors.Join(fn error, Destroy error)
//
// This ensures that a failed Munmap is never silently discarded.
func Scope(size int, fn func(*SecureBuffer) error) (retErr error) {
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		return err
	}
	defer func() {
		if dErr := buf.Destroy(); dErr != nil {
			retErr = errors.Join(retErr, dErr)
		}
	}()
	retErr = fn(buf)
	return retErr
}

// ScopeWith creates a SecureBuffer using the provided constructor, calls fn,
// then destroys the buffer deterministically.
//
// If ctor returns an error, fn is not called and the error is returned.
// Destroy() errors are joined to fn's return value (same semantics as Scope).
//
// Example:
//
//	err := security.ScopeWith(
//	    func() (*security.SecureBuffer, error) {
//	        return security.NewSyscallSafeBuffer(rawKey)
//	    },
//	    func(buf *security.SecureBuffer) error {
//	        return buf.WithBytesErr(func(key []byte) error {
//	            block, err := aes.NewCipher(key)
//	            if err != nil { return err }
//	            block.Encrypt(dst, src)
//	            return nil
//	        })
//	    },
//	)
func ScopeWith(ctor func() (*SecureBuffer, error), fn func(*SecureBuffer) error) (retErr error) {
	buf, err := ctor()
	if err != nil {
		return err
	}
	defer func() {
		if dErr := buf.Destroy(); dErr != nil {
			retErr = errors.Join(retErr, dErr)
		}
	}()
	retErr = fn(buf)
	return retErr
}
