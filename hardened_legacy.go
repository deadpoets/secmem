//go:build !goexperiment.runtimesecret || !(linux && (amd64 || arm64))

// Legacy hardening layer. Compiled when runtime/secret.Do is unavailable or
// when targeting a platform without full five-layer hardening (non-linux, or
// architectures other than amd64/arm64).
//
// DO NOT REMOVE — required for Windows and Darwin targets.
//
// GOEXPERIMENT=runtimesecret compiles on Windows but secret.Do is a no-op
// there (no kernel support). Without this legacy layer, Windows and Darwin
// builds would have ZERO memory-safety hardening beyond basic heap zeroing.
// This file provides the best-effort stack/frame scrubbing that those
// platforms rely on.
//
// On GOEXPERIMENT=runtimesecret + linux/amd64|arm64 (the primary path), this
// entire file is excluded by the build tag. runtime/secret.Do handles CPU
// register and stack frame scrubbing at the hardware level.
//
// Otherwise, this layer provides:
//   - WipeBytes / WipeArray: REP STOSB + SFENCE (amd64) or subtle.ConstantTimeSelect
//   - SecureContext: local frame wipe (wipeScratchFrame assembly) + recover isolation
//     No below-SP writes — Go goroutine guard pages make those unsafe.
//     See hardened_legacy_amd64.s for details.
//   - WithBytesHardened / WithBytesHardenedErr: drop-in wrappers that add
//     wipeScratchFrame around SecureBuffer.WithBytes / WithBytesErr

package secmem

import (
	"fmt"
	"runtime/debug"
)

// WipeBytes zeros b using the hardened wipe path for this platform.
//
// On amd64: REP STOSB + SFENCE — hardware-accelerated, compiler-defeat-resistant.
// On other platforms: constant-time loop via crypto/subtle.
//
// WipeBytes is intended for in-process (non-mmap) memory: Go stack buffers,
// heap allocations, etc. For mmap'd SecureBuffer memory, Destroy() applies the
// full architectural wipe (LFENCE + REP STOSB + SFENCE + CLFLUSH[OPT] loop).
func WipeBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	wipeBytes(b)
}

// WipeArray zeros b. It is an alias for WipeBytes for array-backed slices.
func WipeArray(b []byte) { WipeBytes(b) }

// PanicError is returned by SecureContext.DoErr (or re-panicked by Do) when the
// callback panics. The stack is always scrubbed before the error is surfaced.
type PanicError struct {
	Value any    // the recovered panic value
	Stack []byte // runtime/debug.Stack() captured after recovery
}

// Error implements the error interface.
func (e *PanicError) Error() string {
	return fmt.Sprintf("SecureContext panic: %v", e.Value)
}

// SecureContext provides best-effort stack scrubbing for legacy-path code —
// platforms or build configurations without GOEXPERIMENT=runtimesecret.
//
// On amd64 it zeroes a 2 KiB local frame via wipeScratchFrame
// (REP STOSB + SFENCE) after the callback returns, approximating what
// runtime/secret.Do does at the CPU level.
// On non-amd64 platforms, wipeScratchFrame is a no-op; the value of
// SecureContext is then limited to the recover() wrapper.
//
// For the primary path (linux/amd64|arm64 + GOEXPERIMENT=runtimesecret) this
// type is not compiled; callers should use secret.Do(func() { buf.WithBytesErr(...) }).
//
//	sc := secmem.NewSecureContext()
//	defer sc.Close() // full 32 KiB scrub on scope exit
//
//	err := sc.DoErr(func() error {
//	    return buf.WithBytesErr(processSecret)
//	})
type SecureContext struct{}

// NewSecureContext returns a new SecureContext.
// The zero value is usable; this constructor aids readability.
func NewSecureContext() *SecureContext { return &SecureContext{} }

// Do calls fn, then zeroes a 2 KiB local frame via assembly.
// If fn panics, the scratch frame is still zeroed; the panic is re-raised
// wrapped as *PanicError to preserve the panic value and a stack trace.
//
// On amd64: uses REP STOSB + SFENCE (wipeScratchFrame). Go grows the goroutine
// stack if needed — the wipe covers the freshly-allocated frame which is
// contiguous with (and may overlap) fn's callee frames.
// On other platforms: wipeScratchFrame is a no-op.
func (c *SecureContext) Do(fn func()) {
	defer func() {
		r := recover()
		wipeScratchFrame()
		if r != nil {
			panic(&PanicError{Value: r, Stack: debug.Stack()})
		}
	}()
	fn()
}

// DoErr calls fn, then zeroes a 2 KiB local frame.
// If fn panics, the scratch frame is still zeroed and a *PanicError is returned.
func (c *SecureContext) DoErr(fn func() error) (retErr error) {
	defer func() {
		r := recover()
		wipeScratchFrame()
		if r != nil {
			retErr = &PanicError{Value: r, Stack: debug.Stack()}
		}
	}()
	return fn()
}

// Close zeroes a 32 KiB local frame via assembly.
// Intended to be deferred immediately after NewSecureContext to maximize
// coverage of register spills and callee frame data.
func (c *SecureContext) Close() {
	wipeScratchFrameFull()
}

// WithBytesHardened calls buf.WithBytes(fn) inside a SecureContext scrub scope.
//
// Two scrubs are applied:
//  1. Light (2 KiB): inside DoErr immediately after fn returns.
//  2. Full (32 KiB): via deferred sc.Close() when WithBytesHardened returns.
//
// This is the legacy-platform equivalent of:
//
//	secret.Do(func() { buf.WithBytes(fn) })
func WithBytesHardened(buf *SecureBuffer, fn func([]byte)) error {
	sc := NewSecureContext()
	defer sc.Close()
	return sc.DoErr(func() error {
		return buf.WithBytes(fn)
	})
}

// WithBytesHardenedErr calls buf.WithBytesErr(fn) inside a SecureContext scrub scope.
//
// Two scrubs are applied (see WithBytesHardened for details).
//
// This is the legacy-platform equivalent of:
//
//	secret.Do(func() { _ = buf.WithBytesErr(fn) })
func WithBytesHardenedErr(buf *SecureBuffer, fn func([]byte) error) error {
	sc := NewSecureContext()
	defer sc.Close()
	return sc.DoErr(func() error {
		return buf.WithBytesErr(fn)
	})
}
