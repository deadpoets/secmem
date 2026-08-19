//go:build !goexperiment.runtimesecret || !(linux && (amd64 || arm64))

// scrub_legacy.go is the best-effort Scrub for builds without
// GOEXPERIMENT=runtimesecret, or on platforms the experiment does not support
// (Windows, Darwin, non-amd64/arm64). It exports the same API as the primary
// path in scrub_runtimesecret.go.

package secmem

// Scrub runs fn and then best-effort scrubs the stack region fn used.
//
// On linux/amd64 and linux/arm64 built with GOEXPERIMENT=runtimesecret, Scrub
// is backed by runtime/secret and erases the registers, stack, and heap of fn's
// entire call tree with runtime cooperation. This file is the fallback used on
// every other build; it cannot match that, and scrubs only fn's stack frame via
// assembly — REP STOSB + SFENCE on amd64, and a real store loop on arm64 since
// scrubframe_arm64.s landed, so "a no-op on other architectures" now means
// every architecture except those two.
//
// # Why the wipe runs twice
//
// wipeScratchFrameFull zeroes a 32 KiB region by allocating it as its own
// (non-inlined) stack frame. Goroutines start with an 8 KiB stack, so on a
// shallow call that allocation triggers a stack copy (morestack): a single
// deferred wipe would then run on the RELOCATED stack, zeroing the fresh copy
// while fn's real residue sits on the old segment the runtime just freed —
// untouched. Calling the wipe once on entry forces any growth to happen BEFORE
// fn writes a secret and pre-cleans the band; the deferred call is then
// guaranteed to run in place.
//
// The entry wipe orders that growth, it does not make it free. morestack copies
// the WHOLE stack, so the abandoned segment holds a copy of the caller's stack
// as it was on entry — and an earlier version of this comment claimed nothing
// sensitive was on it. That holds only if the caller had nothing sensitive
// there, which is not the situation this package exists for: a key in a local,
// or residue from an earlier operation, is copied to the new segment and left
// behind on the old one, which returns to the stack pool unwiped. Scrub cannot
// reach it, because the runtime owns the abandoned segment and does not name it.
//
// # Best-effort limits (stated honestly)
//
// Even with headroom reserved, this scrubs only the 32 KiB band below fn's
// return point, and only stack memory. It does NOT cover:
//   - a call tree deeper than 32 KiB (the tail survives);
//   - a stack relocation triggered inside fn if fn exceeds the reserved band;
//   - a GC stack-shrink that frees fn's segment before the wipe (asynchronous,
//     runtime-owned, and unreachable from Go);
//   - the stack segment abandoned by the entry wipe's own growth, which carries
//     a copy of whatever the CALLER already had on its stack (see above);
//   - CPU or vector registers.
//
// None of these are fixable in pure Go without runtime support — the
// runtime/secret path handles them, which is why it is the primary path. Keep
// fn shallow and keep secrets in a SecureBuffer so there is little residue to
// miss.
//
// # Asynchronous preemption
//
// On Linux the window additionally blocks SIGURG for its duration, which stops
// runtime.asyncPreempt spilling the whole register file onto the stack at an
// arbitrary instruction — the one residue source a frame wipe cannot predict.
// See scrub_window_unix.go for why that does not stall the collector, and for
// the one shape of fn that would. Elsewhere it is unsupported and reported as
// such by Capabilities.AsyncPreemptSuppressed.
//
// Panics propagate; the frame is still scrubbed during unwind via the deferred
// wipe. Scrub(nil) is a no-op.
func Scrub(fn func()) {
	if fn == nil {
		return
	}
	// Close the asynchronous register-dump window first: runtime.asyncPreempt
	// spills the ENTIRE register file to this goroutine's stack at an arbitrary
	// instruction, which no frame wipe can anticipate. Linux only; elsewhere
	// this reports unsupported and the window runs with the frame scrub alone.
	// Ordered before the reserve so no preemption can land between them.
	var window preemptWindow
	suppressAsyncPreempt(&window)
	defer window.restore()

	wipeScratchFrameFull()       // reserve headroom + pre-clean, before secrets exist
	defer wipeScratchFrameFull() // now guaranteed to wipe in place
	// TODO(secmem): a register/vector scrub here could cover residue the frame
	// wipe misses, but only if proven to actually reach it — the Go ABI reloads
	// registers around this call. Do not add it without an empirical test; see
	// the deleted 2 KiB wipe for why an unverified scrub is worse than none.
	fn()
}

// ScrubErr is [Scrub] for a fn that returns an error. ScrubErr(nil) is
// a no-op that returns nil.
func ScrubErr(fn func() error) (err error) {
	if fn == nil {
		return nil
	}
	var window preemptWindow
	suppressAsyncPreempt(&window)
	defer window.restore()

	wipeScratchFrameFull()
	defer wipeScratchFrameFull()
	return fn()
}

// RuntimeSecretActive reports whether runtime/secret erasure is active. On the
// legacy path it is always false; [Scrub] uses best-effort frame scrubbing.
func RuntimeSecretActive() bool { return false }
