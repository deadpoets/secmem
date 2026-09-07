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
// (non-inlined) stack frame. Goroutines start on a small stack (2 KiB on
// Linux and macOS, 8 KiB on Windows; adaptive since Go 1.19), so on a
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
// # Vector registers
//
// On amd64 and arm64 the window also zeroes the vector register file — X0–X15
// at full YMM/ZMM width plus Z16–Z31 where AVX-512 is present, or V0–V31 — on
// the thread that ran fn, as the first thing that happens after fn returns.
// Vectorised crypto keeps its working state there and nothing in the Go
// runtime ever clears it. The Go ABI treats vector registers as caller-saved
// scratch, so the clear destroys nothing live, and because the ABI does not
// reload them around a call the clear really reaches what fn left; that is
// proven, not assumed, by scrub_vecclear_test.go, which is the empirical test
// the project requires of any register scrub. Reported as
// Capabilities.VectorRegisterClear. See vecclear_amd64.go.
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
//   - general-purpose registers: the ABI keeps live values in them across the
//     very call that would clear them, so no Go-level clear can be shown to
//     reach anything. Vector registers are cleared on amd64 and arm64 (above)
//     and on no other architecture.
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
// The window pins the goroutine to its OS thread with runtime.LockOSThread on
// every platform: on Linux because the signal mask is a property of the thread,
// and everywhere because the vector-register clear must run on the thread that
// holds the residue. fn must leave that pin balanced: a runtime.UnlockOSThread
// inside fn that fn did not itself pair with a LockOSThread unpins the goroutine
// mid-window, and if it is then rescheduled onto another thread before the mask
// is restored, the original thread keeps SIGURG and SIGPROF blocked for the
// rest of the process — unpreemptible and invisible to the CPU profiler, with
// nothing to say so. On Linux, Scrub detects the case it can observe (the
// goroutine has already moved) and panics rather than restore the wrong
// thread's mask; the leak itself is not repairable.
//
// Panics propagate; the registers are still cleared and the frame still
// scrubbed during unwind via the deferred calls. Scrub(nil) is a no-op.
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
	// Registered last so it runs FIRST on the way out, normal return or panic
	// unwind alike: the vector file is cleared on the thread that ran fn, before
	// the frame wipe and before the pin is released. Proven to reach fn's
	// residue by scrub_vecclear_test.go — the rule for any register scrub here.
	defer clearVectorRegs()
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
	defer clearVectorRegs() // first on the way out; see Scrub
	return fn()
}

// RuntimeSecretActive reports whether runtime/secret erasure is active. On the
// legacy path it is always false; [Scrub] uses best-effort frame scrubbing.
func RuntimeSecretActive() bool { return false }
