//go:build !goexperiment.runtimesecret || !(linux && (amd64 || arm64))

// secretdo_legacy.go is the best-effort SecretDo for builds without
// GOEXPERIMENT=runtimesecret, or on platforms the experiment does not support
// (Windows, Darwin, non-amd64/arm64). It exports the same API as the primary
// path in secretdo_runtimesecret.go.

package secmem

// SecretDo runs fn and then best-effort scrubs the stack region fn used.
//
// On linux/amd64 and linux/arm64 built with GOEXPERIMENT=runtimesecret, SecretDo
// is backed by runtime/secret and erases the registers, stack, and heap of fn's
// entire call tree with runtime cooperation. This file is the fallback used on
// every other build; it cannot match that, and scrubs only fn's stack frame via
// assembly (REP STOSB + SFENCE on amd64; a no-op on other architectures).
//
// # Why the wipe runs twice
//
// wipeScratchFrameFull zeroes a 32 KiB region by allocating it as its own
// (non-inlined) stack frame. Goroutines start with an 8 KiB stack, so on a
// shallow call that allocation triggers a stack copy (morestack): a single
// deferred wipe would then run on the RELOCATED stack, zeroing the fresh copy
// while fn's real residue sits on the old segment the runtime just freed —
// untouched. Calling the wipe once on entry forces any growth to happen BEFORE
// fn writes a secret (nothing sensitive is on the abandoned copy) and pre-cleans
// the band; the deferred call is then guaranteed to run in place.
//
// # Best-effort limits (stated honestly)
//
// Even with headroom reserved, this scrubs only the 32 KiB band below fn's
// return point, and only stack memory. It does NOT cover:
//   - a call tree deeper than 32 KiB (the tail survives);
//   - a stack relocation triggered inside fn if fn exceeds the reserved band;
//   - a GC stack-shrink that frees fn's segment before the wipe (asynchronous,
//     runtime-owned, and unreachable from Go);
//   - CPU or vector registers.
//
// None of these are fixable in pure Go without runtime support — the
// runtime/secret path handles them, which is why it is the primary path. Keep
// fn shallow and keep secrets in a SecureBuffer so there is little residue to
// miss.
//
// Panics propagate; the frame is still scrubbed during unwind via the deferred
// wipe. SecretDo(nil) is a no-op.
func SecretDo(fn func()) {
	if fn == nil {
		return
	}
	wipeScratchFrameFull()       // reserve headroom + pre-clean, before secrets exist
	defer wipeScratchFrameFull() // now guaranteed to wipe in place
	// TODO(secmem): a register/vector scrub here could cover residue the frame
	// wipe misses, but only if proven to actually reach it — the Go ABI reloads
	// registers around this call. Do not add it without an empirical test; see
	// the deleted 2 KiB wipe for why an unverified scrub is worse than none.
	fn()
}

// SecretDoErr is [SecretDo] for a fn that returns an error. SecretDoErr(nil) is
// a no-op that returns nil.
func SecretDoErr(fn func() error) (err error) {
	if fn == nil {
		return nil
	}
	wipeScratchFrameFull()
	defer wipeScratchFrameFull()
	return fn()
}

// RuntimeSecretActive reports whether runtime/secret erasure is active. On the
// legacy path it is always false; [SecretDo] uses best-effort frame scrubbing.
func RuntimeSecretActive() bool { return false }
