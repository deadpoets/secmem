//go:build !goexperiment.runtimesecret || !(linux && (amd64 || arm64))

// secretdo_legacy.go is the best-effort SecretDo for builds
// without GOEXPERIMENT=runtimesecret, or on platforms the experiment does not
// support (Windows, Darwin, non-amd64/arm64). It exports the same API as the
// primary path in secretdo_runtimesecret.go. See that file for the full
// SecretDo contract.

package secmem

// SecretDo runs fn, then scrubs a local stack frame via assembly (REP STOSB +
// SFENCE on amd64; a no-op on other arches). Unlike the runtime/secret-backed
// primary path, it cannot erase fn's full call-tree registers/heap — it scrubs
// only the immediate scratch frame where register spills typically land, which
// is the most that is safely reachable without runtime support.
//
// Panics propagate; the scratch frame is still scrubbed during unwind via the
// deferred wipe, matching the primary path's panic semantics.
func SecretDo(fn func()) {
	defer wipeScratchFrameFull()
	fn()
}

// SecretDoErr is [SecretDo] for a fn that returns an error.
func SecretDoErr(fn func() error) (err error) {
	defer wipeScratchFrameFull()
	return fn()
}

// RuntimeSecretActive reports whether runtime/secret erasure is active. On the
// legacy path it is always false; [SecretDo] uses best-effort frame scrubbing.
func RuntimeSecretActive() bool { return false }
