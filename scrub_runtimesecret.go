//go:build goexperiment.runtimesecret && linux && (amd64 || arm64)

// scrub_runtimesecret.go is the primary-path Scrub, backed by runtime/secret
// (GOEXPERIMENT=runtimesecret, linux/amd64|arm64).
// The legacy best-effort equivalent lives in scrub_legacy.go; the two files
// are mutually exclusive by build tag and export an identical API.

package secmem

import "runtime/secret"

// Scrub runs fn with hardware-backed secret hygiene: the registers and stack
// used by fn's entire call tree are erased before Scrub returns, and heap
// allocations made by fn are erased once the GC observes they are unreachable.
//
// Use it to wrap the "toxic-waste" trees that SecureBuffer cannot reach —
// decrypt (AEAD open), KDF derivation (Argon2/HKDF), and signing — so the
// transient key material, round-key residue, and scalar temporaries that land
// in CPU registers, stack spills, and intermediate heap are scrubbed rather
// than left for swap/core-dump/`/proc/<pid>/mem` to expose.
//
// Result survival: a value produced inside fn survives Scrub only while it
// remains referenced after fn returns (e.g. assigned to a variable declared
// outside fn). Returned-and-retained values are therefore safe. For large or
// grown allocations, copy the result into a caller-allocated buffer to avoid
// the GC tracking/erase overhead described in runtime/secret.Do.
//
// Constraints (inherited from runtime/secret.Do): fn should be allocation-light
// and goroutine-free, and erasure does NOT extend to globals written by fn or
// to goroutines fn spawns. Panics from fn propagate (as if from Scrub).
//
// One constraint of Scrub's own: fn must leave runtime.LockOSThread balanced.
// Scrub pins the goroutine to its OS thread for the window and blocks the
// preemption and profiling signals on that thread; an UnlockOSThread inside fn
// that fn did not itself pair with a LockOSThread unpins the goroutine
// mid-window, and if it is rescheduled onto another thread before the mask is
// restored, the original thread keeps SIGURG and SIGPROF blocked for the rest of
// the process. Scrub detects the case it can observe (the goroutine has already
// moved) and panics rather than restore the wrong thread's mask; the leak itself
// is not repairable. See scrub_window_unix.go.
//
// Scrub(nil) is a no-op.
func Scrub(fn func()) {
	if fn == nil {
		return
	}
	// Even here, block the asynchronous register dump for the window:
	// runtime/secret erases registers and heap on the way OUT, but an
	// asyncPreempt landing mid-flight has already copied the live register file
	// onto the stack at an arbitrary instruction. Suppressing it removes that
	// copy rather than erasing after the fact.
	var window preemptWindow
	suppressAsyncPreempt(&window)
	defer window.restore()
	// Belt and braces: runtime/secret erases the register file on the way out
	// of Do, so on this path the vector clear is redundant. It stays so that
	// both Scrub implementations have the same shape and the same proof
	// (scrub_vecclear_test.go runs here too), and so the clear does not depend
	// on which registers a given runtime version's erasure happens to cover.
	defer clearVectorRegs()
	secret.Do(fn)
}

// ScrubErr is [Scrub] for a fn that returns an error. The returned error
// is referenced by the caller and so is not erased. ScrubErr(nil) is a no-op
// that returns nil.
func ScrubErr(fn func() error) error {
	if fn == nil {
		return nil
	}
	var window preemptWindow
	suppressAsyncPreempt(&window)
	defer window.restore()
	defer clearVectorRegs() // redundant under runtime/secret; see Scrub
	var err error
	secret.Do(func() { err = fn() })
	return err
}

// RuntimeSecretActive reports whether runtime/secret erasure is active in this
// process. This file compiles ONLY under the build tag
// `goexperiment.runtimesecret && linux && (amd64||arm64)` — the experiment is
// present and the platform supports it — so erasure IS active and this is
// unconditionally true.
//
// NOTE: do NOT implement this with runtime/secret.Enabled(). Enabled() reports
// whether Do appears on the CURRENT call stack (it is for assertions *inside* a
// Do closure); at startup — where AssertRuntimeSecret runs, outside any Do — it
// returns false and would fail-closed every correctly-built binary.
func RuntimeSecretActive() bool { return true }
