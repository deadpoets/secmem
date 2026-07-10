//go:build goexperiment.runtimesecret && linux && (amd64 || arm64)

// secretdo_runtimesecret.go is the primary-path SecretDo
// backed by runtime/secret (GOEXPERIMENT=runtimesecret, linux/amd64|arm64).
// The legacy best-effort equivalent lives in secretdo_legacy.go; the two files
// are mutually exclusive by build tag and export an identical API.

package secmem

import "runtime/secret"

// SecretDo runs fn with hardware-backed secret hygiene: the registers and stack
// used by fn's entire call tree are erased before SecretDo returns, and heap
// allocations made by fn are erased once the GC observes they are unreachable.
//
// Use it to wrap the "toxic-waste" trees that SecureBuffer cannot reach —
// decrypt (AEAD open), KDF derivation (Argon2/HKDF), and signing — so the
// transient key material, round-key residue, and scalar temporaries that land
// in CPU registers, stack spills, and intermediate heap are scrubbed rather
// than left for swap/core-dump/`/proc/<pid>/mem` to expose.
//
// Result survival: a value produced inside fn survives SecretDo only while it
// remains referenced after fn returns (e.g. assigned to a variable declared
// outside fn). Returned-and-retained values are therefore safe. For large or
// grown allocations, copy the result into a caller-allocated buffer to avoid
// the GC tracking/erase overhead described in runtime/secret.Do.
//
// Constraints (inherited from runtime/secret.Do): fn should be allocation-light
// and goroutine-free, and erasure does NOT extend to globals written by fn or
// to goroutines fn spawns. Panics from fn propagate (as if from SecretDo).
func SecretDo(fn func()) { secret.Do(fn) }

// SecretDoErr is [SecretDo] for a fn that returns an error. The returned error
// is referenced by the caller and so is not erased.
func SecretDoErr(fn func() error) error {
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
