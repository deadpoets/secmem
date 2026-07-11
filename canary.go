// canary.go implements the overflow canary: the page-rounded slack between a
// buffer's usable bytes and its mapping boundary (and the inter-slot strips
// of a SecureArena) is filled with a random pattern that is verified before
// the memory is wiped. An overflow that stays INSIDE the mapping — too short
// to reach the guard page — corrupts the pattern and is reported as
// ErrCanaryViolation instead of passing silently.
//
// HONESTY: the canary is a memory-safety bug-catcher, NOT a confidentiality
// control. It detects accidental overwrites by the process itself; it does
// nothing against an attacker who can read process memory (that is
// memfd_secret's job), and an in-process attacker who can read the pattern
// can forge it. The pattern is process-global, generated once from
// crypto/rand — the same design as OpenBSD malloc and glibc stack canaries.

package secmem

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"sync"
)

// canaryLen is the length of the repeating canary pattern. 16 bytes makes an
// accidental match of an overwritten strip 2^-128 per block — negligible —
// while keeping arena inter-slot strips cheap.
const canaryLen = 16

var (
	canaryOnce    sync.Once
	canaryPattern [canaryLen]byte
	canaryInitErr error
)

// canaryInit generates the process-global pattern on first use. A crypto/rand
// failure is returned (and allocation fails closed) rather than falling back
// to a predictable pattern: a canary that can be guessed by accident is a
// canary that lies.
func canaryInit() error {
	canaryOnce.Do(func() {
		if _, err := rand.Read(canaryPattern[:]); err != nil {
			canaryInitErr = fmt.Errorf("secmem: canary init: %w", err)
		}
	})
	return canaryInitErr
}

// fillCanary writes the repeating pattern over b (the slack or strip to arm).
// An empty b is a no-op.
func fillCanary(b []byte) error {
	if err := canaryInit(); err != nil {
		return err
	}
	for i := range b {
		b[i] = canaryPattern[i%canaryLen]
	}
	return nil
}

// canaryIntact reports whether b still holds the exact pattern fillCanary
// wrote. The comparison is constant-time in len(b) — it does not short-circuit
// at the first mismatch, so the check's timing reveals nothing about where a
// corruption sits. An empty b is vacuously intact. If the canary was never
// initialized (allocation would have failed), b cannot have been filled and
// the answer is false.
func canaryIntact(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if canaryInit() != nil {
		return false
	}
	acc := byte(0)
	for i := range b {
		acc |= b[i] ^ canaryPattern[i%canaryLen]
	}
	return subtle.ConstantTimeByteEq(acc, 0) == 1
}
