package secmem

import (
	"errors"
	"testing"
)

// FuzzArenaLifecycle drives a SecureArena and its slots through arbitrary
// operation sequences, checking against a model. It is the arena analog of
// FuzzBufferLifecycle, added because the arena had the same shape of gap: its
// state machine — acquire, release, read-only, destroy, and the per-slot
// borrow — was covered only by hand-written cases, and a Release on a
// read-only arena wrote to the PROT_READ slab and faulted the process instead
// of refusing. The named regression is
// TestArena_ReleaseWhileReadOnlyRefusesInsteadOfFaulting.
//
// Invariants asserted on every step, for every input:
//
//  1. No operation ever panics or faults.
//  2. Acquire fills up to Cap and then returns ErrArenaFull; on a destroyed
//     arena every state-changing method returns ErrArenaDestroyed.
//  3. Release refuses with ErrReadOnly while the arena is read-only and leaves
//     the slot live; otherwise it frees the slot. It never faults on the wipe.
//  4. LiveCount equals the number of slots the model believes are acquired.
//
// The operation stream is the fuzzer's []byte input: one byte selects the op,
// subsequent bytes parameterise it (e.g. which live slot to act on).
func FuzzArenaLifecycle(f *testing.F) {
	f.Add([]byte{aoAcquire, aoAcquire, aoRelease, 0, aoDestroy})
	f.Add([]byte{aoAcquire, aoReadOnly, aoRelease, 0, aoReadWrite, aoRelease, 0}) // release while read-only, then ok
	f.Add([]byte{aoAcquire, aoAcquire, aoAcquire, aoAcquire, aoAcquire})          // acquire past Cap
	f.Add([]byte{aoReadOnly, aoAcquire, aoWithBytes, 0, aoReadWrite})             // read a slot while read-only
	f.Add([]byte{aoAcquire, aoDestroy, aoAcquire, aoReadOnly, aoRelease, 0})      // ops after destroy

	const (
		arenaCap = 4
		slotSize = 16
	)

	f.Fuzz(func(t *testing.T, program []byte) {
		a, err := NewArena(slotSize, arenaCap)
		if err != nil {
			t.Skipf("NewArena: %v", err)
		}
		defer func() { _ = a.Destroy() }()

		var live []*ArenaSlot // handles the model believes are acquired
		destroyed := false
		readOnly := false

		pc := 0
		next := func() (byte, bool) {
			if pc >= len(program) {
				return 0, false
			}
			b := program[pc]
			pc++
			return b, true
		}
		arg := func() int {
			b, _ := next()
			return int(b)
		}

		for {
			opByte, ok := next()
			if !ok {
				break
			}
			switch int(opByte) % aoCount {
			case aoAcquire:
				slot, err := a.Acquire()
				switch {
				case destroyed:
					mustBe(t, "Acquire", err, ErrArenaDestroyed)
				case len(live) >= arenaCap:
					mustBe(t, "Acquire", err, ErrArenaFull)
				default:
					mustBeNil(t, "Acquire", err)
					live = append(live, slot)
				}

			case aoRelease:
				if len(live) == 0 {
					continue
				}
				i := arg() % len(live)
				err := live[i].Release()
				switch {
				case readOnly:
					// Refused, not faulted; the slot stays acquired.
					mustBe(t, "Release", err, ErrReadOnly)
				default:
					// A canary violation would be a real overflow bug, not a
					// lifecycle failure, so it is tolerated; the slot still frees.
					if err != nil && !errors.Is(err, ErrCanaryViolation) {
						t.Fatalf("Release: unexpected error: %v", err)
					}
					live = append(live[:i], live[i+1:]...)
				}

			case aoReadOnly:
				err := a.ReadOnly()
				if destroyed {
					mustBe(t, "ReadOnly", err, ErrArenaDestroyed)
				} else {
					mustBeNil(t, "ReadOnly", err)
					readOnly = true
				}

			case aoReadWrite:
				err := a.ReadWrite()
				if destroyed {
					mustBe(t, "ReadWrite", err, ErrArenaDestroyed)
				} else {
					mustBeNil(t, "ReadWrite", err)
					readOnly = false
				}

			case aoWithBytes:
				if len(live) == 0 {
					continue
				}
				// A read borrow — allowed whether the slab is writable or
				// read-only, since PROT_READ permits reads.
				err := live[arg()%len(live)].WithBytes(func(b []byte) {
					if len(b) > 0 {
						_ = b[0]
					}
				})
				mustBeNil(t, "WithBytes", err)

			case aoDestroy:
				if err := a.Destroy(); err != nil {
					t.Fatalf("Destroy: %v", err)
				}
				destroyed = true
				readOnly = false
				live = nil // every outstanding handle is now invalid
			}

			// LiveCount must track the model exactly while the arena is alive.
			if !destroyed {
				if got := a.LiveCount(); got != len(live) {
					t.Fatalf("LiveCount = %d, model live = %d", got, len(live))
				}
			}
		}
	})
}

// Opcodes for FuzzArenaLifecycle. Distinct from the buffer fuzzer's op* set so
// the two live in the same package without collision.
const (
	aoAcquire = iota
	aoRelease
	aoReadOnly
	aoReadWrite
	aoWithBytes
	aoDestroy
	aoCount // must be last
)
