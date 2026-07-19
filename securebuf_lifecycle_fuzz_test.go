package secmem

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzBufferLifecycle drives a SecureBuffer through an arbitrary sequence of
// operations and checks it against a model of what its state should be. It
// closes the coverage gap the crypto and redaction fuzzers leave open: the
// core buffer STATE MACHINE — the interaction of destroy, seal, read-only,
// truncate, and the access methods — where a use-after-destroy, a sealed-window
// disclosure, or a protected-page write fault would live if one existed.
//
// It exists because it found real bugs: a mutating method called after
// ReadOnly() wrote to the PROT_READ page and crashed the process with SIGSEGV
// instead of returning an error. The named regressions are in
// securebuf_readonly_test.go.
//
// The fuzzer asserts these invariants, on every operation, for every input:
//
//  1. No operation ever panics or faults. Misuse returns an error; it never
//     crashes — the whole reason ReadFrom is in the opcode set (it mutates the
//     buffer, and the original harness omitted it, so the read-only fault it
//     also had went uncaught).
//  2. Access is refused whenever the model says the buffer is unusable —
//     destroyed always, sealed for the access/mutate methods, read-only for the
//     mutators — and the refusal unwraps to the right sentinel (ErrDestroyed /
//     ErrSealed / ErrReadOnly).
//  3. A destroyed buffer STAYS destroyed: no sequence of later operations
//     resurrects it into a readable state. This is the use-after-destroy guard,
//     checked structurally rather than by a single hand-written case.
//  4. Reported length never exceeds the live capacity, and equals the model
//     length whenever the buffer is readable.
//
// The operation stream is the fuzzer's []byte input: one byte selects the op,
// subsequent bytes parameterise it. Any input the corpus accumulates is
// therefore a reproducible sequence of API calls.
func FuzzBufferLifecycle(f *testing.F) {
	// Seeds: short programs that exercise the interesting transitions. Each
	// byte is an opcode (see the const block); trailing bytes are arguments.
	f.Add([]byte{opCopyIn, 4, 0xAA, opCopyOut, 4, opDestroy, opCopyOut, 4})            // read after destroy
	f.Add([]byte{opSeal, opCopyIn, 2, 0xBB, opUnseal, opCopyIn, 2, 0xCC})              // mutate while sealed, then ok
	f.Add([]byte{opSeal, opDestroy})                                                   // destroy a sealed buffer
	f.Add([]byte{opTruncate, 2, opByteAt, 3, opSetByteAt, 1, 0x11})                    // access past a truncated tail
	f.Add([]byte{opReadOnly, opSetByteAt, 0, 0x22, opReadWrite, opSetByteAt, 0, 0x33}) // write while read-only, then ok
	f.Add([]byte{opReadOnly, opReadFrom, 4, opReadWrite, opReadFrom, 4})               // ReadFrom while read-only, then ok
	f.Add([]byte{opReadOnly, opSeal, opUnseal, opSetByteAt, 0, 0x44})                  // read-only survives a seal cycle
	f.Add([]byte{opSeal, opSeal, opUnseal, opUnseal, opDestroy, opDestroy})            // idempotency of every terminal op
	f.Add([]byte{opConstEqual, 4, opWriteTo, opExpose})

	const bufSize = 16

	f.Fuzz(func(t *testing.T, program []byte) {
		buf, err := NewEmptyBuffer(bufSize)
		if err != nil {
			// Unsupported platform / fallback refused: nothing to fuzz.
			t.Skipf("NewEmptyBuffer: %v", err)
		}
		// The program may or may not destroy the buffer; Destroy is idempotent,
		// so an unconditional cleanup is always safe.
		defer func() { _ = buf.Destroy() }()

		m := &model{length: bufSize, capacity: bufSize}

		pc := 0
		next := func() (byte, bool) {
			if pc >= len(program) {
				return 0, false
			}
			b := program[pc]
			pc++
			return b, true
		}

		for {
			opByte, ok := next()
			if !ok {
				break
			}
			step(t, buf, m, opByte, next)
			// Cross-cutting invariant, checked after every step: the buffer's
			// live/destroyed state must track the model exactly.
			switch {
			case m.destroyed && !buf.IsDestroyed():
				t.Fatal("buffer reports live after model marked it destroyed")
			case !m.destroyed && buf.IsDestroyed():
				t.Fatal("buffer reports destroyed while model says live")
			}
		}
	})
}

// model is the oracle: what the buffer's observable state should be.
type model struct {
	length    int
	capacity  int
	destroyed bool
	sealed    bool
	readOnly  bool
}

// Opcodes. Kept dense and small so short fuzzer inputs reach deep states.
const (
	opCopyIn = iota
	opCopyOut
	opByteAt
	opSetByteAt
	opTruncate
	opSeal
	opUnseal
	opReadOnly
	opReadWrite
	opConstEqual
	opWriteTo
	opReadFrom
	opExpose
	opDestroy
	opCount // must be last
)

func step(t *testing.T, buf *SecureBuffer, m *model, opByte byte, next func() (byte, bool)) {
	t.Helper()
	arg := func() int {
		b, _ := next() // a missing arg reads as 0 — still a valid, bounds-checked call
		return int(b)
	}

	switch int(opByte) % opCount {
	case opCopyIn:
		src := make([]byte, arg()%(m.capacity+2)) // sometimes oversized on purpose
		_, err := buf.CopyIn(src, 0)
		checkMutate(t, "CopyIn", m, err)

	case opCopyOut:
		dst := make([]byte, arg()%(m.capacity+2))
		_, err := buf.CopyOut(dst, 0)
		checkRead(t, "CopyOut", m, err)

	case opByteAt:
		_, err := buf.ByteAt(arg() % (m.capacity + 2))
		// A read: the destroyed/sealed refusals must hold; an in-range index
		// past the current length is a legitimate value error.
		checkRead(t, "ByteAt", m, err)

	case opSetByteAt:
		i := arg()
		v, _ := next()
		err := buf.SetByteAt(i%(m.capacity+2), v)
		checkMutate(t, "SetByteAt", m, err)

	case opTruncate:
		n := arg() % (m.capacity + 2)
		err := buf.Truncate(n)
		switch {
		case m.destroyed:
			mustBe(t, "Truncate", err, ErrDestroyed)
		case m.sealed:
			mustBe(t, "Truncate", err, ErrSealed)
		case m.readOnly:
			mustBe(t, "Truncate", err, ErrReadOnly)
		case n <= m.length:
			mustBeNil(t, "Truncate", err)
			m.length = n
		default:
			// n > length: out-of-range, must error, length unchanged.
			if err == nil {
				t.Fatalf("Truncate(%d) on length %d returned nil", n, m.length)
			}
		}

	case opSeal:
		err := buf.Seal()
		if m.destroyed {
			mustBe(t, "Seal", err, ErrDestroyed)
		} else {
			mustBeNil(t, "Seal", err) // idempotent when already sealed; works while read-only
			m.sealed = true
		}

	case opUnseal:
		err := buf.Unseal()
		if m.destroyed {
			mustBe(t, "Unseal", err, ErrDestroyed)
		} else {
			mustBeNil(t, "Unseal", err) // read-only, if set, is preserved across the cycle
			m.sealed = false
		}

	case opReadOnly:
		err := buf.ReadOnly()
		switch {
		case m.destroyed:
			mustBe(t, "ReadOnly", err, ErrDestroyed)
		case m.sealed:
			mustBe(t, "ReadOnly", err, ErrSealed)
		default:
			mustBeNil(t, "ReadOnly", err)
			m.readOnly = true
		}

	case opReadWrite:
		err := buf.ReadWrite()
		switch {
		case m.destroyed:
			mustBe(t, "ReadWrite", err, ErrDestroyed)
		case m.sealed:
			mustBe(t, "ReadWrite", err, ErrSealed)
		default:
			mustBeNil(t, "ReadWrite", err)
			m.readOnly = false
		}

	case opConstEqual:
		other := make([]byte, arg()%(m.capacity+2))
		_, err := buf.ConstantTimeEqual(other)
		checkRead(t, "ConstantTimeEqual", m, err)

	case opWriteTo:
		_, err := buf.WriteTo(discardWriter{})
		checkRead(t, "WriteTo", m, err)

	case opReadFrom:
		src := make([]byte, arg()%(m.capacity+2))
		_, err := buf.ReadFrom(bytes.NewReader(src))
		// ReadFrom mutates the buffer, so it carries the mutator contract — the
		// read-only case is exactly the fault the opcode set originally missed.
		checkMutate(t, "ReadFrom", m, err)

	case opExpose:
		_, err := buf.ExposeString()
		checkRead(t, "ExposeString", m, err)

	case opDestroy:
		err := buf.Destroy()
		// Destroy is total and idempotent: it succeeds on a live buffer and is a
		// no-op on an already-destroyed one. A canary violation is a legitimate
		// non-nil result (a real overflow bug would trip it) and is not a
		// lifecycle failure, so it is tolerated here.
		if err != nil && !errors.Is(err, ErrCanaryViolation) {
			t.Fatalf("Destroy returned unexpected error: %v", err)
		}
		m.destroyed = true
	}

	// Length invariant, checked whenever the buffer should be readable.
	if !m.destroyed && !m.sealed {
		if got := buf.Len(); got != m.length {
			t.Fatalf("Len() = %d, model length = %d", got, m.length)
		}
	}
}

// checkRead asserts the refusal contract for a reading method: destroyed →
// ErrDestroyed, sealed → ErrSealed. A read on a read-only buffer is allowed
// (PROT_READ permits reads). Value errors (bad offset/index) are permitted when
// the buffer is otherwise usable, so this only forces the refusals.
func checkRead(t *testing.T, op string, m *model, err error) {
	t.Helper()
	switch {
	case m.destroyed:
		mustBe(t, op, err, ErrDestroyed)
	case m.sealed:
		mustBe(t, op, err, ErrSealed)
	}
}

// checkMutate asserts the refusal contract for a mutating method, including the
// read-only guard the fuzzer originally exposed as a SIGSEGV: destroyed →
// ErrDestroyed, sealed → ErrSealed, read-only → ErrReadOnly. In every blocked
// state a mutator MUST refuse — never fault, never silently write.
func checkMutate(t *testing.T, op string, m *model, err error) {
	t.Helper()
	switch {
	case m.destroyed:
		mustBe(t, op, err, ErrDestroyed)
	case m.sealed:
		mustBe(t, op, err, ErrSealed)
	case m.readOnly:
		mustBe(t, op, err, ErrReadOnly)
	}
}

func mustBe(t *testing.T, op string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: error = %v, want %v", op, err, want)
	}
}

func mustBeNil(t *testing.T, op string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", op, err)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
