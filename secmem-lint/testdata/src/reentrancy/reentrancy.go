package reentrancy

import "github.com/deadpoets/secmem"

func sameBufferMethod(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		_ = b
		buf.ExposeString() // want `secmem-lint: ExposeString called on the same buffer`
	})
}

func sameBufferNested(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		_ = b
		_ = buf.WithBytesErr(func(c []byte) error { // want `secmem-lint: WithBytesErr called on the same buffer`
			return nil
		})
	})
}

// differentBufferOK is the documented decrypt-into pattern: nesting access to a
// DIFFERENT buffer is legal and must not be flagged.
func differentBufferOK(key, out *secmem.SecureBuffer) {
	_ = key.WithBytesErr(func(k []byte) error {
		_ = k
		return out.WithBytesErr(func(o []byte) error {
			_ = o
			return nil
		})
	})
}

// sameBufferLockingInspectors covers the members added after the review: the
// exclusive-lock mutator and the rLock inspectors. SetByteAt self-deadlocks
// outright; the inspectors deadlock as soon as a writer queues between the two
// read acquires, because the lock is writer-preferring.
func sameBufferLockingInspectors(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		_ = b
		_ = buf.SetByteAt(0, 1) // want `secmem-lint: SetByteAt called on the same buffer`
		_ = buf.Len()           // want `secmem-lint: Len called on the same buffer`
		_ = buf.MappedLen()     // want `secmem-lint: MappedLen called on the same buffer`
		_ = buf.IsSealed()      // want `secmem-lint: IsSealed called on the same buffer`
		_ = buf.IsDestroyed()   // want `secmem-lint: IsDestroyed called on the same buffer`
	})
}

// vault holds its buffer in a struct field, which is how any program larger
// than an example holds it. The check used to require a plain identifier on
// both ends, so every one of these was silently clean.
type vault struct {
	buf   *secmem.SecureBuffer
	inner struct{ buf *secmem.SecureBuffer }
}

func (v *vault) fieldReceiver() {
	_ = v.buf.WithBytes(func(b []byte) {
		_ = b
		_ = v.buf.Len() // want `secmem-lint: Len called on the same buffer`
	})
}

func (v *vault) nestedFieldReceiver() {
	_ = v.inner.buf.WithBytes(func(b []byte) {
		_ = b
		_ = v.inner.buf.IsSealed() // want `secmem-lint: IsSealed called on the same buffer`
	})
}

// differentFieldOK: a different field is a different buffer, so the
// decrypt-into pattern still has to survive the wider receiver matching.
func (v *vault) differentFieldOK() {
	_ = v.buf.WithBytes(func(b []byte) {
		_ = b
		_ = v.inner.buf.Len()
	})
}

// indexedReceiverNotDecidable: bufs[i] and bufs[j] are written alike and need
// not be the same buffer, so receivers that are index expressions are left
// alone rather than guessed at.
func indexedReceiverNotDecidable(bufs []*secmem.SecureBuffer) {
	_ = bufs[0].WithBytes(func(b []byte) {
		_ = b
		_ = bufs[1].Len()
	})
}
