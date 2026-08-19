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
