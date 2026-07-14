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
