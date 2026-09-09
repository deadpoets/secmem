// Package idioms holds the documented, recommended patterns. Nothing in this
// file may produce a finding: each was a false positive of an earlier version
// of the analyzer.
package idioms

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/deadpoets/secmem"
)

var (
	later func()
	sinkS string
)

// decryptInto: copying from one borrowed slice into another borrowed slice is
// the documented way to move a secret between buffers — whichever way round
// the two borrows nest.
func decryptInto(key, out *secmem.SecureBuffer) error {
	return key.WithBytesErr(func(k []byte) error {
		return out.WithBytesErr(func(o []byte) error {
			copy(o, k)
			return nil
		})
	})
}

func decryptIntoReversed(key, out *secmem.SecureBuffer) error {
	return out.WithBytesErr(func(o []byte) error {
		return key.WithBytesErr(func(k []byte) error {
			copy(o, k)
			o = append(o[:0], k...)
			return nil
		})
	})
}

func stackArray(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		var a [32]byte
		copy(a[:], b)
		a[0] = b[0]
		_ = a
	})
}

func wipedScratch(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		t := make([]byte, len(b))
		defer secmem.SecureWipe(t)
		copy(t, b)
		t = append(t, b...)
		u := append([]byte(nil), b...)
		_ = u
		var grown []byte
		grown = append(grown, b...)
		_ = grown
	})
}

func inPlace(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		copy(b[8:], b[:8]) // writing into the borrowed slice itself
		b[0] ^= b[1]
		half := b[:len(b)/2]
		copy(half, b[len(b)/2:])
		for i := range b {
			b[i] = 0
		}
	})
}

type record struct{ tag [4]byte }

func localAggregates(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		var r record
		copy(r.tag[:], b)
		p := &r
		p.tag[0] = b[0]
		m := map[string]byte{}
		m["k"] = b[0]
		s := struct{ b []byte }{}
		s.b = b
		_, _, _ = r, m, s
	})
}

// deferredLater only calls the buffer after the lease is over: the literal is
// assigned, not invoked, so it is not reentrant.
func deferredLater(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		later = func() { _ = buf.Len() }
	})
}

func returnedLater(buf *secmem.SecureBuffer) (fn func() int) {
	_ = buf.WithBytes(func(b []byte) {
		fn = func() int { return buf.Len() }
	})
	return fn
}

func lengthsAndComparisons(buf *secmem.SecureBuffer, w io.Writer, other []byte) {
	_ = buf.WithBytes(func(b []byte) {
		sinkS = fmt.Sprintf("%d", len(b))
		io.WriteString(w, "n")
		w.Write(b)
		_ = subtle.ConstantTimeCompare(b, other) == 1
		var x []byte
		x = b
		_ = x
	})
}

// differentBuffer: the inner borrow is of a DIFFERENT buffer, so a method on
// the outer buffer's sibling is not reentrant.
func differentBuffer(a, b *secmem.SecureBuffer) {
	_ = a.WithBytes(func(x []byte) {
		_ = b.Len()
		_ = b.WithBytes(func(y []byte) { copy(y, x) })
	})
}
