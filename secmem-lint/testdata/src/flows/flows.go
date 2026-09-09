// Package flows covers the indirect escapes: the borrowed slice leaves the
// closure wrapped in a conversion, a composite, a closure, an element-wise
// copy, a channel message or a goroutine argument rather than as itself.
package flows

import (
	"bytes"
	"io"
	"reflect"
	"unsafe"

	"github.com/deadpoets/secmem"
)

type holder struct{ b []byte }
type msg struct{ payload []byte }
type myErr struct{ b []byte }

func (e *myErr) Error() string { return "x" }

var (
	sinkB   = make([]byte, 64)
	sinkS   string
	sinkAny any
	sinkSS  [][]byte
	sinkFn  func() []byte
	sinkR   io.Reader
	sinkH   holder
	sinkHP  = &holder{}
	sinkM   = map[string]any{}
	sinkCh  = make(chan any, 8)
	sinkPtr unsafe.Pointer
	sinkP   *byte
)

func use(v any) { sinkAny = v }

func conversions(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkAny = any(b)         // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkAny = b              // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkB = []byte(b)        // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkM["k"] = any(b)      // want `secmem-lint: borrowed secret bytes assigned to a map or slice element`
		sinkS = "k=" + string(b) // want `secmem-lint: string\(\) copies borrowed secret bytes`
		sinkS = string(b[:4])    // want `secmem-lint: string\(\) copies borrowed secret bytes`
	})
}

func composites(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkH = holder{b: b}                // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkHP = &holder{b}                 // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkAny = []any{b}                  // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkAny = map[string][]byte{"k": b} // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		*sinkHP = holder{b}                 // want `secmem-lint: borrowed secret bytes assigned to a pointer target`
	})
}

func appends(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkSS = append(sinkSS, b) // want `secmem-lint: append\(\) copies borrowed secret bytes`
		sinkB = append(b, 'x')     // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
	})
}

func elementWiseLoops(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		for i := range b {
			sinkB[i] = b[i] // want `secmem-lint: borrowed secret bytes assigned to a map or slice element`
		}
		for _, c := range b {
			sinkB = append(sinkB, c) // want `secmem-lint: append\(\) copies borrowed secret bytes`
		}
		d := make([]byte, len(b))
		for i := range b {
			d[i] = b[i] // ok: d is a fresh local; the leak is the line below
		}
		sinkB = d // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
	})
}

func aliases(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		c := b
		sinkB = c // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		d := b[:2]
		sinkB = d // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		var e []byte
		e = b
		sinkS, sinkB = "x", e // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
	})
}

func capturingClosures(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkFn = func() []byte { return b } // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		f := func() []byte { return b }
		sinkFn = f  // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkB = f() // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
	})
}

func returnedClosure(buf *secmem.SecureBuffer) (fn func() []byte) {
	_ = buf.WithBytesErr(func(b []byte) error {
		fn = func() []byte { return b } // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		return nil
	})
	return fn
}

func returns(buf *secmem.SecureBuffer) error {
	return buf.WithBytesErr(func(b []byte) error {
		if len(b) == 0 {
			return &myErr{b} // want `secmem-lint: borrowed secret bytes returned from the closure`
		}
		return nil // ok
	})
}

func channelsAndGoroutines(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkCh <- any(b) // want `secmem-lint: borrowed secret bytes sent to a channel`
		sinkCh <- msg{b} // want `secmem-lint: borrowed secret bytes sent to a channel`
		go use(any(b))   // want `secmem-lint: borrowed secret bytes handed to a goroutine`
		go use(b)        // want `secmem-lint: borrowed secret bytes handed to a goroutine`
		f := func() { use(b) }
		go f() // want `secmem-lint: borrowed secret bytes handed to a goroutine`
	})
}

func unsafeAndReflect(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkS = unsafe.String(unsafe.SliceData(b), len(b)) // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkP = unsafe.SliceData(b)                        // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkPtr = unsafe.Pointer(&b[0])                    // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkAny = reflect.ValueOf(b).Interface()           // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkR = bytes.NewReader(b)                         // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		_, _ = io.Copy(io.Discard, bytes.NewReader(b))     // ok: the reader does not outlive the closure
	})
}

func notTainted(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		n := len(b)
		sinkAny = n                              // ok: a length
		sinkAny = b[0] == 'x'                    // ok: a comparison
		sinkAny = cap(b) > 0                     // ok
		use(reflect.TypeOf(b))                   // ok: not an alias constructor
		sinkAny = uintptr(unsafe.Pointer(&b[0])) // ok: an address, not the bytes
	})
}

// enclosingClosureIsStillOutside: tmp belongs to the OUTER borrow, so it
// outlives the inner lease; the copy is reported like any other copy-out.
func enclosingClosureIsStillOutside(a, b *secmem.SecureBuffer) {
	_ = a.WithBytes(func(x []byte) {
		var tmp [16]byte
		_ = b.WithBytes(func(y []byte) {
			copy(tmp[:], y) // want `secmem-lint: copy\(\) moves borrowed secret bytes`
		})
		copy(x, tmp[:]) // ok: writing into the borrowed slice
	})
}
