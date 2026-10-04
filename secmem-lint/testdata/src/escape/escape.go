package escape

import (
	"fmt"
	"log"
	"log/slog"

	"github.com/deadpoets/secmem"
)

var (
	sink    []byte
	sinkStr string
)

func leaks(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkStr = string(b)       // want `secmem-lint: string\(\) copies borrowed secret bytes`
		sink = append(sink, b...) // want `secmem-lint: append\(\) copies borrowed secret bytes`
		dst := make([]byte, len(b))
		copy(dst, b)   // ok: a scratch slice declared inside the closure (see the idioms fixture)
		copy(sink, b)  // want `secmem-lint: copy\(\) moves borrowed secret bytes`
		sink = dst     // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sink = b       // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		fmt.Println(b) // want `secmem-lint: borrowed secret bytes passed to fmt.Println`
	})
}

func leaksViaGoroutineAndChannel(buf *secmem.SecureBuffer, ch chan []byte) {
	_ = buf.WithBytes(func(b []byte) {
		ch <- b     // want `secmem-lint: borrowed secret bytes sent to a channel`
		go func() { // want `secmem-lint: borrowed secret bytes handed to a goroutine`
			_ = len(b)
		}()
	})
}

func clean(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		_ = len(b) // ok: length is not the secret
		local := make([]byte, len(b))
		_ = local // ok: a fresh, independent buffer
	})
}

type holder struct{ b []byte }

var (
	outer     holder
	outerMap  = map[string][]byte{}
	outerPtr  = new([]byte)
	outerSlab = make([][]byte, 1)
)

// leaksViaNonIdentifierTargets covers assignment shapes that matching only a
// bare identifier let through entirely.
func leaksViaNonIdentifierTargets(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		outer.b = b                   // want `secmem-lint: borrowed secret bytes assigned to a struct field`
		outerMap["k"] = b             // want `secmem-lint: borrowed secret bytes assigned to a map or slice element`
		outerSlab[0] = b              // want `secmem-lint: borrowed secret bytes assigned to a map or slice element`
		*outerPtr = b                 // want `secmem-lint: borrowed secret bytes assigned to a pointer target`
		sink = append(sink, b[:1]...) // want `secmem-lint: append\(\) copies borrowed secret bytes`
		panic(b)                      // want `secmem-lint: panic\(\) puts borrowed secret bytes in the traceback`
	})
}

// leaksViaLoggerMethods covers logging METHODS, which the package-keyed sink
// table could never match.
func leaksViaLoggerMethods(buf *secmem.SecureBuffer, sl *slog.Logger, l *log.Logger) {
	_ = buf.WithBytes(func(b []byte) {
		sl.Info("msg", "secret", b)      // want `secmem-lint: borrowed secret bytes passed to log/slog.Logger.Info`
		l.Printf("%s", b)                // want `secmem-lint: borrowed secret bytes passed to log.Logger.Printf`
		slog.Default().Warn("m", "s", b) // want `secmem-lint: borrowed secret bytes passed to log/slog.Logger.Warn`
		sink = fmt.Appendf(nil, "%s", b) // want `secmem-lint: borrowed secret bytes passed to fmt.Appendf`
	})
}

// cleanInnerAggregate must NOT be flagged: the target is a local struct value,
// so the bytes stay inside the lease.
func cleanInnerAggregate(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		var local holder
		local.b = b // ok: local is a struct VALUE declared inside the closure
		_ = local
	})
}

// shadowedNameInGoroutineOK: the goroutine declares its own b. The capture scan
// used to match on the identifier's NAME, so this unrelated variable was
// reported as a leak of the borrowed slice.
func shadowedNameInGoroutineOK(buf *secmem.SecureBuffer, other [][]byte) {
	_ = buf.WithBytes(func(b []byte) {
		_ = b
		go func() {
			for _, b := range other {
				_ = len(b)
			}
		}()
	})
}

type keyErr struct{ raw []byte }

func (e *keyErr) Error() string { return "bad key" }

// leaksViaNamedResult: a named result of the closure is what the closure
// returns, so storing the bytes in it is the return, whether the bare return
// follows or a deferred literal does the store on the way out.
func leaksViaNamedResult(buf *secmem.SecureBuffer) {
	_ = buf.WithBytesErr(func(b []byte) (err error) {
		err = &keyErr{raw: b} // want `secmem-lint: borrowed secret bytes assigned to a named result of the closure`
		return
	})
	_ = buf.WithBytesErr(func(b []byte) (err error) {
		defer func() {
			err = &keyErr{raw: b} // want `secmem-lint: borrowed secret bytes assigned to a named result of the closure`
		}()
		return nil
	})
	_ = buf.WithBytesErr(namedResultDecl)
}

func namedResultDecl(b []byte) (err error) {
	err = &keyErr{raw: b[:1]} // want `secmem-lint: borrowed secret bytes assigned to a named result of the closure`
	return
}

// namedResultOK: a named result that never holds the bytes is clean, and a
// nested literal's own named result is a local of the closure.
func namedResultOK(buf *secmem.SecureBuffer) {
	_ = buf.WithBytesErr(func(b []byte) (err error) {
		if len(b) == 0 {
			err = &keyErr{}
		}
		head := func() (h []byte) {
			h = b[:1]
			return
		}
		_ = head
		return
	})
}
