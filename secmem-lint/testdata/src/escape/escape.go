package escape

import (
	"fmt"

	"github.com/deadpoets/secmem"
)

var (
	sink    []byte
	sinkStr string
)

func leaks(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkStr = string(b)       // want `secmem-lint: string\(\) copies borrowed secret bytes`
		sink = append(sink, b...) // want `secmem-lint: append\(dst, borrowed\.\.\.\) copies borrowed secret bytes`
		dst := make([]byte, len(b))
		copy(dst, b)   // want `secmem-lint: copy\(\) moves borrowed secret bytes`
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
