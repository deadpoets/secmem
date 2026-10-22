// Package expose covers ExposeString as an E4 sink on the call itself: the
// copy is made inside the library, so it is reported wherever it is written,
// in or out of a closure.
package expose

import "github.com/deadpoets/secmem"

var sinkStr string

func call(buf *secmem.SecureBuffer) {
	s, err := buf.ExposeString() // want `secmem-lint: ExposeString copies the secret into an immutable heap string that can never be wiped`
	_, _ = s, err
}

func methodValue(buf *secmem.SecureBuffer) {
	f := buf.ExposeString // want `secmem-lint: ExposeString copies the secret`
	sinkStr, _ = f()      // ok: reported once, where the method value is taken
}

func methodExpr(buf *secmem.SecureBuffer) {
	sinkStr, _ = (*secmem.SecureBuffer).ExposeString(buf) // want `secmem-lint: ExposeString copies the secret`
}

type embeds struct{ *secmem.SecureBuffer }

func promoted(e embeds) {
	sinkStr, _ = e.ExposeString() // want `secmem-lint: ExposeString copies the secret`
}

// exposer is how a *secmem.SecureBuffer looks behind an interface.
type exposer interface{ ExposeString() (string, error) }

func throughInterface(x exposer) {
	sinkStr, _ = x.ExposeString() // want `secmem-lint: ExposeString copies the secret`
}

// other has a look-alike method on a concrete type from another package: not
// matched, as for the borrowing accessors.
type other struct{}

func (other) ExposeString() (string, error) { return "", nil }

func lookAlike(o other) {
	sinkStr, _ = o.ExposeString() // ok: not a secmem type
}

// differentShape is an interface method of the same name but another shape.
type differentShape interface{ ExposeString(n int) string }

func otherShape(x differentShape) {
	sinkStr = x.ExposeString(1) // ok: not the exposing shape
}

func suppressed(buf *secmem.SecureBuffer) {
	sinkStr, _ = buf.ExposeString() //nolint:secmem-lint // reviewed boundary: the driver takes only a string
}
