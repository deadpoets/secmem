// Package resolve covers the entry-point shapes: the closure is not written
// inline, the accessor is reached through a method value, a local alias, an
// interface, or an aliased parameter type.
package resolve

import (
	"github.com/deadpoets/secmem"
	secmemcrypto "github.com/deadpoets/secmem/secmem-crypto"
)

var sink []byte

type raw = []byte

// leakFn is a package-level function passed by name.
func leakFn(b []byte) {
	sink = b // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
}

func namedFunction(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(leakFn)
}

// namedFunctionTwice: the same body reached from two call sites is reported
// once, at the body.
func namedFunctionTwice(a, b *secmem.SecureBuffer) {
	_ = a.WithBytes(leakFn)
	_ = b.WithBytes(leakFn)
}

func localVariable(buf *secmem.SecureBuffer) {
	fn := func(b []byte) {
		sink = b // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
	}
	_ = buf.WithBytes(fn)
}

func localVarDeclaration(buf *secmem.SecureBuffer) {
	var fn func([]byte) error = func(b []byte) error {
		sink = b // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		return nil
	}
	_ = buf.WithBytesErr(fn)
}

// reassignedNotResolved: a variable assigned twice is not followed (which one
// runs is a runtime question), so nothing is reported here by default.
func reassignedNotResolved(buf *secmem.SecureBuffer, cond bool) {
	fn := func(b []byte) { sink = b }
	if cond {
		fn = func(b []byte) { _ = len(b) }
	}
	_ = buf.WithBytes(fn)
}

func methodValue(buf *secmem.SecureBuffer) {
	f := buf.WithBytes
	_ = f(func(b []byte) {
		sink = b // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
	})
}

func methodValueReentrant(buf *secmem.SecureBuffer) {
	f := buf.WithBytes
	_ = f(func(b []byte) {
		_ = buf.Len() // want `secmem-lint: Len called on the same buffer`
	})
}

// borrower is the interface heuristic: a WithBytes(func([]byte)) error on an
// interface is treated as a borrow, whatever implements it.
type borrower interface {
	WithBytes(func([]byte)) error
	Len() int
}

func interfaceReceiver(i borrower) {
	_ = i.WithBytes(func(b []byte) {
		sink = b    // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		_ = i.Len() // want `secmem-lint: Len called on the same buffer`
	})
}

// unrelatedConcreteType: a concrete type outside secmem with a WithBytes of
// the same shape is not a borrow.
type other struct{}

func (other) WithBytes(fn func([]byte)) error { return nil }

func unrelatedConcreteType(o other) {
	_ = o.WithBytes(func(b []byte) { sink = b })
}

// wrongShape: an interface WithBytes that does not take a []byte closure is
// not a borrow either.
type notBorrower interface{ WithBytes(func(string)) error }

func wrongShape(n notBorrower) {
	_ = n.WithBytes(func(s string) { _ = s })
}

func aliasedParamType(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b raw) {
		sink = b // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
	})
}

func cryptoAccessors(s *secmemcrypto.Ed25519Signer, k *secmemcrypto.X25519Key, r *secmemcrypto.RSASigner) {
	_ = s.WithSeed(func(seed []byte) error {
		sink = seed // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		return nil
	})
	_ = k.WithScalar(func(scalar []byte) error {
		sink = scalar // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		return nil
	})
	_ = r.WithDER(func(der []byte) error {
		sink = der // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		return nil
	})
}

func slotAndSecret(slot *secmem.ArenaSlot, s secmem.Secret) {
	_ = slot.WithBytes(func(b []byte) {
		sink = b // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
	})
	_ = s.WithBytes(func(b []byte) {
		sink = b // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
	})
}

func wrap(f func([]byte)) func([]byte) { return f }

// wrappedNotResolved: a closure produced by a call cannot be checked. Default
// mode is silent; strict mode reports it (see the strict fixture).
func wrappedNotResolved(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(wrap(func(b []byte) { sink = b }))
}

// nilClosure is not a borrow of anything.
func nilClosure(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(nil)
}

// leakG is a generic borrowing function passed by name. Its parameter is
// declared as T and is a []byte only in the signature instantiated at the
// call, which is where the analyzer decides the borrowed parameters. The body
// is reported once however many call sites reach it.
func leakG[T ~[]byte](b T) {
	sink = b // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
}

func genericByName(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(leakG)
}

// genericInstantiated: the same function passed with an explicit
// instantiation resolves to the same declaration (and is not an unresolved
// closure for -strict).
func genericInstantiated(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(leakG[[]byte])
}

// leakG1 is reached ONLY through an explicit instantiation. Its finding pins
// that leakG1[[]byte] resolves to the declaration by itself: leakG's body is
// also reached by name, so it would be reported with or without the
// instantiated shape being understood.
func leakG1[T ~[]byte](b T) {
	sink = b // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
}

func genericInstantiatedOnly(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(leakG1[[]byte])
}

// leakG2 has two type parameters, so its instantiation is an index list.
func leakG2[T ~[]byte, U any](b T) {
	var zero U
	_ = zero
	sink = b // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
}

func genericInstantiatedList(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(leakG2[[]byte, int])
}

// methodExpression: the accessor spelled as a method expression, with the
// receiver as the first argument, is the same borrow.
func methodExpression(buf *secmem.SecureBuffer) {
	_ = (*secmem.SecureBuffer).WithBytes(buf, func(b []byte) {
		sink = b      // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		_ = buf.Len() // want `secmem-lint: Len called on the same buffer`
	})
}

// methodValueBoundTwice: f holds one of two borrowing accessors, so the
// closure is borrowed whichever runs and its escapes are checked. Only the
// receiver's identity is undecidable, so the reentrancy check stays silent.
func methodValueBoundTwice(buf, other *secmem.SecureBuffer, cond bool) {
	f := buf.WithBytes
	if cond {
		f = other.WithBytes
	}
	_ = f(func(b []byte) {
		sink = b      // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		_ = buf.Len() // not decidable: f may be other.WithBytes
	})
}

// methodValueSometimesBorrow: f is a borrowing accessor on one path and an
// unrelated function on the other, so whether the literal is borrowed at all
// is a runtime question. Default mode is silent; strict reports it (see the
// strict fixture).
func methodValueSometimesBorrow(buf *secmem.SecureBuffer, cond bool, plain func(func([]byte)) error) {
	f := buf.WithBytes
	if cond {
		f = plain
	}
	_ = f(func(b []byte) { sink = b })
}
