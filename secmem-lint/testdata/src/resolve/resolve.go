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
