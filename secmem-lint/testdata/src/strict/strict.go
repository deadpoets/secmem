package strict

import "github.com/deadpoets/secmem"

// --- N1: secret-named identifiers held in a plain string ---

var password string // want `secmem-lint: "password" is a secret-named identifier held in a plain string`

type Config struct {
	Token    string // want `secmem-lint: "Token" is a secret-named identifier held in a plain string`
	Name     string // ok: not a secret name
	Password []byte // ok: not a string
}

func n1Locals() {
	apiKey := "literal" // want `secmem-lint: "apiKey" is a secret-named identifier held in a plain string`
	username := "alice" // ok: not a secret name
	_ = apiKey
	_ = username
}

// --- L1: a constructed resource never Destroyed or handed off ---

func leaks() {
	buf, _ := secmem.NewBuffer([]byte("k")) // want `secmem-lint: buf is never Destroyed or handed off`
	_ = buf.WithBytes(func(b []byte) {})
}

func deferredOK() {
	buf, _ := secmem.NewBuffer([]byte("k"))
	defer buf.Destroy()
	_ = buf.WithBytes(func(b []byte) {})
}

// leaksViaDeclaration: the construction spelled as a var declaration is the
// same create-and-forget.
func leaksViaDeclaration() {
	var buf, _ = secmem.NewBuffer([]byte("k")) // want `secmem-lint: buf is never Destroyed or handed off`
	_ = buf.WithBytes(func(b []byte) {})
}

func declarationDeferredOK() {
	var buf, _ = secmem.NewBuffer([]byte("k"))
	defer buf.Destroy()
	_ = buf.WithBytes(func(b []byte) {})
}

func destroyedOK() {
	buf, _ := secmem.NewBuffer([]byte("k"))
	_ = buf.WithBytes(func(b []byte) {})
	_ = buf.Destroy()
}

func returnedOK() *secmem.SecureBuffer {
	buf, _ := secmem.NewBuffer([]byte("k")) // ok: ownership returned to the caller
	return buf
}

func handedOffOK() {
	buf, _ := secmem.NewBuffer([]byte("k")) // ok: ownership passed to consume
	consume(buf)
}

func consume(b *secmem.SecureBuffer) { _ = b.Destroy() }

// --- unresolvable borrowing closures ---

var sink []byte

func wrap(f func([]byte)) func([]byte) { return f }

type callbacks struct{ fn func([]byte) }

func unresolvable(buf *secmem.SecureBuffer, cb callbacks, cond bool) {
	defer buf.Destroy()
	_ = buf.WithBytes(wrap(func(b []byte) { sink = b })) // want `secmem-lint: borrowed closure is not a function literal and cannot be checked`
	_ = buf.WithBytes(cb.fn)                             // want `secmem-lint: borrowed closure is not a function literal and cannot be checked`
	fn := func(b []byte) { sink = b }
	if cond {
		fn = func(b []byte) {}
	}
	_ = buf.WithBytes(fn)                // want `secmem-lint: borrowed closure is not a function literal and cannot be checked`
	_ = buf.WithBytes(func(b []byte) {}) // ok: a literal
	_ = buf.WithBytes(nil)               // ok: not a closure
}

// --- a SecureArena method inside a slot borrow of an unknown arena ---

func unknownArena(slot *secmem.ArenaSlot, arena *secmem.SecureArena) {
	defer arena.Destroy()
	_ = slot.WithBytes(func(b []byte) {
		_ = arena.Destroy() // want `secmem-lint: Destroy called on a SecureArena inside a slot borrow whose arena cannot be resolved`
	})
}

// --- a borrowing method value that is only sometimes one ---

// sometimesBorrow: f is buf.WithBytes on one path and an unrelated function on
// the other, so whether the literal is borrowed is a runtime question and it
// is not checked. (Bound to borrowing accessors on EVERY path it would be —
// see the resolve fixture.)
func sometimesBorrow(buf *secmem.SecureBuffer, cond bool, plain func(func([]byte)) error) {
	defer buf.Destroy()
	f := buf.WithBytes
	if cond {
		f = plain
	}
	_ = f(func(b []byte) { sink = b }) // want `secmem-lint: closure passed through a variable that is sometimes a borrowing method value and sometimes not; it cannot be checked`
}

// --- an explicitly instantiated generic function is a resolved closure ---

// leakG is a generic borrowing function. leakG[[]byte] resolves to this
// declaration exactly as the bare name does, so the call below must not be
// reported as an unresolvable closure (the body is clean, so nothing else is
// reported either).
func leakG[T ~[]byte](b T) { _ = len(b) }

func genericInstantiatedResolved(buf *secmem.SecureBuffer) {
	defer buf.Destroy()
	_ = buf.WithBytes(leakG[[]byte]) // ok: resolved to leakG's declaration, not "cannot be checked"
}
