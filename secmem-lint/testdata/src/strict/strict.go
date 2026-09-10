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
