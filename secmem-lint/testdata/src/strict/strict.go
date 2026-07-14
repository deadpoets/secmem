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
