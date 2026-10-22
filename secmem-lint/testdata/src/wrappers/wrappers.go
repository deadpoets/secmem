// Package wrappers covers borrowing wrappers: functions that forward a func
// parameter, unchanged, to a borrowing accessor. Their callers' closures are
// checked as if passed to the accessor directly.
package wrappers

import (
	"errors"

	"github.com/deadpoets/secmem"

	"wrapdep"
)

var sink []byte

var errNil = errors.New("nil")

type config struct{ pass *secmem.SecureBuffer }

// withPass is the issue's shape: a nil check, then the accessor.
func withPass(cfg *config, fn func([]byte) error) error { // want withPass:`borrowWrapper\[1\]`
	if cfg == nil || cfg.pass == nil {
		return errNil
	}
	return cfg.pass.WithBytesErr(fn)
}

func callers(cfg *config) {
	_ = withPass(cfg, func(b []byte) error {
		sink = b // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		return nil
	})
	_ = withPass(cfg, func(b []byte) error {
		_ = len(b) // ok
		return nil
	})
	fn := func(b []byte) error {
		_ = string(b) // want `secmem-lint: string\(\) copies borrowed secret bytes into a heap string`
		return nil
	}
	_ = withPass(cfg, fn)
	_ = withPass(cfg, leak)
}

func leak(b []byte) error {
	sink = append(sink, b...) // want `secmem-lint: append\(\) copies borrowed secret bytes into a slice outside the closure`
	return nil
}

// keyPair has a method wrapper with a nil check on the closure itself.
type keyPair struct{ priv *secmem.SecureBuffer }

func (kp *keyPair) WithSeed(fn func([]byte) error) error { // want WithSeed:`borrowWrapper\[0\]`
	if fn == nil || kp.priv == nil {
		return errNil
	}
	return kp.priv.WithBytesErr(fn)
}

func methodCallers(kp *keyPair) {
	_ = kp.WithSeed(func(b []byte) error {
		sink = b // want `secmem-lint: borrowed secret bytes assigned`
		return nil
	})
	_ = (*keyPair).WithSeed(kp, func(b []byte) error {
		sink = b // want `secmem-lint: borrowed secret bytes assigned`
		return nil
	})
	f := kp.WithSeed
	_ = f(func(b []byte) error {
		sink = b // want `secmem-lint: borrowed secret bytes assigned`
		return nil
	})
}

// chained forwards to another wrapper: found on a later round.
func chained(cfg *config, fn func([]byte) error) error { // want chained:`borrowWrapper\[1\]`
	return withPass(cfg, fn)
}

func chainedCaller(cfg *config) {
	_ = chained(cfg, func(b []byte) error {
		sink = b // want `secmem-lint: borrowed secret bytes assigned`
		return nil
	})
}

// crossPackage: the wrapper is declared in another package; the fact
// carries it here.
func crossPackage(kp *wrapdep.KeyPair) {
	_ = kp.WithSeed(func(b []byte) error {
		sink = b // want `secmem-lint: borrowed secret bytes assigned`
		return nil
	})
}

// secondParam: the forwarded parameter is not the first func argument.
func secondParam(onErr func([]byte), buf *secmem.SecureBuffer, fn func([]byte)) error { // want secondParam:`borrowWrapper\[2\]`
	if onErr != nil {
		onErr(nil)
	}
	return buf.WithBytes(fn)
}

func secondParamCaller(buf *secmem.SecureBuffer) {
	_ = secondParam(func(b []byte) { sink = b }, buf, func(b []byte) {
		sink = b // want `secmem-lint: borrowed secret bytes assigned`
	})
}

// --- not wrappers: the parameter is used some other way too ---

// callsDirectly also calls fn itself, on bytes that are not borrowed.
func callsDirectly(buf *secmem.SecureBuffer, fn func([]byte) error) error {
	if err := fn(nil); err != nil {
		return err
	}
	return buf.WithBytesErr(fn)
}

// stores keeps fn for later.
var kept func([]byte) error

func stores(buf *secmem.SecureBuffer, fn func([]byte) error) error {
	kept = fn
	return buf.WithBytesErr(fn)
}

// adapts wraps fn in a new literal: the literal is the borrowed closure and
// is checked; fn(trimmed) inside it is a call the analyzer does not follow.
func adapts(buf *secmem.SecureBuffer, fn func([]byte) error) error {
	return buf.WithBytesErr(func(b []byte) error { return fn(b[:1]) })
}

// unused never forwards fn at all.
func unused(buf *secmem.SecureBuffer, fn func([]byte) error) error {
	return buf.WithBytesErr(func(b []byte) error { return nil })
}

// mutual forwards only to each other: no borrow ever happens, so neither is a
// wrapper.
func mutualA(fn func([]byte) error) error { return mutualB(fn) }
func mutualB(fn func([]byte) error) error { return mutualA(fn) }

func notWrapperCallers(buf *secmem.SecureBuffer) {
	leaky := func(b []byte) error { sink = b; return nil }
	_ = callsDirectly(buf, leaky)
	_ = stores(buf, leaky)
	_ = adapts(buf, leaky)
	_ = unused(buf, leaky)
	_ = mutualA(leaky)
}

// both forwards two closures, each to its own buffer: every forwarded
// argument at a call site is checked, not only the first.
func both(a, b *secmem.SecureBuffer, f1, f2 func([]byte)) { // want both:`borrowWrapper\[2 3\]`
	_ = a.WithBytes(f1)
	_ = b.WithBytes(f2)
}

func bothCaller(a, b *secmem.SecureBuffer) {
	both(a, b, func(p []byte) {
		sink = p // want `secmem-lint: borrowed secret bytes assigned`
	}, func(p []byte) {
		sink = append(sink, p...) // want `secmem-lint: append\(\) copies borrowed secret bytes into a slice outside the closure`
	})
}
