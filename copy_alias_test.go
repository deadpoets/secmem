package secmem

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// A SecureBuffer or SecureArena value that has been copied is an alias of the
// original, in the way a copied os.File is: both refer to one region and one
// set of state, and destroying either destroys both. These tests pin that. The
// failure they guard against is a copy that kept its own liveness fields, so
// that after the original's Destroy it still handed out a slice over memory
// that had been unmapped, or that another buffer had since been given.

// TestSecureBuffer_CopyIsAnAlias covers a dereferenced copy outliving Destroy
// on the original.
func TestSecureBuffer_CopyIsAnAlias(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewBuffer(bytes.Repeat([]byte{0x5A}, 32))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	c := *buf

	// State changed through one is seen through the other.
	if err := c.Truncate(16); err != nil {
		t.Fatalf("Truncate through the copy: %v", err)
	}
	if got := buf.Len(); got != 16 {
		t.Errorf("original Len() after Truncate(16) through the copy = %d, want 16", got)
	}
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !c.IsSealed() {
		t.Error("copy does not see the original's Seal")
	}
	if err := c.WithBytes(func([]byte) {}); !errors.Is(err, ErrSealed) {
		t.Errorf("WithBytes through the copy of a sealed buffer = %v, want ErrSealed", err)
	}
	if err := c.Unseal(); err != nil {
		t.Fatalf("Unseal through the copy: %v", err)
	}

	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	// The callbacks only record that they ran: the slice a stale copy hands
	// out points at unmapped memory, and reading it would fault the test.
	called := false
	if err := c.WithBytes(func([]byte) { called = true }); !errors.Is(err, ErrDestroyed) {
		t.Errorf("WithBytes through a copy after Destroy = %v, want ErrDestroyed", err)
	}
	if err := c.WithBytesErr(func([]byte) error { called = true; return nil }); !errors.Is(err, ErrDestroyed) {
		t.Errorf("WithBytesErr through a copy after Destroy = %v, want ErrDestroyed", err)
	}
	if called {
		t.Error("a borrow through a copy ran its callback after the buffer was destroyed")
	}
	if !c.IsDestroyed() {
		t.Error("copy.IsDestroyed() = false after the original was destroyed")
	}
	if got := c.Len(); got != 0 {
		t.Errorf("copy.Len() after Destroy = %d, want 0", got)
	}
	if err := c.Destroy(); err != nil {
		t.Errorf("Destroy through the copy after the original's = %v, want nil", err)
	}
}

// TestSecureBuffer_DestroyThroughCopy is the other direction: Destroy on the
// copy retires the original.
func TestSecureBuffer_DestroyThroughCopy(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewBuffer(bytes.Repeat([]byte{0x5A}, 32))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	c := *buf
	if err := c.Destroy(); err != nil {
		t.Fatalf("Destroy through the copy: %v", err)
	}
	called := false
	if err := buf.WithBytes(func([]byte) { called = true }); !errors.Is(err, ErrDestroyed) {
		t.Errorf("WithBytes on the original after Destroy through a copy = %v, want ErrDestroyed", err)
	}
	if called {
		t.Error("a borrow on the original ran its callback after a copy destroyed the buffer")
	}
	if !buf.IsDestroyed() {
		t.Error("IsDestroyed() = false on the original after Destroy through a copy")
	}
}

// TestSecureBuffer_OverwriteIsAnAlias covers assignment through the pointer:
// *a = *b makes a refer to b's buffer.
func TestSecureBuffer_OverwriteIsAnAlias(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	a, err := NewBuffer(bytes.Repeat([]byte{0xA1}, 8))
	if err != nil {
		t.Skipf("NewBuffer(a): %v", err)
	}
	old := *a // keeps a's own buffer reachable so it can be destroyed below
	defer func() { _ = old.Destroy() }()
	b, err := NewBuffer(bytes.Repeat([]byte{0xB2}, 24))
	if err != nil {
		t.Skipf("NewBuffer(b): %v", err)
	}
	defer func() { _ = b.Destroy() }()

	*a = *b
	if got := a.Len(); got != 24 {
		t.Errorf("Len() after *a = *b is %d, want b's 24", got)
	}
	if a.LockOrder() != b.LockOrder() {
		t.Error("a and b report different identities after *a = *b")
	}
	if err := b.Destroy(); err != nil {
		t.Fatalf("b.Destroy: %v", err)
	}
	called := false
	if err := a.WithBytes(func([]byte) { called = true }); !errors.Is(err, ErrDestroyed) {
		t.Errorf("a.WithBytes after b.Destroy = %v, want ErrDestroyed", err)
	}
	if called {
		t.Error("a borrow through the overwritten handle ran after its buffer was destroyed")
	}
	// a's first buffer is untouched by any of that.
	if old.IsDestroyed() {
		t.Error("the buffer a referred to before the overwrite was destroyed with b")
	}
}

// TestSecureArena_CopyIsAnAlias is the arena half. A copy that carried its own
// destroyed flag and region kept handing out slots in a slab that was gone.
func TestSecureArena_CopyIsAnAlias(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	arena, err := NewArena(32, 4)
	if err != nil {
		t.Skipf("NewArena: %v", err)
	}
	defer func() { _ = arena.Destroy() }()

	c := *arena
	slot, err := c.Acquire()
	if err != nil {
		t.Fatalf("Acquire through the copy: %v", err)
	}
	if got := arena.LiveCount(); got != 1 {
		t.Errorf("original LiveCount() after Acquire through the copy = %d, want 1", got)
	}

	if err := arena.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if !c.IsDestroyed() {
		t.Error("copy.IsDestroyed() = false after the original was destroyed")
	}
	if _, err := c.Acquire(); !errors.Is(err, ErrArenaDestroyed) {
		t.Errorf("Acquire through a copy after Destroy = %v, want ErrArenaDestroyed", err)
	}
	called := false
	if err := slot.WithBytes(func([]byte) { called = true }); !errors.Is(err, ErrArenaDestroyed) {
		t.Errorf("slot.WithBytes after Destroy = %v, want ErrArenaDestroyed", err)
	}
	if called {
		t.Error("a slot borrow ran its callback after the arena was destroyed")
	}
	if err := c.Destroy(); err != nil {
		t.Errorf("Destroy through the copy after the original's = %v, want nil", err)
	}
}

// TestZeroValues_BehaveAsDestroyed pins that a SecureBuffer, SecureArena or
// ArenaSlot that was declared rather than constructed is an already-destroyed
// one: every method returns what it returns after Destroy (or Release), and
// none of them panics. A nil pointer was always handled; the zero value used to
// dereference its nil lock.
func TestZeroValues_BehaveAsDestroyed(t *testing.T) {
	noPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s panicked on a zero value: %v", name, r)
			}
		}()
		fn()
	}
	wantErr := func(name string, got, want error) {
		t.Helper()
		if !errors.Is(got, want) {
			t.Errorf("%s on a zero value = %v, want %v", name, got, want)
		}
	}
	never := func([]byte) { t.Error("callback ran on a zero value") }
	neverErr := func([]byte) error { t.Error("callback ran on a zero value"); return nil }

	var b SecureBuffer
	noPanic("SecureBuffer.Destroy", func() { wantErr("SecureBuffer.Destroy", b.Destroy(), nil) })
	noPanic("SecureBuffer.IsDestroyed", func() {
		if !b.IsDestroyed() {
			t.Error("SecureBuffer.IsDestroyed() on a zero value = false")
		}
	})
	noPanic("SecureBuffer.Len", func() {
		if n := b.Len(); n != 0 {
			t.Errorf("SecureBuffer.Len() on a zero value = %d", n)
		}
	})
	noPanic("SecureBuffer.MappedLen", func() {
		if n := b.MappedLen(); n != 0 {
			t.Errorf("SecureBuffer.MappedLen() on a zero value = %d", n)
		}
	})
	noPanic("SecureBuffer.IsSealed", func() {
		if b.IsSealed() {
			t.Error("SecureBuffer.IsSealed() on a zero value = true")
		}
	})
	noPanic("SecureBuffer.LockOrder", func() {
		if k := b.LockOrder(); k != 0 {
			t.Errorf("SecureBuffer.LockOrder() on a zero value = %d", k)
		}
	})
	noPanic("SecureBuffer.Capabilities", func() {
		if got, want := b.Capabilities(), (*SecureBuffer)(nil).Capabilities(); got != want {
			t.Errorf("SecureBuffer.Capabilities() on a zero value = %v, want the nil receiver's %v", got, want)
		}
	})
	bufErrs := map[string]func() error{
		"WithBytes":         func() error { return b.WithBytes(never) },
		"WithBytesErr":      func() error { return b.WithBytesErr(neverErr) },
		"ExposeString":      func() error { _, e := b.ExposeString(); return e },
		"CopyOut":           func() error { _, e := b.CopyOut(make([]byte, 1), 0); return e },
		"CopyIn":            func() error { _, e := b.CopyIn([]byte{1}, 0); return e },
		"ByteAt":            func() error { _, e := b.ByteAt(0); return e },
		"SetByteAt":         func() error { return b.SetByteAt(0, 1) },
		"ConstantTimeEqual": func() error { _, e := b.ConstantTimeEqual([]byte{0}); return e },
		"WriteTo":           func() error { _, e := b.WriteTo(io.Discard); return e },
		"ReadFrom":          func() error { _, e := b.ReadFrom(bytes.NewReader([]byte{1})); return e },
		"ReadOnly":          b.ReadOnly,
		"ReadWrite":         b.ReadWrite,
		"Seal":              b.Seal,
		"Unseal":            b.Unseal,
		"Truncate":          func() error { return b.Truncate(0) },
	}
	for name, fn := range bufErrs {
		noPanic("SecureBuffer."+name, func() { wantErr("SecureBuffer."+name, fn(), ErrDestroyed) })
	}

	var a SecureArena
	noPanic("SecureArena.Destroy", func() { wantErr("SecureArena.Destroy", a.Destroy(), nil) })
	noPanic("SecureArena.IsDestroyed", func() {
		if !a.IsDestroyed() {
			t.Error("SecureArena.IsDestroyed() on a zero value = false")
		}
	})
	noPanic("SecureArena.Acquire", func() {
		_, err := a.Acquire()
		wantErr("SecureArena.Acquire", err, ErrArenaDestroyed)
	})
	noPanic("SecureArena.LiveCount/Cap/SlotSize", func() {
		if a.LiveCount() != 0 || a.Cap() != 0 || a.SlotSize() != 0 {
			t.Error("SecureArena size queries on a zero value are not all 0")
		}
	})
	noPanic("SecureArena.ReadOnly", func() { wantErr("SecureArena.ReadOnly", a.ReadOnly(), ErrArenaDestroyed) })
	noPanic("SecureArena.ReadWrite", func() { wantErr("SecureArena.ReadWrite", a.ReadWrite(), ErrArenaDestroyed) })
	noPanic("SecureArena.Capabilities", func() {
		if got, want := a.Capabilities(), (*SecureArena)(nil).Capabilities(); got != want {
			t.Errorf("SecureArena.Capabilities() on a zero value = %v, want the nil receiver's %v", got, want)
		}
	})

	var s ArenaSlot
	noPanic("ArenaSlot.WithBytes", func() { wantErr("ArenaSlot.WithBytes", s.WithBytes(never), ErrSlotReleased) })
	noPanic("ArenaSlot.WithBytesErr", func() { wantErr("ArenaSlot.WithBytesErr", s.WithBytesErr(neverErr), ErrSlotReleased) })
	noPanic("ArenaSlot.Release", func() { wantErr("ArenaSlot.Release", s.Release(), nil) })
	noPanic("ArenaSlot.IsLive", func() {
		if s.IsLive() {
			t.Error("ArenaSlot.IsLive() on a zero value = true")
		}
	})
	noPanic("ArenaSlot.Index", func() {
		if got, want := s.Index(), (*ArenaSlot)(nil).Index(); got != want {
			t.Errorf("ArenaSlot.Index() on a zero value = %d, want the nil receiver's %d", got, want)
		}
	})
}
