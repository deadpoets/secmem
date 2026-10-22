//go:build linux || windows

package secmem

import (
	"bytes"
	"errors"
	"testing"
	"unsafe"
)

// innerAddr is the address of the first secret byte of buf's region.
func innerAddr(buf *SecureBuffer) uintptr {
	return uintptr(unsafe.Pointer(&buf.region.inner[0]))
}

// requireClosed fails unless buf's page is mapped and inaccessible.
func requireClosed(t *testing.T, buf *SecureBuffer, when string) {
	t.Helper()
	if mapped, accessible := addrState(t, innerAddr(buf)); !mapped || accessible {
		t.Errorf("%s: page is mapped=%v accessible=%v, want mapped and inaccessible", when, mapped, accessible)
	}
}

func newClosed(t *testing.T, secret []byte) *SecureBuffer {
	t.Helper()
	buf, err := NewBuffer(bytes.Clone(secret), WithClosedAtRest())
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	t.Cleanup(func() { _ = buf.Destroy() })
	return buf
}

// TestClosedAtRest_OpenOnlyDuringABorrow is the option's whole claim: the page
// cannot be read at rest, can be read inside a callback, and cannot be read
// again once the last concurrent callback has returned.
func TestClosedAtRest_OpenOnlyDuringABorrow(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5A}, 48)
	buf := newClosed(t, secret)
	if !buf.Capabilities().ClosedAtRest {
		t.Error("Capabilities().ClosedAtRest = false")
	}
	requireClosed(t, buf, "after construction")

	if err := buf.WithBytes(func(b []byte) {
		if _, accessible := addrState(t, innerAddr(buf)); !accessible {
			t.Error("page is not accessible inside the callback")
		}
		if !bytes.Equal(b, secret) {
			t.Error("callback did not see the secret")
		}
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	requireClosed(t, buf, "after a borrow")

	// Two borrows overlap. The first to return must not close the page under
	// the second, and the second must close it.
	firstIn, firstOut := make(chan struct{}), make(chan struct{})
	secondIn, secondOut := make(chan struct{}), make(chan struct{})
	done := make(chan error, 2)
	go func() {
		done <- buf.WithBytes(func([]byte) { close(firstIn); <-firstOut })
	}()
	<-firstIn
	go func() {
		done <- buf.WithBytes(func(b []byte) {
			close(secondIn)
			<-secondOut
			if !bytes.Equal(b, secret) { // read after the first borrow ended
				t.Error("second borrow did not see the secret")
			}
		})
	}()
	<-secondIn
	close(firstOut)
	if err := <-done; err != nil {
		t.Fatalf("first borrow: %v", err)
	}
	if _, accessible := addrState(t, innerAddr(buf)); !accessible {
		t.Error("the first borrow to return closed the page under a borrow still running")
	}
	close(secondOut)
	if err := <-done; err != nil {
		t.Fatalf("second borrow: %v", err)
	}
	requireClosed(t, buf, "after the last concurrent borrow")
}

// TestClosedAtRest_EveryMethodOpensAndCloses runs each access method on a
// closed buffer. Any that touched the region without opening it would fault
// the test binary; each must also leave the page closed.
func TestClosedAtRest_EveryMethodOpensAndCloses(t *testing.T) {
	secret := []byte("closed-at-rest secret, 32 bytes!")
	buf := newClosed(t, secret)

	out := make([]byte, len(secret))
	steps := []struct {
		name string
		run  func() error
	}{
		{"WithBytesErr", func() error { return buf.WithBytesErr(func([]byte) error { return nil }) }},
		{"CopyOut", func() error {
			if _, err := buf.CopyOut(out, 0); err != nil {
				return err
			}
			if !bytes.Equal(out, secret) {
				return errors.New("CopyOut returned other bytes")
			}
			return nil
		}},
		{"ByteAt", func() error {
			b, err := buf.ByteAt(0)
			if err == nil && b != secret[0] {
				err = errors.New("ByteAt returned another byte")
			}
			return err
		}},
		{"ConstantTimeEqual", func() error {
			eq, err := buf.ConstantTimeEqual(secret)
			if err == nil && !eq {
				err = errors.New("ConstantTimeEqual = false for the contents")
			}
			return err
		}},
		{"WriteTo", func() error {
			var w bytes.Buffer
			if _, err := buf.WriteTo(&w); err != nil {
				return err
			}
			if !bytes.Equal(w.Bytes(), secret) {
				return errors.New("WriteTo wrote other bytes")
			}
			return nil
		}},
		{"SetByteAt", func() error { return buf.SetByteAt(0, 'C') }},
		{"CopyIn", func() error { _, err := buf.CopyIn([]byte("XY"), 1); return err }},
		{"ReadFrom", func() error { _, err := buf.ReadFrom(bytes.NewReader([]byte("read-from"))); return err }},
		{"ExposeString", func() error {
			s, err := buf.ExposeString() //nolint:secmem-lint // the accessor under test; test fixture, not a secret
			if err == nil && s[:9] != "read-from" {
				err = errors.New("ExposeString does not show what ReadFrom stored")
			}
			return err
		}},
		{"Truncate", func() error { return buf.Truncate(9) }},
		{"ReadOnly", buf.ReadOnly},
		{"read while read-only", func() error {
			return buf.WithBytes(func(b []byte) {
				if !bytes.Equal(b, []byte("read-from")) {
					t.Errorf("contents = %q", b) //nolint:secmem-lint // a test fixture, not a secret
				}
			})
		}},
		{"write while read-only is refused", func() error {
			if err := buf.SetByteAt(0, 1); !errors.Is(err, ErrReadOnly) {
				return errors.New("SetByteAt on a read-only buffer did not return ErrReadOnly")
			}
			return nil
		}},
		{"ReadWrite", buf.ReadWrite},
		{"Seal", buf.Seal},
		{"borrow while sealed is refused", func() error {
			if err := buf.WithBytes(func([]byte) {}); !errors.Is(err, ErrSealed) {
				return errors.New("WithBytes on a sealed buffer did not return ErrSealed")
			}
			return nil
		}},
		{"Unseal", buf.Unseal},
		{"contents survive the seal cycle", func() error {
			eq, err := buf.ConstantTimeEqual([]byte("read-from"))
			if err == nil && !eq {
				err = errors.New("contents changed across Seal and Unseal")
			}
			return err
		}},
	}
	for _, st := range steps {
		if err := st.run(); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		requireClosed(t, buf, "after "+st.name)
	}
}

// TestClosedAtRest_ClosedAfterAPanickingCallback: a callback that panics must
// not leave the buffer open, or stuck open for every later borrow.
func TestClosedAtRest_ClosedAfterAPanickingCallback(t *testing.T) {
	buf := newClosed(t, bytes.Repeat([]byte{0x5A}, 16))
	for name, borrow := range map[string]func(){
		"WithBytes":    func() { _ = buf.WithBytes(func([]byte) { panic("boom") }) },
		"WithBytesErr": func() { _ = buf.WithBytesErr(func([]byte) error { panic("boom") }) },
	} {
		func() {
			defer func() { _ = recover() }()
			borrow()
		}()
		requireClosed(t, buf, "after a panic in "+name)
		if err := buf.WithBytes(func([]byte) {}); err != nil {
			t.Fatalf("borrow after a panic in %s: %v", name, err)
		}
		requireClosed(t, buf, "after the borrow that followed a panic in "+name)
	}
}

// TestClosedAtRest_RetainedSliceFaults reads through a slice kept from a
// callback of a LIVE closed-at-rest buffer, in a child process: it has to die
// on a fault at that address.
func TestClosedAtRest_RetainedSliceFaults(t *testing.T) {
	if !probeFaulted(t, "closed_at_rest_retained") {
		t.Fatal("a read through a slice retained from a closed-at-rest buffer did not fault")
	}
}

// TestClosedAtRest_Lifecycle covers the paths that end the buffer: the
// emergency wipe refuses later borrows as for any buffer, and Destroy works
// from the closed state.
func TestClosedAtRest_Lifecycle(t *testing.T) {
	buf := newClosed(t, bytes.Repeat([]byte{0x5A}, 16))
	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}
	requireWiped(t, "WithBytes", buf.WithBytes(func([]byte) {}))
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy after the emergency wipe: %v", err)
	}

	other := newClosed(t, bytes.Repeat([]byte{0x5A}, 16))
	if err := other.Destroy(); err != nil {
		t.Fatalf("Destroy from the closed state: %v", err)
	}
	if err := other.WithBytes(func([]byte) {}); !errors.Is(err, ErrDestroyed) {
		t.Errorf("WithBytes after Destroy = %v, want ErrDestroyed", err)
	}

	if _, err := NewArena(32, 2, WithClosedAtRest()); err == nil {
		t.Error("NewArena accepted WithClosedAtRest")
	}
	plain, err := NewEmptyBuffer(16)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = plain.Destroy() }()
	if plain.Capabilities().ClosedAtRest {
		t.Error("an ordinary buffer reports ClosedAtRest")
	}
}
