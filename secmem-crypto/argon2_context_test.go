package secmemcrypto

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	xargon2 "golang.org/x/crypto/argon2"

	"github.com/deadpoets/secmem"
)

// armedContext ends at a chosen point inside a call, without a timer and
// without a second goroutine: its nth call to Done returns a channel that is
// already closed, and from then on Err reports Canceled. Earlier calls to
// Done return a channel that never closes.
//
// The functions under test call Done once per place they can wait, in
// order, so n picks the place: for Argon2IntoContext 1 is the derivation
// itself; for Argon2Workspace.DeriveContext 1 is the wait for the workspace
// and 2 the derivation. A cancellation that lands "somewhere during the
// call" from another goroutine would exercise one of those at random.
type armedContext struct {
	context.Context
	n     int32
	calls atomic.Int32
	ended atomic.Bool
}

func newArmedContext(n int32) *armedContext {
	return &armedContext{Context: context.Background(), n: n}
}

func (c *armedContext) Done() <-chan struct{} {
	if c.calls.Add(1) < c.n {
		return make(chan struct{})
	}
	c.ended.Store(true)
	closed := make(chan struct{})
	close(closed)
	return closed
}

func (c *armedContext) Err() error {
	if c.ended.Load() {
		return context.Canceled
	}
	return nil
}

const argon2Sentinel = 0xA5

func newSentinelBuffer(t *testing.T) *secmem.SecureBuffer {
	t.Helper()
	out := newTestBuffer(t, 32)
	if err := out.WithBytesErr(func(b []byte) error {
		for i := range b {
			b[i] = argon2Sentinel
		}
		return nil
	}); err != nil {
		skipIfLockRefused(t, err)
		t.Fatal(err)
	}
	return out
}

func requireUntouched(t *testing.T, name string, out *secmem.SecureBuffer) {
	t.Helper()
	if got := readBuf(t, out); !bytes.Equal(got, bytes.Repeat([]byte{argon2Sentinel}, len(got))) {
		t.Errorf("%s: out was written: %x", name, got)
	}
}

func requireWorkspaceZero(t *testing.T, name string, ws *Argon2Workspace) {
	t.Helper()
	var dirty bool
	_ = ws.mem.WithBytesErr(func(b []byte) error {
		for _, v := range b {
			if v != 0 {
				dirty = true
				break
			}
		}
		return nil
	})
	if dirty {
		t.Errorf("%s: the workspace region holds residue", name)
	}
}

// within fails the test when f has not returned in a generous time, so a
// call that is supposed to stop waiting and does not shows up as a failure
// and not as a hung test binary.
func within(t *testing.T, name string, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: still blocked after 30s", name)
		return nil
	}
}

var (
	ctxTestPassword = []byte("password")
	ctxTestSalt     = []byte("0123456789abcdef")
)

// TestArgon2Workspace_DeriveContextCancelledMidDerivation ends the context
// after the workspace has been acquired, so the derivation itself is what
// gets abandoned: the error is the context's, out is untouched, the locked
// region is zero, and the same workspace then derives the right bytes.
//
// Time is 3, so there are twelve slice boundaries and the first one stops
// it. The control is the same call on a context that never ends, which must
// write the tag: an implementation that never wrote out would pass
// otherwise.
func TestArgon2Workspace_DeriveContextCancelledMidDerivation(t *testing.T) {
	ws := newWorkspaceOrSkip(t, wsTestMemory, wsTestThreads)
	p := Argon2Params{Time: 3, Memory: wsTestMemory, Threads: wsTestThreads}
	want := xargon2.IDKey(ctxTestPassword, ctxTestSalt, p.Time, p.Memory, p.Threads, 32)

	control := newSentinelBuffer(t)
	if err := ws.DeriveContext(context.Background(), ctxTestPassword, ctxTestSalt, p, control); err != nil {
		skipIfLockRefused(t, err)
		t.Fatalf("control: %v", err)
	}
	if got := readBuf(t, control); !bytes.Equal(got, want) {
		t.Fatalf("control failed: a context that never ends gave %x, want %x", got, want)
	}

	out := newSentinelBuffer(t)
	ctx := newArmedContext(2)
	err := ws.DeriveContext(ctx, ctxTestPassword, ctxTestSalt, p, out)
	if !errors.Is(err, context.Canceled) {
		skipIfLockRefused(t, err)
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := ctx.calls.Load(); n != 2 {
		t.Fatalf("Done was called %d times, want 2: the context did not end where this test means it to", n)
	}
	requireUntouched(t, "cancelled", out)
	requireWorkspaceZero(t, "cancelled", ws)

	if err := ws.Derive(ctxTestPassword, ctxTestSalt, p, out); err != nil {
		skipIfLockRefused(t, err)
		t.Fatalf("Derive after a cancelled one: %v", err)
	}
	if got := readBuf(t, out); !bytes.Equal(got, want) {
		t.Errorf("Derive after a cancelled one: %x, want %x", got, want)
	}
}

// TestArgon2Workspace_DeriveContextLeavesTheQueue holds the workspace the
// way a derivation in flight does and requires a queued DeriveContext to
// return when its context ends. Before the semaphore the wait was a
// sync.Mutex and this call could only return when the holder finished.
func TestArgon2Workspace_DeriveContextLeavesTheQueue(t *testing.T) {
	ws := newWorkspaceOrSkip(t, wsTestMemory, wsTestThreads)
	p := Argon2Params{Time: 1, Memory: wsTestMemory, Threads: wsTestThreads}
	out := newSentinelBuffer(t)

	ws.busy <- struct{}{} // a derivation is in flight
	held := true
	release := func() {
		if held {
			held = false
			<-ws.busy
		}
	}
	// Registered after the workspace's own cleanup, so it runs first: a
	// failure above must not leave Destroy waiting on the hold.
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(context.Background())
	queued := make(chan error, 1)
	go func() { queued <- ws.DeriveContext(ctx, ctxTestPassword, ctxTestSalt, p, out) }()
	select {
	case err := <-queued:
		t.Fatalf("control failed: DeriveContext returned %v while the workspace was held", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	err := within(t, "queued DeriveContext after cancel", func() error { return <-queued })
	if !errors.Is(err, context.Canceled) {
		skipIfLockRefused(t, err)
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	requireUntouched(t, "left the queue", out)
	release() // the in-flight derivation ends

	if err := within(t, "Derive after release", func() error { return ws.Derive(ctxTestPassword, ctxTestSalt, p, out) }); err != nil {
		skipIfLockRefused(t, err)
		t.Fatalf("Derive after the queue emptied: %v", err)
	}
	if err := within(t, "Destroy", ws.Destroy); err != nil {
		skipIfLockRefused(t, err)
		t.Fatalf("Destroy: %v", err)
	}
}

// TestArgon2Pool_DeriveContextLeavesTheQueue drains the pool and requires a
// waiting DeriveContext to return when its context ends, leaving the pool
// balanced: the workspace goes back, a later Derive succeeds, and Destroy,
// which takes every workspace back, does not hang.
func TestArgon2Pool_DeriveContextLeavesTheQueue(t *testing.T) {
	pool, err := NewArgon2Pool(1, wsTestMemory, wsTestThreads)
	if err != nil {
		t.Skipf("NewArgon2Pool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Destroy() })
	p := Argon2Params{Time: 1, Memory: wsTestMemory, Threads: wsTestThreads}
	out := newSentinelBuffer(t)

	held := <-pool.free // every workspace is busy
	release := func() {
		if held != nil {
			pool.free <- held
			held = nil
		}
	}
	t.Cleanup(release) // before the pool's Destroy, which takes every workspace back
	ctx, cancel := context.WithCancel(context.Background())
	queued := make(chan error, 1)
	go func() { queued <- pool.DeriveContext(ctx, ctxTestPassword, ctxTestSalt, p, out) }()
	select {
	case err := <-queued:
		t.Fatalf("control failed: DeriveContext returned %v while the pool was empty", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	err = within(t, "queued DeriveContext after cancel", func() error { return <-queued })
	if !errors.Is(err, context.Canceled) {
		skipIfLockRefused(t, err)
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	requireUntouched(t, "left the queue", out)
	release()

	if err := within(t, "Derive after release", func() error { return pool.Derive(ctxTestPassword, ctxTestSalt, p, out) }); err != nil {
		skipIfLockRefused(t, err)
		t.Fatalf("Derive after the queue emptied: %v", err)
	}
	want := xargon2.IDKey(ctxTestPassword, ctxTestSalt, p.Time, p.Memory, p.Threads, 32)
	if got := readBuf(t, out); !bytes.Equal(got, want) {
		t.Errorf("Derive after the queue emptied: %x, want %x", got, want)
	}
	if err := within(t, "Destroy", pool.Destroy); err != nil {
		skipIfLockRefused(t, err)
		t.Fatalf("Destroy: %v", err)
	}
}

// TestArgon2Workspace_DeriveContextEndedBeforeTheCall covers the three entry
// points with a context that has already ended, and with none at all.
func TestArgon2Workspace_DeriveContextEndedBeforeTheCall(t *testing.T) {
	ws := newWorkspaceOrSkip(t, wsTestMemory, wsTestThreads)
	pool, err := NewArgon2Pool(1, wsTestMemory, wsTestThreads)
	if err != nil {
		t.Skipf("NewArgon2Pool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Destroy() })
	p := Argon2Params{Time: 1, Memory: wsTestMemory, Threads: wsTestThreads}

	ended, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel2 := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel2()
	var none context.Context

	calls := map[string]func(context.Context, *secmem.SecureBuffer) error{
		"Argon2IntoContext": func(ctx context.Context, out *secmem.SecureBuffer) error {
			return Argon2IntoContext(ctx, ctxTestPassword, ctxTestSalt, p, out)
		},
		"Workspace.DeriveContext": func(ctx context.Context, out *secmem.SecureBuffer) error {
			return ws.DeriveContext(ctx, ctxTestPassword, ctxTestSalt, p, out)
		},
		"Pool.DeriveContext": func(ctx context.Context, out *secmem.SecureBuffer) error {
			return pool.DeriveContext(ctx, ctxTestPassword, ctxTestSalt, p, out)
		},
	}
	for name, call := range calls {
		out := newSentinelBuffer(t)
		if err := call(ended, out); !errors.Is(err, context.Canceled) {
			skipIfLockRefused(t, err)
			t.Errorf("%s, cancelled: err = %v, want context.Canceled", name, err)
		}
		if err := call(expired, out); !errors.Is(err, context.DeadlineExceeded) {
			skipIfLockRefused(t, err)
			t.Errorf("%s, expired: err = %v, want context.DeadlineExceeded", name, err)
		}
		if err := call(none, out); err == nil {
			t.Errorf("%s, nil context: no error", name)
		}
		requireUntouched(t, name, out)
	}
	requireWorkspaceZero(t, "after refused calls", ws)
}

// TestArgon2Workspace_IntoContextCancelledMidDerivation is the heap path's
// version of the mid-derivation test: Argon2IntoContext has no queue, so the
// first Done it asks for is the derivation's.
func TestArgon2Workspace_IntoContextCancelledMidDerivation(t *testing.T) {
	p := Argon2Params{Time: 3, Memory: wsTestMemory, Threads: wsTestThreads}
	want := xargon2.IDKey(ctxTestPassword, ctxTestSalt, p.Time, p.Memory, p.Threads, 32)

	control := newSentinelBuffer(t)
	if err := Argon2IntoContext(context.Background(), ctxTestPassword, ctxTestSalt, p, control); err != nil {
		skipIfLockRefused(t, err)
		t.Fatalf("control: %v", err)
	}
	if got := readBuf(t, control); !bytes.Equal(got, want) {
		t.Fatalf("control failed: a context that never ends gave %x, want %x", got, want)
	}

	out := newSentinelBuffer(t)
	ctx := newArmedContext(1)
	if err := Argon2IntoContext(ctx, ctxTestPassword, ctxTestSalt, p, out); !errors.Is(err, context.Canceled) {
		skipIfLockRefused(t, err)
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := ctx.calls.Load(); n != 1 {
		t.Fatalf("Done was called %d times, want 1", n)
	}
	requireUntouched(t, "cancelled", out)
}
