package secmem

import (
	"bytes"
	"errors"
	"testing"
)

// TestJanitorRegister_RefusesKeyCollision pins two things about registration
// identity: the key is 64 bits wide all the way through, and a collision is
// refused rather than absorbed.
//
// The key was minted as uintptr(counter). On a 32-bit target that truncation
// wraps after 2^32 registrations, and the next register silently overwrote a
// live entry: from then on the older buffer's Destroy resolved its key to the
// NEWER buffer's mapping and wiped and unmapped it, with no lock held on it,
// while the older mapping leaked. The counter is uint64 now and cannot wrap
// in practice, but register also checks: a minted key that is already in
// either set is an error, and the live registration is left untouched.
//
// The collision is injected by winding the counter back to just before a
// live buffer's key, so the next mint reproduces it. The counter is global,
// so the window in which it is wound back is kept to one constructor call
// and restored immediately after.
func TestJanitorRegister_RefusesKeyCollision(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	secret := bytes.Repeat([]byte{0x5A}, 32)
	live, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	defer func() { _ = live.Destroy() }()
	key := live.janitorKey
	if key == 0 {
		t.Fatal("live buffer has a zero janitor key")
	}
	if got := live.LockOrder(); got != key {
		t.Fatalf("LockOrder() = %d, want the janitor key %d", got, key)
	}

	// Wind the counter back so the next mint collides with the live key.
	saved := nextJanitorKey.Load()
	nextJanitorKey.Store(key - 1)
	dup, err := NewBuffer(append([]byte(nil), secret...))
	// Restore before anything else can mint: whatever happened, the counter
	// must not hand out keys below the ones already in use.
	if cur := nextJanitorKey.Load(); cur < saved {
		nextJanitorKey.Store(saved)
	}
	if err == nil {
		_ = dup.Destroy()
		t.Fatal("NewBuffer succeeded with a colliding janitor key")
	}
	if !errors.Is(err, errJanitorKeyCollision) {
		t.Fatalf("NewBuffer error = %v, want errJanitorKeyCollision", err)
	}

	// The live registration was not overwritten: it still resolves to the
	// live buffer's own lock, and the buffer still holds its secret.
	emergencyJanitor.mu.Lock()
	reg, ok := emergencyJanitor.regions[key]
	emergencyJanitor.mu.Unlock()
	if !ok {
		t.Fatal("live registration disappeared after a refused collision")
	}
	if reg.mu != live.mu {
		t.Fatal("live registration was overwritten by the colliding registration")
	}
	if err := live.WithBytes(func(b []byte) {
		if !bytes.Equal(b, secret) {
			t.Errorf("live buffer = %x…, want %x…", b[:4], secret[:4]) //nolint:secmem-lint // diagnostic on failure only; test fixture, not a secret
		}
	}); err != nil {
		t.Fatalf("live.WithBytes: %v", err)
	}

	// And the counter is back where it was: a fresh registration gets a
	// fresh key, above every key handed out so far.
	fresh, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("NewBuffer(fresh): %v", err)
	}
	defer func() { _ = fresh.Destroy() }()
	if fresh.janitorKey <= key {
		t.Errorf("fresh key %d is not above the live key %d", fresh.janitorKey, key)
	}
}

// TestJanitorRegister_RefusesZeroKey pins the reserved zero: a janitorKey of 0
// means "never registered" everywhere (LockOrder on a nil buffer, the
// arena's zero value), so the mint must never produce it — which after a
// full wrap it would.
func TestJanitorRegister_RefusesZeroKey(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	saved := nextJanitorKey.Load()
	nextJanitorKey.Store(^uint64(0)) // the next Add(1) wraps to 0
	buf, err := NewBuffer(bytes.Repeat([]byte{0x5A}, 32))
	if cur := nextJanitorKey.Load(); cur < saved {
		nextJanitorKey.Store(saved)
	}
	if err == nil {
		_ = buf.Destroy()
		t.Fatal("NewBuffer succeeded with janitor key 0")
	}
	if !errors.Is(err, errJanitorKeyCollision) {
		t.Fatalf("NewBuffer error = %v, want errJanitorKeyCollision", err)
	}
}
