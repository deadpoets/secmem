//go:build unix

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// afterSuspend returns now as a clock reads it once the machine has slept
// for asleep: the wall clock that much later, the monotonic reading where it
// was, because the monotonic clock Go reads does not run during a suspend.
// No time API builds such a value (every one that moves the wall clock moves
// or drops the monotonic reading with it), so this adds whole seconds to the
// seconds field of Time's first word, bits 30 to 62 while a monotonic
// reading is present. checkAfterSuspend pins that this is what it did.
func afterSuspend(now time.Time, asleep time.Duration) time.Time {
	//nolint:gosec // G103, G115: test-only edit of a time.Time, checked by checkAfterSuspend; asleep is a positive constant.
	*(*uint64)(unsafe.Pointer(&now)) += uint64(asleep/time.Second) << 30
	return now
}

// checkAfterSuspend fails the test if time.Time's layout has changed under
// afterSuspend: the result must be asleep later on the wall clock and no
// later at all on the monotonic one.
func checkAfterSuspend(t *testing.T, asleep time.Duration) {
	t.Helper()
	now := time.Now()
	woke := afterSuspend(now, asleep)
	if wall := woke.Round(0).Sub(now.Round(0)); wall != asleep {
		t.Fatalf("afterSuspend moved the wall clock by %v, want %v: time.Time's layout has changed", wall, asleep)
	}
	if mono := woke.Sub(now); mono != 0 {
		t.Fatalf("afterSuspend moved the monotonic reading by %v, want 0: time.Time's layout has changed", mono)
	}
}

// TestConstraint_Lifetime_IsWallClockAcrossSuspend proves an ssh-add -t
// deadline is a wall-clock one. A laptop that sleeps through the deadline
// wakes with its monotonic clock still short of it; the key must be
// destroyed at the first request after resume all the same, not serve for
// the awake time that was left.
func TestConstraint_Lifetime_IsWallClockAcrossSuspend(t *testing.T) {
	const asleep = 8 * time.Hour
	checkAfterSuspend(t, asleep)

	// Registered before startAgent so it runs after the server has stopped
	// (see startServer): no connection goroutine reads timeNow past this.
	var suspended atomic.Bool
	t.Cleanup(func() { timeNow = time.Now })
	timeNow = func() time.Time {
		if suspended.Load() {
			return afterSuspend(time.Now(), asleep)
		}
		return time.Now()
	}

	client, keyring := startAgent(t)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, _ := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err := client.Add(agent.AddedKey{PrivateKey: priv, Comment: "one hour", LifetimeSecs: 3600}); err != nil {
		t.Fatalf("constrained Add: %v", err)
	}
	keyring.mu.Lock()
	if len(keyring.keys) != 1 {
		keyring.mu.Unlock()
		t.Fatalf("expected 1 key, got %d", len(keyring.keys))
	}
	buf := keyring.keys[0].keyBuf
	keyring.mu.Unlock()

	// Control: awake and inside the hour, the key signs.
	if _, err := client.Sign(pub, []byte("before the lid closes")); err != nil {
		t.Fatalf("sign before the deadline: %v", err)
	}

	// Eight hours asleep: seven past the deadline on the wall clock, and
	// nearly the whole hour still to run on the monotonic one.
	suspended.Store(true)
	if _, err := client.Sign(pub, []byte("after resume")); err == nil {
		t.Error("signed with a key whose deadline passed 7h ago on the wall clock")
	}
	if !buf.IsDestroyed() {
		t.Error("the expired key's SecureBuffer was not destroyed at the first request after resume")
	}
}
