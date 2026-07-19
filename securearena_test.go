package secmem

import (
	"bytes"
	"errors"
	"math"
	"math/rand/v2"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNewArena_Basic(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 8)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	if a.SlotSize() != 32 {
		t.Errorf("SlotSize = %d, want 32", a.SlotSize())
	}
	if a.Cap() != 8 {
		t.Errorf("Cap = %d, want 8", a.Cap())
	}
	if a.LiveCount() != 0 {
		t.Errorf("LiveCount = %d, want 0", a.LiveCount())
	}
	if a.IsDestroyed() {
		t.Error("IsDestroyed = true, want false immediately after create")
	}
}

func TestNewArena_InvalidArgs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		slotSize int
		count    int
	}{
		{"zero slotSize", 0, 4},
		{"negative slotSize", -1, 4},
		{"zero count", 32, 0},
		{"negative count", 32, -1},
		{"overflow slotSize*count", math.MaxInt/2 + 1, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewArena(tt.slotSize, tt.count)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Acquire / Release
// ---------------------------------------------------------------------------

func TestArena_AcquireReleaseCycle(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 4)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	slot, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if !slot.IsLive() {
		t.Error("slot.IsLive() = false immediately after Acquire")
	}
	if a.LiveCount() != 1 {
		t.Errorf("LiveCount = %d, want 1", a.LiveCount())
	}

	if err := slot.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if slot.IsLive() {
		t.Error("slot.IsLive() = true after Release")
	}
	if a.LiveCount() != 0 {
		t.Errorf("LiveCount after Release = %d, want 0", a.LiveCount())
	}
}

func TestArena_ReleaseIdempotent(t *testing.T) {
	t.Parallel()
	a, err := NewArena(16, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	slot, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := slot.Release(); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	// Second Release must be a no-op — not an error.
	if err := slot.Release(); err != nil {
		t.Errorf("second Release (idempotent) returned error: %v", err)
	}
}

func TestArena_AcquireFull(t *testing.T) {
	t.Parallel()
	const maxCap = 4
	a, err := NewArena(32, maxCap)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	slots := make([]*ArenaSlot, maxCap)
	for i := range maxCap {
		s, acqErr := a.Acquire()
		if acqErr != nil {
			t.Fatalf("Acquire %d: %v", i, acqErr)
		}
		slots[i] = s
	}

	// One more must fail with ErrArenaFull.
	_, err = a.Acquire()
	if !errors.Is(err, ErrArenaFull) {
		t.Errorf("Acquire on full arena = %v, want ErrArenaFull", err)
	}

	// Release one → Acquire succeeds again.
	if relErr := slots[0].Release(); relErr != nil {
		t.Fatalf("Release: %v", relErr)
	}
	s, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire after release: %v", err)
	}
	_ = s.Release()
	for _, sl := range slots[1:] {
		_ = sl.Release()
	}
}

func TestArena_SlotIndexStable(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 3)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	s0, _ := a.Acquire()
	s1, _ := a.Acquire()
	s2, _ := a.Acquire()

	if s0.Index() != 0 || s1.Index() != 1 || s2.Index() != 2 {
		t.Errorf("indices = %d,%d,%d, want 0,1,2", s0.Index(), s1.Index(), s2.Index())
	}
	_ = s0.Release()
	_ = s1.Release()
	_ = s2.Release()
}

// ---------------------------------------------------------------------------
// WithBytes / WithBytesErr
// ---------------------------------------------------------------------------

func TestArena_WithBytesRoundTrip(t *testing.T) {
	t.Parallel()
	a, err := NewArena(16, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	payload := []byte("hello, arena!!")
	if len(payload) != 14 {
		t.Fatal("payload length unexpected")
	}

	slot, _ := a.Acquire()
	defer func() { _ = slot.Release() }()

	err = slot.WithBytesErr(func(b []byte) error {
		copy(b, payload)
		return nil
	})
	if err != nil {
		t.Fatalf("WithBytesErr write: %v", err)
	}

	var out [16]byte
	err = slot.WithBytesErr(func(b []byte) error {
		copy(out[:], b) //nolint:secmem-lint // test assertion copies borrowed bytes into a stack array for comparison.
		return nil
	})
	if err != nil {
		t.Fatalf("WithBytesErr read: %v", err)
	}

	if !bytes.Equal(out[:len(payload)], payload) {
		t.Errorf("read back %q, want %q", out[:len(payload)], payload)
	}
}

func TestArena_WithBytesAfterRelease(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	slot, _ := a.Acquire()
	_ = slot.Release()

	err = slot.WithBytesErr(func([]byte) error { return nil })
	if !errors.Is(err, ErrSlotReleased) {
		t.Errorf("WithBytesErr on released slot = %v, want ErrSlotReleased", err)
	}
}

func TestArena_WithBytesErrorPropagated(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	sentinel := errors.New("test sentinel")
	slot, _ := a.Acquire()
	defer func() { _ = slot.Release() }()

	err = slot.WithBytesErr(func([]byte) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Errorf("WithBytesErr = %v, want sentinel", err)
	}
}

func TestArena_WithBytesSlotSizeEnforced(t *testing.T) {
	t.Parallel()
	a, err := NewArena(8, 3)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	s0, _ := a.Acquire()
	s1, _ := a.Acquire()
	defer func() { _ = s0.Release(); _ = s1.Release() }()

	// Fill s0 with 0xAA.
	_ = s0.WithBytesErr(func(b []byte) error {
		for i := range b {
			b[i] = 0xAA
		}
		return nil
	})

	// Fill s1 with 0xBB.
	_ = s1.WithBytesErr(func(b []byte) error {
		for i := range b {
			b[i] = 0xBB
		}
		return nil
	})

	// Verify s0 is unaffected by s1's write.
	_ = s0.WithBytesErr(func(b []byte) error {
		for i, v := range b {
			if v != 0xAA {
				t.Errorf("s0[%d] = 0x%02X after s1 write, want 0xAA", i, v)
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Wipe on Release
// ---------------------------------------------------------------------------

func TestArena_ReleaseWipesSlot(t *testing.T) {
	t.Parallel()
	const slotSize = 32
	a, err := NewArena(slotSize, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	slot, _ := a.Acquire()
	idx := slot.Index()

	_ = slot.WithBytesErr(func(b []byte) error {
		for i := range b {
			b[i] = 0xFF
		}
		return nil
	})

	_ = slot.Release()

	// Re-acquire the same index.
	slot2, err := a.Acquire()
	if err != nil {
		t.Fatalf("re-Acquire: %v", err)
	}
	if slot2.Index() != idx {
		t.Skipf("different slot index assigned (%d != %d) — skip wipe check", slot2.Index(), idx)
	}
	defer func() { _ = slot2.Release() }()

	_ = slot2.WithBytesErr(func(b []byte) error {
		for i, v := range b {
			if v != 0x00 {
				t.Errorf("slot[%d] = 0x%02X after Release, want 0x00 (wiped)", i, v)
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Destroy
// ---------------------------------------------------------------------------

func TestArena_DestroyIdempotent(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 4)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}

	if err := a.Destroy(); err != nil {
		t.Fatalf("first Destroy: %v", err)
	}
	if !a.IsDestroyed() {
		t.Error("IsDestroyed = false after Destroy")
	}
	if err := a.Destroy(); err != nil {
		t.Errorf("second Destroy (idempotent) returned error: %v", err)
	}
}

func TestArena_AcquireAfterDestroy(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 4)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	_ = a.Destroy()

	_, err = a.Acquire()
	if !errors.Is(err, ErrArenaDestroyed) {
		t.Errorf("Acquire after Destroy = %v, want ErrArenaDestroyed", err)
	}
}

func TestArena_WithBytesAfterDestroy(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}

	slot, _ := a.Acquire()
	_ = a.Destroy()

	err = slot.WithBytesErr(func([]byte) error { return nil })
	if !errors.Is(err, ErrArenaDestroyed) {
		t.Errorf("WithBytesErr after Destroy = %v, want ErrArenaDestroyed", err)
	}
}

// ---------------------------------------------------------------------------
// Nil receivers
// ---------------------------------------------------------------------------

func TestArena_NilReceiverSafe(t *testing.T) {
	t.Parallel()
	var a *SecureArena

	if err := a.Destroy(); err != nil {
		t.Errorf("nil Destroy: %v", err)
	}
	if !a.IsDestroyed() {
		t.Error("nil IsDestroyed = false, want true")
	}
	if a.Cap() != 0 {
		t.Errorf("nil Cap = %d, want 0", a.Cap())
	}
	if a.SlotSize() != 0 {
		t.Errorf("nil SlotSize = %d, want 0", a.SlotSize())
	}
	if a.LiveCount() != 0 {
		t.Errorf("nil LiveCount = %d, want 0", a.LiveCount())
	}
	_, err := a.Acquire()
	if !errors.Is(err, ErrArenaDestroyed) {
		t.Errorf("nil Acquire = %v, want ErrArenaDestroyed", err)
	}
}

func TestArenaSlot_NilReceiverSafe(t *testing.T) {
	t.Parallel()
	var s *ArenaSlot

	if s.IsLive() {
		t.Error("nil ArenaSlot.IsLive() = true, want false")
	}
	if s.Index() != -1 {
		t.Errorf("nil ArenaSlot.Index() = %d, want -1", s.Index())
	}
	if err := s.Release(); err != nil {
		t.Errorf("nil ArenaSlot.Release() = %v, want nil", err)
	}
	if err := s.WithBytes(func([]byte) {}); !errors.Is(err, ErrSlotReleased) {
		t.Errorf("nil ArenaSlot.WithBytes() = %v, want ErrSlotReleased", err)
	}
}

// ---------------------------------------------------------------------------
// Concurrency — synctest
// ---------------------------------------------------------------------------

// TestArena_ConcurrentAcquireRelease verifies that N goroutines can each
// acquire+use+release a slot without data races or LiveCount errors.
func TestArena_ConcurrentAcquireRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			slotSize = 32
			maxCap   = 8
		)
		a, err := NewArena(slotSize, maxCap)
		if err != nil {
			t.Fatalf("NewArena: %v", err)
		}
		defer func() { _ = a.Destroy() }()

		var wg sync.WaitGroup
		for i := range maxCap {
			//nolint:revive // waitgroup wrapper unavailable
			wg.Add(1)
			go func(id byte) {
				defer wg.Done()
				slot, err := a.Acquire()
				if err != nil {
					t.Errorf("Acquire: %v", err)
					return
				}
				_ = slot.WithBytesErr(func(b []byte) error {
					for j := range b {
						b[j] = id
					}
					return nil
				})
				// Read back and verify.
				_ = slot.WithBytesErr(func(b []byte) error {
					for j, v := range b {
						if v != id {
							t.Errorf("goroutine %d: slot[%d] = 0x%02X, want 0x%02X", id, j, v, id)
						}
					}
					return nil
				})
				_ = slot.Release()
			}(byte(i + 1))
		}
		wg.Wait()

		if got := a.LiveCount(); got != 0 {
			t.Errorf("LiveCount after all releases = %d, want 0", got)
		}
	})
}

// TestArena_DestroyRacesRelease verifies that Destroy and concurrent Release
// do not deadlock or panic (Destroy drains in-flight rLocks before munmap).
func TestArena_DestroyRacesRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, err := NewArena(32, 4)
		if err != nil {
			t.Fatalf("NewArena: %v", err)
		}

		slot, err := a.Acquire()
		if err != nil {
			t.Fatalf("Acquire: %v", err)
		}

		// Goroutine holds a WithBytesErr callback open while Destroy races.
		leave := make(chan struct{})
		go func() {
			_ = slot.WithBytesErr(func(_ []byte) error {
				<-leave // durably blocked — Destroy must wait for this to drain
				return nil
			})
		}()

		synctest.Wait() // goroutine is durably blocked on <-leave

		// Destroy must not deadlock — it will block on mu.lock until callback drains.
		destroyDone := make(chan struct{})
		go func() {
			_ = a.Destroy()
			close(destroyDone)
		}()

		synctest.Wait() // Destroy goroutine is now blocked on mu.lock (durably).

		// Let the callback goroutine exit — Destroy will then proceed.
		close(leave)
		synctest.Wait()

		<-destroyDone
		if !a.IsDestroyed() {
			t.Error("IsDestroyed = false after Destroy")
		}
	})
}

// ---------------------------------------------------------------------------
// GC leaf-struct property (documentation test)
// ---------------------------------------------------------------------------

// arenaSlotSize returns the size of slotMeta in bytes.
// Used to verify the cache-line padding in tests.
func arenaSlotSize() uintptr {
	return unsafe.Sizeof(slotMeta{})
}

// TestArena_SlotStructSize verifies that slotMeta is exactly 64 bytes —
// one cache line — confirming the pointer-free leaf and padding invariants.
func TestArena_SlotStructSize(t *testing.T) {
	t.Parallel()
	const want = 64
	if got := int(arenaSlotSize()); got != want {
		t.Errorf("slotMeta size = %d bytes, want %d (one cache line)", got, want)
	}
}

// TestArena_MappedLenIsPageAligned confirms the slab is page-rounded.
func TestArena_MappedLenIsPageAligned(t *testing.T) {
	t.Parallel()
	a, err := NewArena(1, 1) // minimal: 1-byte slot, 1 slot
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	// The raw slab must be a multiple of the OS page size.
	pageSize := 4096 // minimum on all supported platforms
	if len(a.region.inner)%pageSize != 0 {
		t.Errorf("slab inner len %d is not page-aligned (page size %d)", len(a.region.inner), pageSize)
	}
}

// ---------------------------------------------------------------------------
// ReadOnly / ReadWrite coverage (finding CQ-P1-RWTEST)
// ---------------------------------------------------------------------------

func TestArena_ReadOnlyReadWrite(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	if err := a.ReadOnly(); err != nil {
		t.Errorf("ReadOnly on live arena: %v", err)
	}
	if err := a.ReadWrite(); err != nil {
		t.Errorf("ReadWrite on live arena: %v", err)
	}

	_ = a.Destroy()

	if err := a.ReadOnly(); !errors.Is(err, ErrArenaDestroyed) {
		t.Errorf("ReadOnly after Destroy = %v, want ErrArenaDestroyed", err)
	}
	if err := a.ReadWrite(); !errors.Is(err, ErrArenaDestroyed) {
		t.Errorf("ReadWrite after Destroy = %v, want ErrArenaDestroyed", err)
	}
}

func TestArena_NilReadOnlyReadWrite(t *testing.T) {
	t.Parallel()
	var a *SecureArena
	if err := a.ReadOnly(); err == nil {
		t.Error("nil ReadOnly: want non-nil error, got nil")
	}
	if err := a.ReadWrite(); err == nil {
		t.Error("nil ReadWrite: want non-nil error, got nil")
	}
}

// TestArena_ReleaseWhileReadOnlyRefusesInsteadOfFaulting is the named
// regression for the arena analog of the SecureBuffer read-only bug: Release
// wipes the slot (a write), and before the fix that write hit the PROT_READ
// slab set by ReadOnly() and crashed the process with SIGSEGV. Release now
// returns ErrReadOnly instead — no fault, and the frozen slab is left intact.
// ReadWrite lifts the restriction so the slot releases cleanly.
func TestArena_ReleaseWhileReadOnlyRefusesInsteadOfFaulting(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	slot, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := slot.WithBytes(func(b []byte) { b[0] = 0xAB }); err != nil {
		t.Fatalf("WithBytes while writable: %v", err)
	}

	if err := a.ReadOnly(); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}

	// Release must refuse rather than fault, and must NOT return the slot to
	// the pool (it was not wiped).
	if err := slot.Release(); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Release while read-only = %v, want ErrReadOnly", err)
	}
	if !slot.IsLive() {
		t.Error("slot returned to the pool despite a refused (un-wiped) Release")
	}
	if got := a.LiveCount(); got != 1 {
		t.Errorf("LiveCount after refused Release = %d, want 1", got)
	}
	// A read still works while read-only (PROT_READ permits reads).
	if err := slot.WithBytes(func(b []byte) {
		if b[0] != 0xAB {
			t.Errorf("slot contents = %#x, want 0xAB", b[0])
		}
	}); err != nil {
		t.Errorf("WithBytes while read-only should succeed, got %v", err)
	}

	// ReadWrite lifts the restriction; the slot then releases cleanly.
	if err := a.ReadWrite(); err != nil {
		t.Fatalf("ReadWrite: %v", err)
	}
	if err := slot.Release(); err != nil {
		t.Errorf("Release after ReadWrite = %v, want nil", err)
	}
	if got := a.LiveCount(); got != 0 {
		t.Errorf("LiveCount after successful Release = %d, want 0", got)
	}
}

// TestArena_DestroyWhileReadOnly confirms Destroy needs no ReadWrite first: its
// wipe path makes the slab writable before zeroing, so destroying a read-only
// arena with a live slot completes without faulting.
func TestArena_DestroyWhileReadOnly(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	if _, err := a.Acquire(); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := a.ReadOnly(); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}
	if err := a.Destroy(); err != nil {
		t.Fatalf("Destroy of a read-only arena: %v", err)
	}
	if !a.IsDestroyed() {
		t.Error("arena not reported destroyed")
	}
}

// TestArena_ConcurrentReadOnlyRelease races slot Release against ReadOnly/
// ReadWrite on a shared arena — the concurrent form of the fault that
// TestArena_ReleaseWhileReadOnlyRefusesInsteadOfFaulting covers sequentially.
// A Release that lands during a read-only window must refuse (ErrReadOnly), not
// fault on the slot wipe; workers retry through the window. Run under -race for
// the data-race half: Release reads a.readOnly under rLock while ReadOnly sets
// it under the exclusive lock. The invariant is simply "no fault, no race, no
// panic" — a storm that returns from Wait has held it.
func TestArena_ConcurrentReadOnlyRelease(t *testing.T) {
	a, err := NewArena(16, 8)
	if err != nil {
		t.Skipf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	// Toggler: flip the whole slab read-only/read-write until told to stop, then
	// leave it writable so the deferred Destroy wipes without contention.
	stop := make(chan struct{})
	togglerDone := make(chan struct{})
	go func() {
		defer close(togglerDone)
		r := rand.New(rand.NewPCG(99, 0x9e3779b9))
		for {
			select {
			case <-stop:
				_ = a.ReadWrite()
				return
			default:
			}
			if r.IntN(2) == 0 {
				_ = a.ReadOnly()
			} else {
				_ = a.ReadWrite()
			}
			runtime.Gosched()
		}
	}()

	const (
		workers = 6
		iters   = 2000
	)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(w)+1, 0x2545F4914F6CDD1D))
			for range iters {
				slot, err := a.Acquire()
				if err != nil { // ErrArenaFull while others hold slots — fine
					runtime.Gosched()
					continue
				}
				_ = slot.WithBytes(func(b []byte) {
					if len(b) > 0 {
						_ = b[0]
					}
				})
				_ = r.IntN(2) // keep the RNG advancing between slots
				// Release, retrying through read-only windows. If it never wins,
				// the slot is reclaimed by Destroy — the point is that Release
				// never faults, only refuses.
				for range 100 {
					if !errors.Is(slot.Release(), ErrReadOnly) {
						break
					}
					runtime.Gosched()
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	<-togglerDone

	// After the storm the arena is writable and still works.
	if err := a.ReadWrite(); err != nil {
		t.Fatalf("ReadWrite after stress: %v", err)
	}
	slot, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire after stress: %v", err)
	}
	if err := slot.Release(); err != nil {
		t.Fatalf("Release after stress: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ABA generation guard (finding CQ-P0-ABA)
// ---------------------------------------------------------------------------

// TestArenaSlot_GenerationGuard verifies that a stale ArenaSlot handle
// (retained after Release + re-Acquire) cannot access the re-acquired slot's
// data. Without generation tracking, WithBytesErr would incorrectly succeed on
// the old handle because inUse == 1 (re-acquired by new owner).
func TestArenaSlot_GenerationGuard(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 1) // single slot — ensures same index is re-used
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	// Acquire, then release the slot.
	old, err := a.Acquire()
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if releaseErr := old.Release(); releaseErr != nil {
		t.Fatalf("Release: %v", releaseErr)
	}

	// Re-acquire the same slot — new owner.
	newSlot, err := a.Acquire()
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	defer func() { _ = newSlot.Release() }()

	// The old handle must now fail — it should not be able to read the new
	// owner's data.
	err = old.WithBytesErr(func([]byte) error { return nil })
	if !errors.Is(err, ErrSlotReleased) {
		t.Errorf("stale slot WithBytesErr = %v, want ErrSlotReleased (generation guard)", err)
	}
}
