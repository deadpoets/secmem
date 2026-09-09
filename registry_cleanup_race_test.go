package secmem

import (
	"bytes"
	"testing"
	"time"
)

// TestJanitorRelease_ConcurrentWithWipePass_ReclaimsMapping pins the ordering
// between the GC-cleanup release and an emergency wipe pass.
//
// The cleanup path (runtime.AddCleanup → janitor.release with lockHeld=false)
// used to consult the registry BEFORE taking the region's lock, while the wipe
// passes take the lock first. A pass that held the lock and had already
// removed the region from the live set — but not yet parked it in the wiped
// set — left a window in which the cleanup found the key in NEITHER map,
// returned nil, and was consumed for good: the pass then parked the region in
// the wiped set, where only a Destroy or that same cleanup could ever reclaim
// it. The wrapper was already unreachable (that is why the cleanup ran), so
// nothing ever unmapped the mapping — a locked, mlock-budget-consuming leak
// for the life of the process.
//
// Two changes close it, and this test needs both: the passes now move the
// region between the sets in one registry critical section, so there is no
// instant at which a live registration is in neither map; and the cleanup now
// peeks, locks, then re-resolves under its own exclusive lock, the same order
// the passes use, so it either finds the region or blocks until the pass is
// done with it.
//
// The interleaving is forced, not raced: janitorWipeTestHook parks the pass
// inside its critical section (region lock held, registry updated), and the
// cleanup's release is invoked there. Both passes are driven, because each is
// its own copy of the sequence.
func TestJanitorRelease_ConcurrentWithWipePass_ReclaimsMapping(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	for _, pass := range []struct {
		name string
		run  func(j *janitor, key uint64) error
	}{
		{"tryWipeInPlace", func(j *janitor, key uint64) error { _, err := j.tryWipeInPlace(key); return err }},
		{"wipeInPlace", func(j *janitor, key uint64) error { return j.wipeInPlace(key) }},
	} {
		t.Run(pass.name, func(t *testing.T) {
			buf, err := NewBuffer(bytes.Repeat([]byte{0x5A}, 40))
			if err != nil {
				t.Skipf("NewBuffer: %v", err)
			}
			key := buf.janitorKey

			inPass := make(chan struct{})
			resume := make(chan struct{})
			janitorWipeTestHook = func() {
				close(inPass)
				<-resume
			}
			defer func() { janitorWipeTestHook = nil }()

			passDone := make(chan error, 1)
			go func() { passDone <- pass.run(emergencyJanitor, key) }()
			<-inPass // the pass holds buf's lock and has updated the registry

			// The GC cleanup, exactly as runtime.AddCleanup invokes it. It must
			// either block on the region lock the pass holds, or find the region
			// once the pass has released it — never return with nothing done.
			relDone := make(chan error, 1)
			go func() { relDone <- emergencyJanitor.release(key, false) }()

			// Wait for the release to commit to one of its two possible
			// behaviours: queued on the lock (correct), or returned while the
			// pass still holds it (the bug: the cleanup is consumed with the
			// mapping still registered).
			var early bool
			deadline := time.Now().Add(5 * time.Second)
		wait:
			for {
				select {
				case err := <-relDone:
					early = true
					relDone <- err // put it back for the drain below
					break wait
				default:
				}
				buf.mu.mu.Lock()
				queued := buf.mu.writersWaiting >= 1
				buf.mu.mu.Unlock()
				if queued {
					break wait
				}
				if time.Now().After(deadline) {
					t.Fatal("release neither queued on the region lock nor returned")
				}
				time.Sleep(time.Millisecond)
			}

			close(resume)
			if err := <-passDone; err != nil {
				t.Errorf("wipe pass: %v", err)
			}
			if err := <-relDone; err != nil {
				t.Errorf("release: %v", err)
			}

			emergencyJanitor.mu.Lock()
			_, live := emergencyJanitor.regions[key]
			_, wiped := emergencyJanitor.wiped[key]
			emergencyJanitor.mu.Unlock()
			if live || wiped {
				t.Errorf("after the cleanup ran concurrently with the wipe pass the mapping is still registered "+
					"(live=%v wiped=%v; release returned early=%v) — the cleanup was consumed and nothing will ever unmap it",
					live, wiped, early)
				// Reclaim it so the leak does not outlive the test.
				_ = buf.Destroy()
				return
			}
			// The mapping is gone; Destroy must be an idempotent no-op now.
			if err := buf.Destroy(); err != nil {
				t.Errorf("Destroy after cleanup: %v", err)
			}
		})
	}
}
