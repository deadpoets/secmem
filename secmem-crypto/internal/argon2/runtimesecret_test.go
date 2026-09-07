//go:build goexperiment.runtimesecret && linux && (amd64 || arm64)

package argon2

import (
	"runtime/secret"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/deadpoets/secmem"
)

// TestWorkersRunInsideSecretDo proves the load-bearing claim of the worker
// design on the one platform where it can be observed: each worker
// goroutine's Scrub window is a real runtime/secret window, so the runtime
// erases the worker's stack and registers on exit and does not
// asynchronously preempt it mid-block. secret.Enabled() is the runtime's
// own answer to "is this goroutine inside Do", asked from inside the worker
// through the test hook. The control is that the same question asked from
// a plain goroutine answers false.
func TestWorkersRunInsideSecretDo(t *testing.T) {
	if !secmem.RuntimeSecretActive() {
		t.Fatal("runtime/secret build tag is set but secmem reports the layer inactive")
	}

	var control bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		control = secret.Enabled()
	}()
	wg.Wait()
	if control {
		t.Fatal("control failed: secret.Enabled() is true in a plain goroutine, so the assertion below would be vacuous")
	}

	var inside, total atomic.Int32
	segmentProbe = func() {
		total.Add(1)
		if secret.Enabled() {
			inside.Add(1)
		}
	}
	defer func() { segmentProbe = nil }()

	ws := NewWorkspace(64, 3)
	defer ws.Wipe()
	Derive(make([]byte, 32), ModeID, []byte("p"), []byte("0123456789abcdef"), nil, nil, 2, ws)

	if want := int32(2 * syncPoints * 3); total.Load() != want {
		t.Fatalf("probe ran %d times, want %d (one per segment)", total.Load(), want)
	}
	if inside.Load() != total.Load() {
		t.Fatalf("%d of %d worker segments ran outside a runtime/secret window", total.Load()-inside.Load(), total.Load())
	}
}
