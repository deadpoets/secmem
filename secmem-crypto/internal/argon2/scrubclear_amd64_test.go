//go:build amd64 && gc && !purego

package argon2

import (
	"runtime"
	"testing"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/secmem-crypto/internal/regprobe"
)

// TestScrubClearsVectorRegs is the empirical check the project requires
// before any register scrub is trusted, applied to this package's windows:
// the vector-register clear the fork relies on is the core's, at the end of
// every secmem.Scrub window it opens, and the test shows that clear reaches
// what this package's code leaves behind. Three parts, in order:
//
//  1. Control. The SSE blamka run bare, outside any window, must leave
//     block state readable in X0–X15. A zero here is a failure, not a skip:
//     if a build ever makes the residue unobservable this way, the test has
//     to be rethought, not silently passed.
//  2. The worker's window. The same block step inside a Scrub window —
//     runSegment's shape — must leave the file all zero afterwards.
//  3. The parent's windows, end to end. A whole Derive, whose last act is
//     the extraction window, must return with the file all zero.
//
// The goroutine is pinned for the whole sequence so every dump reads the
// thread that ran the code before it; nothing between a step and its dump
// touches the vector registers. secmem's own scrub_vecclear_test.go proves
// the clear in the abstract (planted pattern, controls without the clear,
// panic unwind); this test only has to show it applies here.
func TestScrubClearsVectorRegs(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var s laneScratch
	for i := range s.in {
		s.in[i] = 0x0123456789abcdef ^ uint64(i)
	}
	var out block
	var got [256]byte

	// 1. Control.
	processBlock(&out, &s.in, &zeroBlock, &s)
	regprobe.DumpXMM(&got)
	if isZero(got[:]) {
		t.Fatal("control failed: no vector-register residue observed after blamka outside a window, so the clear cannot be shown to reach anything")
	}

	// 2. The worker's window.
	secmem.Scrub(func() {
		processBlock(&out, &s.in, &zeroBlock, &s)
	})
	regprobe.DumpXMM(&got)
	if !isZero(got[:]) {
		t.Fatalf("vector registers hold residue after the worker-shaped Scrub window: %x", got)
	}

	// 3. The parent's windows, end to end.
	ws := NewWorkspace(64, 2)
	defer ws.Wipe()
	Derive(make([]byte, 32), ModeID, []byte("password"), []byte("0123456789abcdef"), nil, nil, 1, ws)
	regprobe.DumpXMM(&got)
	if !isZero(got[:]) {
		t.Fatalf("vector registers hold residue after Derive returned: %x", got)
	}
}
