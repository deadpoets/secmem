package argon2

import (
	"bytes"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"testing"

	upstream "golang.org/x/crypto/argon2"
)

// TestDeriveCancellable_StopsAtTheNextSliceBoundary closes done from inside
// a worker of slice k and pins everything the doc promises about what
// happens next: the slice in progress finishes (every one of its workers
// ran), no later slice starts, out is not written, the matrix is left for
// the caller to wipe, and the wiped Workspace derives correctly afterwards.
//
// The probe count is the granularity claim: (k+1)·threads means the
// cancellation was honoured at the first boundary after it and not before.
// The control is the same derivation with done left open, which must run
// every slice; without it a derivation that stopped for any other reason
// would pass.
func TestDeriveCancellable_StopsAtTheNextSliceBoundary(t *testing.T) {
	const (
		threads = 2
		passes  = 2
		slices  = passes * syncPoints
	)
	password, salt := []byte("password"), []byte("0123456789abcdef")
	sentinel := bytes.Repeat([]byte{0xA5}, 32)

	run := func(cancelInSlice int) (completed bool, probes int32, out []byte, ws *Workspace) {
		ws = NewWorkspace(64, threads)
		out = bytes.Clone(sentinel)
		done := make(chan struct{})
		var count atomic.Int32
		var once sync.Once
		segmentProbe = func() {
			// Workers of slice s see counts s·threads+1 … (s+1)·threads.
			if n := count.Add(1); cancelInSlice >= 0 && n > int32(cancelInSlice*threads) {
				once.Do(func() { close(done) })
			}
		}
		defer func() { segmentProbe = nil }()
		completed = DeriveCancellable(out, ModeID, password, salt, nil, nil, passes, ws, done)
		return completed, count.Load(), out, ws
	}

	completed, probes, out, ws := run(-1)
	if !completed || probes != slices*threads {
		t.Fatalf("control failed: with done open, completed=%v after %d segments, want true after %d", completed, probes, slices*threads)
	}
	want := upstream.IDKey(password, salt, passes, 64, threads, 32)
	if !bytes.Equal(out, want) {
		t.Fatalf("control failed: with done open the tag is %x, upstream says %x", out, want)
	}
	ws.Wipe()

	for _, k := range []int{0, 3, slices - 1} {
		completed, probes, out, ws := run(k)
		if k == slices-1 {
			// Closed during the last slice: there is no boundary left, so the
			// derivation completes. Cancellation is not retroactive.
			if !completed || !bytes.Equal(out, want) {
				t.Errorf("cancel in the last slice: completed=%v tag=%x, want a completed derivation", completed, out)
			}
			ws.Wipe()
			continue
		}
		if completed {
			t.Errorf("cancel in slice %d: reported completed", k)
		}
		if wantProbes := int32((k + 1) * threads); probes != wantProbes {
			t.Errorf("cancel in slice %d: %d segments ran, want %d (the slice in progress and no more)", k, probes, wantProbes)
		}
		if !bytes.Equal(out, sentinel) {
			t.Errorf("cancel in slice %d: out was written: %x", k, out)
		}
		if isZero(workspaceResidue(ws)["B"]) {
			t.Errorf("cancel in slice %d: control failed: the matrix is all zero before Wipe, the assertion after it would be vacuous", k)
		}
		ws.Wipe()
		if !isZero(ws.mem) {
			t.Errorf("cancel in slice %d: the workspace holds residue after Wipe", k)
		}
		again := make([]byte, 32)
		Derive(again, ModeID, password, salt, nil, nil, passes, ws)
		if !bytes.Equal(again, want) {
			t.Errorf("cancel in slice %d: the next derivation on the wiped workspace is %x, want %x", k, again, want)
		}
		ws.Wipe()
	}
}

// TestDeriveCancellable_AlreadyClosed: a done that is closed before the call
// starts no worker at all.
func TestDeriveCancellable_AlreadyClosed(t *testing.T) {
	done := make(chan struct{})
	close(done)
	var count atomic.Int32
	segmentProbe = func() { count.Add(1) }
	defer func() { segmentProbe = nil }()

	ws := NewWorkspace(64, 2)
	defer ws.Wipe()
	out := bytes.Repeat([]byte{0xA5}, 32)
	if DeriveCancellable(out, ModeID, []byte("p"), []byte("0123456789abcdef"), nil, nil, 1, ws, done) {
		t.Error("reported completed")
	}
	if n := count.Load(); n != 0 {
		t.Errorf("%d segments ran, want 0", n)
	}
	if !bytes.Equal(out, bytes.Repeat([]byte{0xA5}, 32)) {
		t.Errorf("out was written: %x", out)
	}
}

// TestDeriveCancellable_OpenChannelMatchesRFC runs the RFC 9106 vectors
// through the cancellable entry point with a channel that never closes: the
// check between slices must not change the output in any mode. (A nil done
// is what Derive passes, so every other test in the package covers it.)
func TestDeriveCancellable_OpenChannelMatchesRFC(t *testing.T) {
	password := bytes.Repeat([]byte{0x01}, 32)
	salt := bytes.Repeat([]byte{0x02}, 16)
	secret := bytes.Repeat([]byte{0x03}, 8)
	data := bytes.Repeat([]byte{0x04}, 12)
	for _, v := range rfc9106Vectors {
		ws := NewWorkspace(32, 4)
		out := make([]byte, 32)
		if !DeriveCancellable(out, v.mode, password, salt, secret, data, 3, ws, make(chan struct{})) {
			t.Errorf("%s: not completed", v.name)
		}
		ws.Wipe()
		if got := hex.EncodeToString(out); got != v.tag {
			t.Errorf("%s: %s, want %s", v.name, got, v.tag)
		}
	}
}
