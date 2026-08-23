// Minimal reproducer for the windows/amd64 runtime corruption secmem's CI hits.
//
// It contains NO secmem code and writes to NO off-heap memory. It only does what
// secmem's guard-page tests do to the RUNTIME: arm debug.SetPanicOnFault and take
// a deliberate hardware access violation, many times, in parallel, under -race —
// while churning small heap objects (the shape of the victims seen in the dump: a
// testing.T whose header was overwritten by a Windows CONTEXT record with
// Rip=runtime.sigresume).
//
// If this reproduces the same class of crash (fatal error tripping over damaged
// runtime/heap state, or a CONTEXT landing in live memory), the corruption is in
// the Go runtime's Windows fault-recovery path, exercised by deliberate faults —
// not a secmem out-of-bounds write. That is the whole question the release train
// is held on.
//
// Runs everywhere; only expected to fire on the hosted windows/amd64 image, which
// is the only place the real crash has appeared.
package faultstress

import (
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"unsafe"
)

// faults mirrors secmem's guard_canary_test.go helper exactly: SetPanicOnFault,
// then a read that the hardware refuses, recovered as a panic.
//
//go:noinline
func faults(fn func()) (faulted bool) {
	old := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(old)
	defer func() {
		if recover() != nil {
			faulted = true
		}
	}()
	fn()
	return false
}

//go:noinline
//go:nocheckptr
func probeRead(addr uintptr) byte {
	return *(*byte)(unsafe.Pointer(addr))
}

// churn keeps live, pointer-bearing heap objects the size of a testing.T being
// allocated and dropped, so the allocator is constantly handing back memory a
// stray CONTEXT write can land on.
func churn(stop <-chan struct{}) {
	sink := make([]*[64]*int, 0, 4096)
	for {
		select {
		case <-stop:
			return
		default:
		}
		for i := 0; i < 4096; i++ {
			o := new([64]*int)
			o[i%64] = &i
			sink = append(sink, o)
		}
		if len(sink) > 3<<16 {
			sink = sink[:0]
		}
	}
}

func TestFaultStress(t *testing.T) {
	// A guaranteed-unmapped canonical address: reserved PROT_NONE space is what
	// secmem's guards are, but a fixed non-canonical-free low address faults just
	// as reliably and needs no syscall. Use address 4096 (page 1, never mapped).
	const guard = uintptr(0x1000)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		wg.Add(1)
		go func() { defer wg.Done(); churn(stop) }()
	}

	const workers = 64
	for w := 0; w < workers; w++ {
		t.Run("probe", func(t *testing.T) {
			t.Parallel()
			for i := 0; i < 2000; i++ {
				if !faults(func() { _ = probeRead(guard) }) {
					t.Fatal("probe did not fault — test is vacuous")
				}
			}
		})
	}
	close(stop)
	wg.Wait()
}
