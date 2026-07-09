package secmem

import (
	"runtime"
	"testing"
)

// ---------------------------------------------------------------------------
// bufferRWLock — Micro-benchmarks for the sync.Cond-based RWLock
// ---------------------------------------------------------------------------

// BenchmarkBufferRWLock_RLockUnlock measures uncontended reader lock/unlock.
// This is the atomic baseline for all SecureBuffer access methods.
func BenchmarkBufferRWLock_RLockUnlock(b *testing.B) {
	l := newBufferRWLock()
	b.ResetTimer()
	for b.Loop() {
		l.rLock()
		l.rUnlock()
	}
	b.ReportAllocs()
}

// BenchmarkBufferRWLock_LockUnlock measures uncontended writer lock/unlock.
func BenchmarkBufferRWLock_LockUnlock(b *testing.B) {
	l := newBufferRWLock()
	b.ResetTimer()
	for b.Loop() {
		l.lock()
		l.unlock()
	}
	b.ReportAllocs()
}

// BenchmarkBufferRWLock_RLockUnlock_Parallel measures contended reader
// throughput — the dominant pattern in production (N concurrent WithBytesErr).
func BenchmarkBufferRWLock_RLockUnlock_Parallel(b *testing.B) {
	l := newBufferRWLock()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.rLock()
			l.rUnlock()
		}
	})
	runtime.KeepAlive(l)
}
