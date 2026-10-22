package secmem

import "testing"

// BenchmarkBorrow compares the cost of one WithBytes on a 32-byte buffer in
// the three ways a secret can be kept between uses:
//
//   - open: an ordinary buffer, readable at rest;
//   - closed-at-rest: WithClosedAtRest, no-access between borrows;
//   - seal-per-borrow: Unseal, borrow, Seal by hand, which on Windows also
//     encrypts the contents while dormant.
//
// The callback reads one byte, so what is measured is the borrow itself.
func BenchmarkBorrow(b *testing.B) {
	var sink byte
	read := func(p []byte) { sink ^= p[0] } //nolint:secmem-lint // one byte of an all-zero benchmark buffer, read so the borrow is not optimised away

	b.Run("open", func(b *testing.B) {
		buf, err := NewBuffer(make([]byte, 32))
		if err != nil {
			b.Skipf("NewBuffer: %v", err)
		}
		defer func() { _ = buf.Destroy() }()
		b.ReportAllocs()
		for b.Loop() {
			if err := buf.WithBytes(read); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("closed-at-rest", func(b *testing.B) {
		buf, err := NewBuffer(make([]byte, 32), WithClosedAtRest())
		if err != nil {
			b.Skipf("NewBuffer: %v", err)
		}
		defer func() { _ = buf.Destroy() }()
		b.ReportAllocs()
		for b.Loop() {
			if err := buf.WithBytes(read); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("seal-per-borrow", func(b *testing.B) {
		buf, err := NewBuffer(make([]byte, 32))
		if err != nil {
			b.Skipf("NewBuffer: %v", err)
		}
		defer func() { _ = buf.Destroy() }()
		if err := buf.Seal(); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			if err := buf.Unseal(); err != nil {
				b.Fatal(err)
			}
			if err := buf.WithBytes(read); err != nil {
				b.Fatal(err)
			}
			if err := buf.Seal(); err != nil {
				b.Fatal(err)
			}
		}
	})
	// Eight goroutines borrowing at once share one open: the protection
	// changes only when the count leaves and returns to zero.
	b.Run("closed-at-rest-parallel", func(b *testing.B) {
		buf, err := NewBuffer(make([]byte, 32), WithClosedAtRest())
		if err != nil {
			b.Skipf("NewBuffer: %v", err)
		}
		defer func() { _ = buf.Destroy() }()
		b.ReportAllocs()
		b.SetParallelism(1)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = buf.WithBytes(func(p []byte) { _ = p[0] })
			}
		})
	})
	b.Run("open-parallel", func(b *testing.B) {
		buf, err := NewBuffer(make([]byte, 32))
		if err != nil {
			b.Skipf("NewBuffer: %v", err)
		}
		defer func() { _ = buf.Destroy() }()
		b.ReportAllocs()
		b.SetParallelism(1)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = buf.WithBytes(func(p []byte) { _ = p[0] })
			}
		})
	})
	_ = sink
}
