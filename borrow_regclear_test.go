//go:build (amd64 || arm64) && !race

// Not under the race detector, for the reason scrub_gpclear_test.go gives.

package secmem

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// regProbe is one architecture's register probe: the vector file and the
// general-purpose registers, each with a planted pattern and a dump buffer.
type regProbe struct {
	vPlanted, vGot   []byte
	fillV, dumpV     func()
	gpPlanted, gpGot []byte
	gpNames          []string
	fillGP, dumpGP   func()
}

// plant fills both pattern buffers: vector bytes never zero, general-purpose
// words at a non-canonical address no pointer can equal.
func (p *regProbe) plant() {
	for i := range p.vPlanted {
		p.vPlanted[i] = byte(i%0xEE) + 0x11
	}
	for i := range p.gpNames {
		binary.LittleEndian.PutUint64(p.gpPlanted[8*i:], 0xB0B0_5EC3_0000_0000|uint64(i+1)*0x01010101)
	}
}

// survivors dumps both files and reports what still holds the pattern: the
// number of vector registers whose whole 16 bytes are still the planted
// value, and the names of general-purpose registers still holding their
// planted word. Matching whole registers matters: code that runs after a
// subject (a Destroy, say) legitimately leaves its own values in the
// registers, and over hundreds of bytes some will equal a planted byte by
// chance.
func (p *regProbe) survivors() (int, []string) {
	p.dumpV()
	p.dumpGP()
	v := 0
	for off := 0; off+16 <= len(p.vPlanted); off += 16 {
		if bytes.Equal(p.vGot[off:off+16], p.vPlanted[off:off+16]) {
			v++
		}
	}
	var gp []string
	for i, n := range p.gpNames {
		if binary.LittleEndian.Uint64(p.gpGot[8*i:]) == binary.LittleEndian.Uint64(p.gpPlanted[8*i:]) {
			gp = append(gp, n)
		}
	}
	return v, gp
}

//go:noinline
func borrowControlCall(fill func()) { fill() }

// TestBorrowPaths_ClearRegistersOnReturn proves the borrow, copy and compare
// paths clear the registers on the way out. Each subject plants the pattern
// in both register files — inside its callback, or just before a path that
// takes none — and after it returns no planted vector byte and no planted
// general-purpose word may remain. The control plants the same way through a
// plain function and must see some of both survive, or the subjects' zeros
// would prove nothing. The residue this closes is measured end to end by
// secmem-crypto's WithBytesErr/copy-then-preempted scenario.
func TestBorrowPaths_ClearRegistersOnReturn(t *testing.T) {
	p := archRegProbe()
	p.plant()
	fill := func() { p.fillV(); p.fillGP() }

	borrowControlCall(fill)
	if v, gp := p.survivors(); v == 0 || len(gp) == 0 {
		t.Fatalf("control: %d planted vector registers and %v survive a plain call; the probe cannot show a clear doing anything", v, gp)
	} else {
		t.Logf("control: %d planted vector registers and %v survive a plain call", v, gp)
	}

	buf, err := NewBuffer(bytes.Repeat([]byte{0x42}, 64))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	defer buf.Destroy()
	arena, err := NewArena(64, 1)
	if err != nil {
		t.Skipf("NewArena: %v", err)
	}
	defer arena.Destroy()
	slot, err := arena.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	src, dst := bytes.Repeat([]byte{0x24}, 64), make([]byte, 64)

	for _, sub := range []struct {
		name string
		run  func()
	}{
		{"SecureBuffer.WithBytes", func() { _ = buf.WithBytes(func([]byte) { fill() }) }},
		{"SecureBuffer.WithBytesErr", func() { _ = buf.WithBytesErr(func([]byte) error { fill(); return nil }) }},
		{"ArenaSlot.WithBytesErr", func() { _ = slot.WithBytesErr(func([]byte) error { fill(); return nil }) }},
		{"SecureBuffer.CopyIn", func() { fill(); _, _ = buf.CopyIn(src, 0) }},
		{"SecureBuffer.CopyOut", func() { fill(); _, _ = buf.CopyOut(dst, 0) }},
		{"SecureBuffer.ConstantTimeEqual", func() { fill(); _, _ = buf.ConstantTimeEqual(src) }},
		{"SecureBuffer.WriteTo", func() { fill(); _, _ = buf.WriteTo(io.Discard) }},
		{"SecureBuffer.ReadFrom", func() { fill(); _, _ = buf.ReadFrom(bytes.NewReader(src)) }},
		{"NewBuffer", func() {
			fill()
			b, err := NewBuffer(bytes.Clone(src))
			if err == nil {
				_ = b.Destroy()
			}
		}},
	} {
		sub.run()
		if v, gp := p.survivors(); v != 0 || len(gp) != 0 {
			t.Errorf("%s: %d planted vector registers and planted %v survive its return", sub.name, v, gp)
		}
	}
}
