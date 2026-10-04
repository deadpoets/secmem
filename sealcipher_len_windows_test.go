//go:build windows

package secmem

import (
	"strconv"
	"testing"
)

// TestSealCipherLen pins the length the seal cipher is called with.
// CryptProtectMemory takes a DWORD: a longer area would be encrypted for its
// length modulo 2^32 and recorded as fully encrypted, so it is refused.
func TestSealCipherLen(t *testing.T) {
	for _, n := range []int{16, 4096, 1 << 20} {
		if got, err := sealCipherLen(n); err != nil || int(got) != n {
			t.Errorf("sealCipherLen(%d) = (%d, %v), want (%d, nil)", n, got, err, n)
		}
	}
	if _, err := sealCipherLen(4097); err == nil {
		t.Error("sealCipherLen(4097) = nil error, want a refusal (not a multiple of the cipher block)")
	}
	if strconv.IntSize < 64 {
		return // no int can exceed a DWORD
	}
	for _, n64 := range []uint64{1 << 32, 1<<32 + 65536} {
		if _, err := sealCipherLen(int(n64)); err == nil {
			t.Errorf("sealCipherLen(%d) = nil error, want a refusal: the call would cover %d bytes", n64, uint32(n64))
		}
	}
}
