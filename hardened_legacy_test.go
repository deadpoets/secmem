//go:build !goexperiment.runtimesecret || !(linux && (amd64 || arm64))

// Tests for the legacy wipe helpers (WipeBytes / WipeArray).

package secmem

import "testing"

// TestWipeBytes_ZerosSlice verifies WipeBytes zeros every byte in a non-empty slice.
func TestWipeBytes_ZerosSlice(t *testing.T) {
	t.Parallel()
	b := []byte("secret-password-1234")
	WipeBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte[%d] = %d, want 0", i, v)
		}
	}
}

// TestWipeBytes_EmptySlice verifies WipeBytes does not panic on nil or empty input.
func TestWipeBytes_EmptySlice(t *testing.T) {
	t.Parallel()
	WipeBytes(nil)
	WipeBytes([]byte{})
}

// TestWipeArray_ZerosArray verifies WipeArray (alias for WipeBytes) zeros the slice.
func TestWipeArray_ZerosArray(t *testing.T) {
	t.Parallel()
	b := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	WipeArray(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte[%d] = 0x%02X, want 0", i, v)
		}
	}
}
