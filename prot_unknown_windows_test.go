//go:build windows

package secmem

import "testing"

// TestMprotectSecretMem_RefusesUnknownProtection pins the protection values the
// Windows mapping accepts. Anything other than none (0) and read (1) used to
// become PAGE_READWRITE, so a mistyped or new value at a call site made the
// region as permissive as it can be and reported success.
func TestMprotectSecretMem_RefusesUnknownProtection(t *testing.T) {
	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	for _, prot := range []int{2, 4, 5, 7, -1} {
		if err := mprotectSecretMem(buf.region, prot); err == nil {
			t.Errorf("mprotectSecretMem(prot=%d) = nil, want a refusal", prot)
		}
	}
	for _, prot := range []int{1, 3} {
		if err := mprotectSecretMem(buf.region, prot); err != nil {
			t.Errorf("mprotectSecretMem(prot=%d) = %v, want nil", prot, err)
		}
	}
}
