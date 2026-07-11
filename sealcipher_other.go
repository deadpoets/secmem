//go:build !windows

// Seal-cipher stubs. Only Windows has a kernel-keyed in-place memory cipher
// (CryptProtectMemory); on other platforms Seal is page protection only.
// Linux's strongest dump defenses are memfd_secret (pages invisible to
// kernel-mediated readers, hibernation refused while mapped) and
// MADV_DONTDUMP — both applied at allocation, not at seal time.

package secmem

// sealEncrypt is a no-op off Windows: applied=false, sealed contents stay
// plaintext behind PROT_NONE.
func sealEncrypt(_ secRegion) (applied bool, err error) {
	return false, nil
}

// sealDecrypt is a no-op off Windows. It is never reached in practice
// because the cipher flag is only set when sealEncrypt applied.
func sealDecrypt(_ secRegion) error {
	return nil
}
