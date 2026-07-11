//go:build windows

// sealcipher_windows.go encrypts sealed buffers with CryptProtectMemory.
//
// While a buffer is sealed its pages are PAGE_NOACCESS, which already blocks
// in-process reads — but full process dumps (procdump, Task Manager, WER full
// dumps, the hibernation file) read through the kernel and ignore page
// protection. Encrypting the sealed contents with a KERNEL-HELD per-boot key
// (CRYPTPROTECTMEMORY_SAME_PROCESS) means any userspace memory dump of a
// dormant sealed buffer contains ciphertext, and the key is not in the dump.
//
// HONESTY — what this is and is not:
//   - It protects the SEALED window only. An unsealed buffer is plaintext in
//     a dump; seal long-lived secrets when not in use.
//   - It is not a defense against in-process CODE EXECUTION: code running in
//     the process can call CryptUnprotectMemory itself.
//   - It is not cold-boot/RAM-remanence protection: the kernel's key is in
//     RAM too. Hardware memory encryption (TME/SME) owns that threat.
//
// crypt32.dll is resolved with NewLazySystemDLL (System32 only — immune to
// DLL planting). The buffer length is page-rounded and therefore always a
// multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE (16); checked anyway.

package secmem

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// cryptProtectMemorySameProcess is CRYPTPROTECTMEMORY_SAME_PROCESS: the
// kernel key is scoped to this process and this boot.
const cryptProtectMemorySameProcess = 0

// cryptProtectMemoryBlockSize is CRYPTPROTECTMEMORY_BLOCK_SIZE.
const cryptProtectMemoryBlockSize = 16

//nolint:gochecknoglobals // process-wide lazy handles to a System32 DLL.
var (
	crypt32                  = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectMemory   = crypt32.NewProc("CryptProtectMemory")
	procCryptUnprotectMemory = crypt32.NewProc("CryptUnprotectMemory")
)

// sealCipherCall invokes CryptProtectMemory/CryptUnprotectMemory over the
// whole secret area (data and canary slack together — decryption restores the
// canary bit-exactly).
func sealCipherCall(proc *windows.LazyProc, region secRegion) error {
	inner := region.inner
	if len(inner) == 0 {
		return nil
	}
	if len(inner)%cryptProtectMemoryBlockSize != 0 {
		return fmt.Errorf("secmem: seal cipher: area %d bytes is not a multiple of %d", len(inner), cryptProtectMemoryBlockSize)
	}
	r1, _, callErr := proc.Call(
		//nolint:gosec // G103: passing the secret area's address to the crypt32 in-place cipher; OS-mapped, audited.
		uintptr(unsafe.Pointer(&inner[0])),
		uintptr(len(inner)),
		cryptProtectMemorySameProcess,
	)
	if r1 == 0 {
		return fmt.Errorf("secmem: %s: %w", proc.Name, callErr)
	}
	return nil
}

// sealEncrypt encrypts the secret area in place with the kernel-held per-boot
// process key. Returns applied=true on success so the caller can record that
// the contents are ciphertext (the janitor must not canary-check ciphertext).
func sealEncrypt(region secRegion) (applied bool, err error) {
	if err := sealCipherCall(procCryptProtectMemory, region); err != nil {
		return false, err
	}
	return true, nil
}

// sealDecrypt reverses sealEncrypt, restoring the plaintext and the canary
// slack bit-exactly.
func sealDecrypt(region secRegion) error {
	return sealCipherCall(procCryptUnprotectMemory, region)
}
