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
	"math"
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
	n, err := sealCipherLen(len(inner))
	if err != nil {
		return err
	}
	r1, _, callErr := proc.Call(
		//nolint:gosec // G103: passing the secret area's address to the crypt32 in-place cipher; OS-mapped, audited.
		uintptr(unsafe.Pointer(&inner[0])),
		uintptr(n),
		cryptProtectMemorySameProcess,
	)
	if r1 == 0 {
		return fmt.Errorf("secmem: %s: %w", proc.Name, callErr)
	}
	return nil
}

// sealCipherLen returns the byte count to pass to the cipher for an area of n
// bytes, or an error when the cipher cannot cover it. CryptProtectMemory takes
// the length as a DWORD: an area of 4 GiB or more would be encrypted only for
// its length modulo 2^32 while Seal recorded it as ciphertext, so it is
// refused and Seal fails visibly. Compared in uint64 for the reason given in
// werExcludeFromDumps.
func sealCipherLen(n int) (uint32, error) {
	if n%cryptProtectMemoryBlockSize != 0 {
		return 0, fmt.Errorf("secmem: seal cipher: area %d bytes is not a multiple of %d", n, cryptProtectMemoryBlockSize)
	}
	if n < 0 || uint64(n) > uint64(math.MaxUint32) {
		return 0, fmt.Errorf("secmem: seal cipher: area %d bytes exceeds the %d-byte limit of one cipher call", n, uint64(math.MaxUint32))
	}
	return uint32(n), nil
}

// sealEncrypt encrypts the secret area in place with the kernel-held per-boot
// process key. Returns applied=true on success so the caller can record that
// the contents are ciphertext (the janitor must not canary-check ciphertext).
//
// sealEncrypt and sealDecrypt are package vars, not plain funcs, solely so a
// test can wrap them — make the decrypt fail on demand, count the encrypts.
// Seal's rollback state machine only runs when VirtualProtect refuses a
// committed region and CryptUnprotectMemory then refuses too, which no real
// environment produces to order. Production always runs the values defined
// here.
var sealEncrypt = func(region secRegion) (applied bool, err error) {
	if err := sealCipherCall(procCryptProtectMemory, region); err != nil {
		return false, err
	}
	return true, nil
}

// sealDecrypt reverses sealEncrypt, restoring the plaintext and the canary
// slack bit-exactly.
var sealDecrypt = func(region secRegion) error {
	return sealCipherCall(procCryptUnprotectMemory, region)
}
