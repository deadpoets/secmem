// region.go defines secRegion, the typed handle for one guarded secret
// allocation. It exists to make the guard-page layout impossible to misuse:
// with guard pages, "the memory you wipe/lock/protect" and "the memory you
// unmap" are DIFFERENT ranges, and passing the wrong one to the wrong syscall
// is not a style problem — it is a fault (wiping PROT_NONE guards), a leak
// (unmapping only the middle), or a quota bug (mlocking the guards).
// Threading two bare []byte values through every call site invites exactly
// that mistake; a struct with named, documented fields does not.

package secmem

// secRegion is one guarded secret allocation.
//
// Layout (sizes are page-multiples; guards are one page each):
//
//	outer:  [ guard PROT_NONE | inner (secret pages, RW) | guard PROT_NONE ]
//	inner:                     [ data | canary-filled slack ]
//
// Contract — the fields are NOT interchangeable:
//
//   - outer is the entire reserved range, including both guard pages. It is
//     passed to exactly one operation: freeSecretMem (munmap / VirtualFree of
//     the WHOLE reservation). Guard pages are PROT_NONE address space with no
//     backing frames: never wiped, never locked, never mprotected.
//   - inner is the page-rounded secret area in the middle. Every in-place
//     operation — secureWipeSlice, mlock, mprotect (seal/readonly), madvise —
//     takes inner and only inner. Touching outer with any of these faults on
//     the guards.
//
// On the insecure heap fallback (stub platforms) there are no guards and
// outer and inner alias the same slice; the contract above still holds.
//
// The zero value (both fields nil) means "no allocation".
type secRegion struct {
	// outer is the full reservation including guard pages. Unmap target ONLY.
	outer []byte

	// inner is the page-rounded secret area. Wipe/lock/protect target ONLY.
	inner []byte
}
