//go:build !linux && !windows

package secmem

// The quarantine is not implemented here. On Darwin the same MAP_FIXED
// replace Linux uses is available, but the zero-on-release backstop there
// depends on how a wired range is deleted (see freeSecretMem in
// mlock_darwin.go) and the replace has not been run on that platform; a
// destroy path nobody has executed is not shipped. On the heap-fallback
// platforms there is no reservation to keep. Destroy unmaps as before.
const quarantineSupported = false

const quarantineFailureKeepsRange = true // unused: nothing is ever quarantined

func quarantineSecretMem(secRegion) error { return nil }

func releaseQuarantined([]byte) error { return nil }
