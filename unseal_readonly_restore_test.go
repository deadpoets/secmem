package secmem

import (
	"bytes"
	"errors"
	"testing"
)

// TestUnseal_FailedReadOnlyRestoreStaysSealed drives the last step of Unseal
// on a buffer that was read-only when it was sealed: the page has been made
// writable and the contents decrypted, and re-applying PROT_READ then fails.
//
// Unseal returned with the sealed flag still set and called that failing
// closed, but nothing was closed: the region was left read-write plaintext,
// and a Seal in response returned nil from its already-sealed early return
// without protecting anything. The flag has to be true of the memory, so the
// failure path seals again before it returns.
func TestUnseal_FailedReadOnlyRestoreStaysSealed(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	secret := bytes.Repeat([]byte{0x5A}, 48)
	buf, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()
	if err := buf.ReadOnly(); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	wasCipher := buf.sealCipher.Load()

	refused := errors.New("mprotect refused (injected)")
	origRestore, origProtect := unsealRestoreReadOnly, sealProtect
	defer func() { unsealRestoreReadOnly, sealProtect = origRestore, origProtect }()
	unsealRestoreReadOnly = func(secRegion) error { return refused }
	reprotected := 0
	sealProtect = func(r secRegion) error { reprotected++; return origProtect(r) }

	if err := buf.Unseal(); !errors.Is(err, refused) {
		t.Fatalf("Unseal = %v, want the injected failure", err)
	}
	if !buf.IsSealed() {
		t.Error("IsSealed() = false after a failed Unseal")
	}
	if reprotected != 1 {
		t.Errorf("the failed Unseal re-applied the seal protection %d times, want 1: "+
			"the buffer is flagged sealed over a read-write page", reprotected)
	}
	if got := buf.sealCipher.Load(); got != wasCipher {
		t.Errorf("seal-cipher state after the failed Unseal = %v, want %v as it was while sealed", got, wasCipher)
	}

	// The buffer recovers: with the protection working again Unseal succeeds,
	// the secret is intact and the buffer is read-only as it was.
	unsealRestoreReadOnly, sealProtect = origRestore, origProtect
	if err := buf.Unseal(); err != nil {
		t.Fatalf("second Unseal: %v", err)
	}
	if err := buf.WithBytes(func(b []byte) {
		if !bytes.Equal(b, secret) {
			t.Error("contents changed across the failed Unseal")
		}
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	if _, err := buf.CopyIn([]byte{1}, 0); !errors.Is(err, ErrReadOnly) {
		t.Errorf("CopyIn after the recovery = %v, want ErrReadOnly", err)
	}
}
