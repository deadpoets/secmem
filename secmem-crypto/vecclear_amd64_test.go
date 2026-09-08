//go:build amd64 && gc && !purego

package secmemcrypto

import (
	"runtime"
	"testing"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/secmem-crypto/internal/regprobe"
)

// TestOpensshCrypt_ScrubClearsVectorRegs shows that the passphrase path
// leaves nothing in the vector registers once its enclosing window closes.
// opensshCrypt runs SHA-512 (bcrypt_pbkdf's hashing) and AES-NI, both of
// which keep working state in X0–X15, and clears none of it itself: both
// of its callers run it inside a secmem.ScrubErr window, and the core's
// clear at the end of that window is what removes the residue. The control
// runs the function bare and requires residue to be visible — a zero there
// is a failure, not a skip, because it would mean the clear could not be
// shown to reach anything — and the subject runs it inside the window the
// callers use and requires the file all zero. The goroutine is pinned for
// the whole sequence so each dump reads the thread that ran the code
// before it. See secmem's scrub_vecclear_test.go for the proof of the clear
// itself.
func TestOpensshCrypt_ScrubClearsVectorRegs(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	passphrase := []byte(testPassphrase)
	salt := []byte("0123456789abcdef")
	src := make([]byte, 4*opensshAESBlock)
	for i := range src {
		src[i] = byte(i) + 1
	}
	dst := make([]byte, len(src))
	var got [256]byte

	// Control: bare, no window.
	if err := opensshCrypt(dst, src, passphrase, salt, 1, cipherAES256CTR, false); err != nil {
		t.Skipf("opensshCrypt: %v", err) // its one failure outside the arguments is the locked scratch allocation
	}
	regprobe.DumpXMM(&got)
	if allZero(got[:]) {
		t.Fatal("control failed: no vector-register residue observed after opensshCrypt outside a window, so the clear cannot be shown to reach anything")
	}

	// Subject: the window both callers use.
	err := secmem.ScrubErr(func() error {
		return opensshCrypt(dst, src, passphrase, salt, 1, cipherAES256CTR, false)
	})
	regprobe.DumpXMM(&got)
	if err != nil {
		t.Fatal(err)
	}
	if !allZero(got[:]) {
		t.Fatalf("vector registers hold residue after the passphrase path's ScrubErr window: %x", got)
	}
}

func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}
