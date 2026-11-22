//go:build amd64 && gc && !purego

package secmemcrypto

import (
	"crypto/aes"
	"errors"
	"runtime"
	"testing"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/secmem-crypto/internal/bcryptpbkdf"
	"github.com/deadpoets/secmem/secmem-crypto/internal/regprobe"
)

// TestOpensshCrypt_ScrubClearsVectorRegs shows that the passphrase path
// leaves nothing in the vector registers once its enclosing window closes.
// opensshCrypt runs SHA-512 (bcrypt_pbkdf's hashing) and AES-NI, both of
// which keep working state in X0–X15, and clears none of it itself: both
// of its callers run it inside a secmem.ScrubErr window, and the core's
// clear at the end of that window is what removes the residue. The control
// runs the same derivation and cipher over plain memory, outside any secmem
// call, and requires residue to be visible — a zero there is a failure, not
// a skip, because it would mean the clear could not be shown to reach
// anything. It does not run opensshCrypt bare: since core v0.6.0 the borrow
// of opensshCrypt's scratch buffer clears the registers when it returns, and
// what the buffer's release leaves afterwards differs by platform, so a bare
// run shows residue on some machines and none on others. The subject runs
// opensshCrypt inside the window the callers use and requires the file all
// zero. The goroutine is pinned for the whole sequence so each dump reads
// the thread that ran the code before it. See secmem's
// scrub_vecclear_test.go for the proof of the clear itself.
//
// One thing can write to the registers between the window's clear and the
// dump: the runtime copying the goroutine's stack, a memmove through the
// vector registers that leaves stack words in them (see regprobe.StackMark).
// Residue is therefore excused, and the subject repeated, if and only if the
// stack is shown to have moved while it ran. Residue with the stack in place
// fails at once, and so does the last attempt's wherever the stack is: a
// clear that does not reach this path fails every attempt, and the stack
// does not move in every one.
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

	// Control: opensshCrypt's computation over plain memory, no window and no
	// secmem call.
	kiv := make([]byte, aes256KeyIVLen)
	if err := bcryptpbkdf.Derive(kiv, passphrase, salt, 1, bcryptpbkdf.NewWorkspace()); err != nil {
		skipIfLockRefused(t, err)
		t.Fatal(err)
	}
	blk, err := aes.NewCipher(kiv[:32])
	if err != nil {
		skipIfLockRefused(t, err)
		t.Fatal(err)
	}
	ctrXOR(blk, kiv[32:], dst, src, make([]byte, cipherScratch))
	regprobe.DumpXMM(&got)
	if allZero(got[:]) {
		t.Fatal("control failed: no vector-register residue observed after bcrypt_pbkdf and AES-CTR outside a window, so the clear cannot be shown to reach anything")
	}

	// Subject: the window both callers use.
	const attempts = 5
	for attempt := 1; ; attempt++ {
		mark := regprobe.StackMark()
		err = secmem.ScrubErr(func() error {
			return opensshCrypt(nil, dst, src, nil, passphrase, salt, 1, cipherAES256CTR, false)
		})
		regprobe.DumpXMM(&got)
		now := regprobe.StackMark()
		if errors.Is(err, secmem.ErrNoSecureMemory) {
			t.Skipf("opensshCrypt: %v", err) // its one failure outside the arguments is the locked scratch allocation
		}
		if err != nil {
			skipIfLockRefused(t, err)
			t.Fatal(err)
		}
		if allZero(got[:]) {
			return
		}
		if now == mark || attempt == attempts {
			t.Fatalf("vector registers hold residue after the passphrase path's ScrubErr window (attempt %d, stack mark %#x then %#x): %x", attempt, mark, now, got)
		}
		t.Logf("attempt %d discarded: the stack was copied during the window (mark %#x, then %#x); the dump showed %x", attempt, mark, now, got)
	}
}

func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}
