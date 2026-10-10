package secmem

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// flipSealedBit flips one bit of a sealed buffer's region behind its back:
// lifts the protection, flips, re-protects. This is the fault the tag exists
// to catch, injected deterministically.
func flipSealedBit(t *testing.T, buf *SecureBuffer, off int, mask byte) {
	t.Helper()
	if err := mprotectSecretMem(buf.region, 3); err != nil {
		t.Fatalf("mprotect RW: %v", err)
	}
	buf.region.inner[off] ^= mask
	if err := mprotectSecretMem(buf.region, 0); err != nil {
		t.Fatalf("mprotect NONE: %v", err)
	}
}

func newSealedBuffer(t *testing.T, n int, opts ...Option) (*SecureBuffer, []byte) {
	t.Helper()
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	want := make([]byte, n)
	rand.Read(want)
	buf, err := NewBuffer(bytes.Clone(want), opts...)
	if err != nil {
		t.Skipf("cannot lock a %d-byte buffer: %v", n, err)
	}
	t.Cleanup(func() { _ = buf.Destroy() })
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return buf, want
}

func mustEqualContents(t *testing.T, buf *SecureBuffer, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := buf.CopyOut(got, 0); err != nil {
		t.Fatalf("CopyOut: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("contents differ from what was sealed")
	}
}

// TestSeal_FlipWhileSealedIsRefused is the regression test for the tag. The
// unfixed behaviour is reproduced in-test by the opt-out: with
// WithUnauthenticatedSeal, exactly what every buffer did before, the flipped
// secret comes back as if nothing happened. Every byte class of the region
// is covered: first and last secret byte, first and last byte of the canary
// slack.
func TestSeal_FlipWhileSealedIsRefused(t *testing.T) {
	const n = 64
	buf, want := newSealedBuffer(t, n)
	inner := len(buf.region.inner)
	offsets := map[string]int{"first": 0, "last secret": n - 1}
	if inner > n {
		offsets["first slack"] = n
		offsets["last slack"] = inner - 1
	}
	for name, off := range offsets {
		t.Run(name, func(t *testing.T) {
			flipSealedBit(t, buf, off, 0x01)
			err := buf.Unseal()
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("Unseal after flip = %v, want ErrIntegrity", err)
			}
			if !buf.IsSealed() {
				t.Fatal("buffer unsealed after an integrity failure")
			}
			if err := buf.WithBytes(func([]byte) {}); !errors.Is(err, ErrSealed) {
				t.Fatalf("WithBytes = %v, want ErrSealed", err)
			}
			// Fail closed, not fail destroyed: undo the fault and the same
			// sealed state verifies again.
			flipSealedBit(t, buf, off, 0x01)
			if err := buf.Unseal(); err != nil {
				t.Fatalf("Unseal after restoring the bit: %v", err)
			}
			mustEqualContents(t, buf, want)
			if err := buf.Seal(); err != nil {
				t.Fatalf("Seal: %v", err)
			}
		})
	}

	t.Run("control: unauthenticated seal hands the flip back", func(t *testing.T) {
		ctl, want := newSealedBuffer(t, n, WithUnauthenticatedSeal())
		flipSealedBit(t, ctl, 0, 0x01)
		if err := ctl.Unseal(); err != nil {
			t.Fatalf("Unseal: %v", err)
		}
		got := make([]byte, n)
		if _, err := ctl.CopyOut(got, 0); err != nil {
			t.Fatal(err)
		}
		// Off Windows the one bit comes back flipped; on Windows the seal
		// cipher turns it into a garbled block. Either way: altered contents,
		// handed out as the secret, no error.
		if bytes.Equal(got, want) {
			t.Fatal("control did not reproduce the unprotected behaviour")
		}
	})
}

// TestSeal_DestroyReportsIntegrity: Destroy on a corrupted sealed buffer
// reports the corruption and still wipes and frees.
func TestSeal_DestroyReportsIntegrity(t *testing.T) {
	buf, _ := newSealedBuffer(t, 32)
	flipSealedBit(t, buf, 5, 0x80)
	err := buf.Destroy()
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Destroy = %v, want ErrIntegrity", err)
	}
	if !buf.IsDestroyed() {
		t.Fatal("Destroy reported integrity but did not destroy")
	}
	if err := buf.Destroy(); err != nil {
		t.Fatalf("second Destroy = %v, want nil", err)
	}
}

// TestSeal_CorruptTagOrNonceIsRefused: the heap-side metadata can flip too;
// that is indistinguishable from a corrupted secret and reported the same.
func TestSeal_CorruptTagOrNonceIsRefused(t *testing.T) {
	for name, flip := range map[string]func(*SecureBuffer){
		"tag":   func(b *SecureBuffer) { b.sealTag[0] ^= 1 },
		"nonce": func(b *SecureBuffer) { b.sealNonce[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			buf, _ := newSealedBuffer(t, 32)
			flip(buf)
			if err := buf.Unseal(); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("Unseal = %v, want ErrIntegrity", err)
			}
			flip(buf)
			if err := buf.Unseal(); err != nil {
				t.Fatalf("Unseal after restoring: %v", err)
			}
		})
	}
}

// TestSeal_PrekeyFlipIsRefused: a flip in the prekey re-keys every tag, so
// every sealed buffer fails closed, and recovers when the bit is restored.
func TestSeal_PrekeyFlipIsRefused(t *testing.T) {
	a, wantA := newSealedBuffer(t, 32)
	b, wantB := newSealedBuffer(t, 4096)

	sealKeys.mu.Lock()
	region := sealKeys.region
	sealKeys.mu.Unlock()
	flip := func() {
		if err := mprotectSecretMem(region, 3); err != nil {
			t.Fatal(err)
		}
		region.inner[sealPrekeyLen/2] ^= 0x10
		if err := mprotectSecretMem(region, 1); err != nil {
			t.Fatal(err)
		}
	}
	flip()
	for _, buf := range []*SecureBuffer{a, b} {
		if err := buf.Unseal(); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("Unseal under a flipped prekey = %v, want ErrIntegrity", err)
		}
	}
	flip()
	if err := a.Unseal(); err != nil {
		t.Fatal(err)
	}
	if err := b.Unseal(); err != nil {
		t.Fatal(err)
	}
	mustEqualContents(t, a, wantA)
	mustEqualContents(t, b, wantB)
}

// TestSeal_NonceIsFreshPerSeal: a reseal of unchanged contents gets a new
// nonce and a new tag — the binding the planned cipher will rely on.
func TestSeal_NonceIsFreshPerSeal(t *testing.T) {
	buf, _ := newSealedBuffer(t, 32)
	nonce1, tag1 := buf.sealNonce, buf.sealTag
	if err := buf.Unseal(); err != nil {
		t.Fatal(err)
	}
	if err := buf.Seal(); err != nil {
		t.Fatal(err)
	}
	if buf.sealNonce == nonce1 {
		t.Fatal("nonce reused across seals")
	}
	if buf.sealTag == tag1 {
		t.Fatal("tag unchanged across seals with different nonces")
	}
}

// TestSeal_UnauthenticatedOptionIsReported pins the opt-out's visibility.
func TestSeal_UnauthenticatedOptionIsReported(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewEmptyBuffer(16, WithUnauthenticatedSeal())
	if err != nil {
		t.Skipf("cannot lock: %v", err)
	}
	t.Cleanup(func() { _ = buf.Destroy() })
	caps := buf.Capabilities()
	if !caps.UnauthenticatedSeal {
		t.Fatal("Capabilities.UnauthenticatedSeal = false with the option")
	}
	found := false
	for _, w := range caps.Warnings() {
		found = found || strings.Contains(w, "WithUnauthenticatedSeal")
	}
	if !found {
		t.Fatalf("Warnings() does not name the opt-out: %q", caps.Warnings())
	}
	if !strings.Contains(caps.String(), "unauthenticated-seal") {
		t.Fatalf("String() does not show the opt-out: %q", caps.String())
	}
	if err := buf.Seal(); err != nil {
		t.Fatal(err)
	}
	if buf.sealTagged {
		t.Fatal("tag taken despite WithUnauthenticatedSeal")
	}
	if Probe().UnauthenticatedSeal {
		t.Fatal("Probe reports the opt-out")
	}
	plain, err := NewEmptyBuffer(16)
	if err != nil {
		t.Skipf("cannot lock: %v", err)
	}
	t.Cleanup(func() { _ = plain.Destroy() })
	if plain.Capabilities().UnauthenticatedSeal {
		t.Fatal("default buffer reports the opt-out")
	}
}

// TestSeal_PrekeyRegeneratesAfterWipe: WipeAllSecrets zeroes the prekey; the
// next Seal must get a fresh one, never a key derived from zeros, and a
// buffer sealed under the old generation must not verify under the new.
func TestSeal_PrekeyRegeneratesAfterWipe(t *testing.T) {
	old, _ := newSealedBuffer(t, 32)
	oldGen := old.sealGen
	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}
	sealKeys.mu.Lock()
	wiped := sealKeys.wiped.Load()
	sealKeys.mu.Unlock()
	if !wiped {
		t.Fatal("prekey not flagged wiped by WipeAllSecrets")
	}
	if err := old.Unseal(); !errors.Is(err, ErrWiped) {
		t.Fatalf("Unseal of a wiped buffer = %v, want ErrWiped", err)
	}

	fresh, want := newSealedBuffer(t, 32)
	if fresh.sealGen == oldGen {
		t.Fatal("prekey generation did not advance after the wipe")
	}
	sealKeys.mu.Lock()
	allZero := bytes.Equal(sealKeys.region.inner, make([]byte, sealPrekeyLen))
	sealKeys.mu.Unlock()
	if allZero {
		t.Fatal("new prekey is zeros")
	}
	if err := fresh.Unseal(); err != nil {
		t.Fatal(err)
	}
	mustEqualContents(t, fresh, want)

	// A buffer that carries an old generation but was not itself wiped (the
	// errWipeSkipped shape) is refused as wiped, not reported as corrupted.
	stale, _ := newSealedBuffer(t, 32)
	stale.sealGen = oldGen
	if err := stale.Unseal(); !errors.Is(err, ErrWiped) {
		t.Fatalf("Unseal under a stale generation = %v, want ErrWiped", err)
	}
}

// TestSealComputeTag_KnownAnswer pins the construction: against an
// independent crypto/hmac computation, and against a fixed vector so a
// change to the label or layout is a deliberate new version.
func TestSealComputeTag_KnownAnswer(t *testing.T) {
	prekey := make([]byte, sealPrekeyLen)
	for i := range prekey {
		prekey[i] = byte(i * 7)
	}
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i ^ 0xA5)
	}
	var nonce [sealNonceLen]byte
	for i := range nonce {
		nonce[i] = byte(0xF0 + i)
	}
	const id = 0x0123456789abcdef
	var got [sealTagLen]byte
	sealComputeTag(&got, prekey, id, &nonce, data)

	root := sha512.Sum512(prekey)
	d := sha512.Sum512(data)
	m := hmac.New(sha512.New, root[:])
	m.Write(sealLabelMac[:])
	_ = binary.Write(m, binary.BigEndian, uint64(id))
	m.Write(nonce[:])
	_ = binary.Write(m, binary.BigEndian, uint64(len(data)))
	m.Write(d[:])
	if want := m.Sum(nil)[:sealTagLen]; !bytes.Equal(got[:], want) {
		t.Fatalf("tag disagrees with crypto/hmac:\n got %x\nwant %x", got, want)
	}
	const pinned = "d8b7d69cdf5ee5ed99f255ef63ff6c6001a0992329d7acaa7409fce5181ea743"
	if hex.EncodeToString(got[:]) != pinned {
		t.Fatalf("tag %x differs from the pinned vector; a changed construction needs a new label version", got)
	}
	if n := testing.AllocsPerRun(50, func() { sealComputeTag(&got, prekey, id, &nonce, data) }); n != 0 {
		t.Fatalf("sealComputeTag allocates %v times per call; the key must stay off the heap", n)
	}
}
