//go:build !race

// Allocation-site attribution needs an exact memory profile, which the race
// detector's instrumentation perturbs; the non-race CI job runs this.

package secmemcrypto

import (
	"runtime"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/deadpoets/secmem"
)

// The passphrase paths make one heap allocation on purpose — the AES Block
// crypto/aes returns, whose round keys aeswipe.go clears — and must make no
// other. These proofs run the profiler at rate 1 over the encrypted parse
// and both marshal forms and fail on any allocation owned by the files that
// implement them, with the AES packages allowlisted alongside the core's
// buffer bookkeeping. A stray copy — the seed cloned into a []byte, the
// container marshalled through x/crypto, base64 encoded through a heap
// encoder — shows up here as a named allocation site.

var passphrasePathFiles = map[string]bool{
	"parse.go": true, "parse_openssh.go": true, "parse_encrypted.go": true,
	"marshal_openssh.go": true, "openssh_wire.go": true, "openssh_cipher.go": true,
	"aeswipe.go": true,
}

var passphrasePathAllowed = []string{
	"github.com/deadpoets/secmem.",    // SecureBuffer bookkeeping; the contents are off-heap
	"crypto/aes.",                     // the one Block, wiped before return
	"crypto/internal/fips140/aes.",    // where crypto/aes allocates it
	"golang.org/x/crypto/cryptobyte.", // not on these paths; kept for symmetry with the plain proof
	"crypto/rand.",                    // the salt and check bytes: crypto/rand's reader bookkeeping, not the bytes
	"crypto/internal/rand.",           // (IsDefaultReader boxes an interface); the bytes land in the caller's array
}

// proveNoOwnedAllocations runs fn once to warm lazily initialised state,
// then three measured times, and reports every allocation owned by files
// through an allowlist gap.
func proveNoOwnedAllocations(t *testing.T, files map[string]bool, allowed []string, fn func()) {
	t.Helper()
	old := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	t.Cleanup(func() { runtime.MemProfileRate = old })

	fn()
	runtime.GC()
	runtime.GC()
	before := memProfileByStack()
	for range 3 {
		fn()
	}
	runtime.GC()
	runtime.GC()
	after := memProfileByStack()
	for stack, rec := range after {
		delta := rec.AllocObjects - before[stack].AllocObjects
		if delta <= 0 {
			continue
		}
		if site := ownedAllocation(rec, delta, files, allowed); site != "" {
			t.Errorf("allocated on the heap: %s", site)
		}
	}
}

func TestParsePrivateKeyWithPassphrase_AllocatesOnlyTheAESBlock(t *testing.T) {
	for _, k := range parseTestKeys(t) {
		if !k.openssh || k.pkcs1 {
			continue // no OpenSSH form for P-224; the RSA block computes CRT exponents with math/big by design
		}
		block, err := ssh.MarshalPrivateKeyWithPassphrase(k.priv, "a comment", []byte(testPassphrase))
		if err != nil {
			t.Fatal(err)
		}
		for form, data := range map[string][]byte{"pem": pemEncodeToMemory(block), "raw": block.Bytes} {
			t.Run(k.name+"/"+form, func(t *testing.T) {
				proveNoOwnedAllocations(t, passphrasePathFiles, passphrasePathAllowed, func() {
					s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase))
					if err != nil {
						t.Fatal(err)
					}
					s.Destroy()
				})
			})
		}
	}
}

func TestMarshalOpenSSHPrivateKey_AllocatesOnlyTheAESBlock(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	t.Run("plain", func(t *testing.T) {
		proveNoOwnedAllocations(t, passphrasePathFiles, passphrasePathAllowed, func() {
			buf, err := signer.MarshalOpenSSHPrivateKey("a comment")
			if err != nil {
				t.Fatal(err)
			}
			buf.Destroy()
		})
	})
	t.Run("encrypted", func(t *testing.T) {
		proveNoOwnedAllocations(t, passphrasePathFiles, passphrasePathAllowed, func() {
			buf, err := signer.MarshalOpenSSHPrivateKeyWithPassphrase("a comment", []byte(testPassphrase))
			if err != nil {
				t.Fatal(err)
			}
			buf.Destroy()
		})
	})
}

// BcryptPBKDFInto is a stricter case than the paths above: it has no AES
// Block to account for, so nothing it owns may allocate at all. The
// workspace is a SecureBuffer whose contents are off-heap, the derived
// bytes go into the caller's buffer, and the salt is short enough not to
// spill. Ownership is decided by the package prefix before the file name,
// so the identically named file in internal/bcryptpbkdf — a different
// package — is never the owner here, and an allocation inside the fork
// would be reported against its own caller rather than hidden.
var (
	bcryptPBKDFFiles   = map[string]bool{"bcrypt_pbkdf.go": true}
	bcryptPBKDFAllowed = []string{"github.com/deadpoets/secmem."} // SecureBuffer bookkeeping; the contents are off-heap
)

func TestBcryptPBKDFInto_AllocatesNothing(t *testing.T) {
	out, err := secmem.NewEmptyBuffer(opensshKeyIVLen)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = out.Destroy() }()
	password, salt := []byte(testPassphrase), []byte("0123456789abcdef")
	proveNoOwnedAllocations(t, bcryptPBKDFFiles, bcryptPBKDFAllowed, func() {
		if err := BcryptPBKDFInto(password, salt, 1, out); err != nil {
			t.Fatal(err)
		}
	})
}
