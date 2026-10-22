package secmemcrypto

import (
	"crypto"
	"crypto/cipher"
	"crypto/mlkem"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/deadpoets/secmem"
)

const wipedKeysChildEnv = "SECMEMCRYPTO_TEST_WIPED_KEYS_CHILD"

// TestKeysRefuseAfterWipeAllSecrets pins what a key does once the process has
// emergency-wiped its secrets and kept running (InstallTerminationWipeNoExit, a
// handler of the caller's own, a recovered panic). The wipe zeroes every key
// buffer and leaves it mapped, so an operation that still borrowed the buffer
// would compute under an all-zero key and report success: AES-GCM sealing
// under the zero key, X25519 with scalar clamp(0), ML-KEM decapsulating to a
// value any observer of the ciphertext can compute, Ed25519 signing under the
// zero seed. Every one of them has to return secmem.ErrWiped instead, and
// produce nothing.
//
// WipeAllSecrets reaches every buffer in the process, the fixtures other tests
// share included, so the body runs in a re-executed copy of the test binary.
func TestKeysRefuseAfterWipeAllSecrets(t *testing.T) {
	if os.Getenv(wipedKeysChildEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestKeysRefuseAfterWipeAllSecrets$", "-test.v")
		cmd.Env = append(os.Environ(), wipedKeysChildEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		// A child that skipped proved nothing; say so rather than pass.
		if strings.Contains(string(out), "--- SKIP") {
			t.Skipf("child skipped:\n%s", out)
		}
		return
	}

	aesKey, err := secmem.NewBuffer(make([]byte, 32))
	if err != nil {
		t.Skipf("NewBuffer: %v (an mlock refusal is an environment condition)", err)
	}
	defer func() { _ = aesKey.Destroy() }()
	if err := aesKey.WithBytes(func(b []byte) {
		for i := range b {
			b[i] = byte(i + 1)
		}
	}); err != nil {
		t.Fatalf("fill AES key: %v", err)
	}

	x, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("GenerateX25519Key: %v", err)
	}
	defer func() { _ = x.Destroy() }()
	peer, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("GenerateX25519Key(peer): %v", err)
	}
	defer func() { _ = peer.Destroy() }()
	peerPub, err := peer.PublicKey()
	if err != nil {
		t.Fatalf("peer.PublicKey: %v", err)
	}

	kem, err := GenerateMLKEM768Key(AllowHeapTransients())
	if err != nil {
		t.Fatalf("GenerateMLKEM768Key: %v", err)
	}
	defer func() { _ = kem.Destroy() }()
	ekBytes, err := kem.EncapsulationKeyBytes()
	if err != nil {
		t.Fatalf("EncapsulationKeyBytes: %v", err)
	}
	ek, err := mlkem.NewEncapsulationKey768(ekBytes)
	if err != nil {
		t.Fatalf("NewEncapsulationKey768: %v", err)
	}
	_, kemCT := ek.Encapsulate()

	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer func() { _ = signer.Destroy() }()
	msg := []byte("signed after the wipe")

	// Each operation works before the wipe; without this the refusals below
	// could be failures of the test's own setup.
	ops := []struct {
		name string
		run  func() (produced bool, err error)
	}{
		{"WithAESGCM", func() (bool, error) {
			called := false
			err := WithAESGCM(aesKey, func(aead cipher.AEAD) error {
				called = true
				_ = aead.Seal(nil, make([]byte, aead.NonceSize()), []byte("plaintext"), nil)
				return nil
			})
			return called, err
		}},
		{"X25519Key.SharedSecret", func() (bool, error) {
			ss, err := x.SharedSecret(peerPub)
			if ss != nil {
				_ = ss.Destroy()
			}
			return ss != nil, err
		}},
		{"X25519Key.WithScalar", func() (bool, error) {
			called := false
			err := x.WithScalar(func([]byte) error { called = true; return nil })
			return called, err
		}},
		{"MLKEM768Key.Decapsulate", func() (bool, error) {
			ss, err := kem.Decapsulate(kemCT)
			if ss != nil {
				_ = ss.Destroy()
			}
			return ss != nil, err
		}},
		{"Ed25519Signer.Sign", func() (bool, error) {
			sig, err := signer.Sign(nil, msg, crypto.Hash(0))
			return sig != nil, err
		}},
		{"Ed25519Signer.WithSeed", func() (bool, error) {
			called := false
			err := signer.WithSeed(func([]byte) error { called = true; return nil })
			return called, err
		}},
	}

	for _, op := range ops {
		if produced, err := op.run(); err != nil || !produced {
			t.Fatalf("%s before the wipe: produced=%v err=%v", op.name, produced, err)
		}
	}

	if err := secmem.WipeAllSecrets(); err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}

	for _, op := range ops {
		produced, err := op.run()
		if !errors.Is(err, secmem.ErrWiped) {
			t.Errorf("%s after WipeAllSecrets: err = %v, want secmem.ErrWiped", op.name, err)
		}
		if produced {
			t.Errorf("%s after WipeAllSecrets produced output from a wiped key", op.name)
		}
	}
}
