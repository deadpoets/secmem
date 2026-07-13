package secmemcrypto_test

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	secmemcrypto "github.com/deadpoets/secmem/secmem-crypto"

	"github.com/deadpoets/secmem"
)

// A Signer drops into any crypto.Signer consumer (TLS, x509, SSH, JWT/JOSE),
// with the Ed25519 seed kept in locked, off-heap memory for its lifetime.
func ExampleSigner() {
	signer, err := secmemcrypto.GenerateEd25519Signer()
	if err != nil {
		panic(err)
	}
	defer signer.Destroy()

	msg := []byte("sign me")
	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		panic(err)
	}

	pub := signer.Public().(ed25519.PublicKey)
	fmt.Println(ed25519.Verify(pub, msg, sig))
	// Output: true
}

// GenerateEd25519Signer traps the seed in protected memory. To persist a
// generated key (write it to a keyring, seal it to disk), read it out
// through WithSeed — the one deliberate egress point.
func ExampleSigner_WithSeed() {
	signer, err := secmemcrypto.GenerateEd25519Signer()
	if err != nil {
		panic(err)
	}
	defer signer.Destroy()

	// Persist the seed somewhere durable (shown here as a local copy the
	// caller is now responsible for protecting and wiping).
	stored := make([]byte, ed25519.SeedSize)
	if err := signer.WithSeed(func(seed []byte) error {
		copy(stored, seed)
		return nil
	}); err != nil {
		panic(err)
	}

	// Later: reload into a fresh SecureBuffer and reconstruct the signer.
	buf, err := secmem.NewBuffer(stored) // NewBuffer wipes `stored` after copying
	if err != nil {
		panic(err)
	}
	restored, err := secmemcrypto.NewEd25519Signer(buf)
	if err != nil {
		panic(err)
	}
	defer restored.Destroy()

	fmt.Println(restored.Equal(signer.Public()))
	// Output: true
}

// OpenInto decrypts an AEAD ciphertext straight into a SecureBuffer, so the
// plaintext secret never exists as a heap []byte the garbage collector would
// hold onto. Size the output buffer to exactly the plaintext length.
func ExampleOpenInto() {
	// A key and an encrypted secret you loaded from disk or the network.
	key := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, gcm.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	secret := []byte("api-token-value")
	ciphertext := gcm.Seal(nil, nonce, secret, nil)

	// Decrypt directly into protected memory.
	out, err := secmem.NewEmptyBuffer(len(ciphertext) - gcm.Overhead())
	if err != nil {
		panic(err)
	}
	defer out.Destroy()
	if err := secmemcrypto.OpenInto(out, gcm, nonce, ciphertext, nil); err != nil {
		panic(err) // authentication failure leaves out zeroed
	}

	_ = out.WithBytesErr(func(plaintext []byte) error {
		fmt.Printf("recovered %d bytes\n", len(plaintext))
		return nil
	})
	// Output: recovered 15 bytes
}

// Key32 does X25519 Diffie-Hellman with the private scalar held off-heap;
// the agreed shared secret is returned in a fresh SecureBuffer.
func ExampleKey32() {
	alice, err := secmemcrypto.GenerateKey32()
	if err != nil {
		panic(err)
	}
	defer alice.Destroy()
	bob, err := secmemcrypto.GenerateKey32()
	if err != nil {
		panic(err)
	}
	defer bob.Destroy()

	alicePub, _ := alice.PublicKey()
	bobPub, _ := bob.PublicKey()

	// Each side computes the same shared secret from its own private key and
	// the peer's public key.
	aShared, _ := alice.SharedSecret(bobPub)
	defer aShared.Destroy()
	bShared, _ := bob.SharedSecret(alicePub)
	defer bShared.Destroy()

	// The two shared secrets agree — compared in constant time, borrowing
	// bob's copy to check against alice's.
	agree := false
	_ = bShared.WithBytesErr(func(b []byte) error {
		eq, err := aShared.ConstantTimeEqual(b)
		agree = eq
		return err
	})
	fmt.Println(agree)
	// Output: true
}

// An ECDSASigner drops into any crypto.Signer consumer with the P-256
// scalar held off-heap between operations — see the type's honesty caveat
// for what happens during one. Unlike Ed25519, ECDSA signs a digest.
func ExampleECDSASigner() {
	signer, err := secmemcrypto.GenerateECDSASigner(elliptic.P256())
	if err != nil {
		panic(err)
	}
	defer signer.Destroy()

	digest := sha256.Sum256([]byte("sign me"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		panic(err)
	}

	pub := signer.Public().(*ecdsa.PublicKey)
	fmt.Println(ecdsa.VerifyASN1(pub, digest[:], sig))
	// Output: true
}

// AsSSH adapts any of this package's signers (or any crypto.Signer) for
// golang.org/x/crypto/ssh. For RSA keys it also makes the legacy ssh-rsa
// (SHA-1) algorithm unreachable.
func ExampleAsSSH() {
	signer, err := secmemcrypto.GenerateEd25519Signer()
	if err != nil {
		panic(err)
	}
	defer signer.Destroy()

	sshSigner, err := secmemcrypto.AsSSH(signer)
	if err != nil {
		panic(err)
	}
	fmt.Println(sshSigner.PublicKey().Type())
	// Output: ssh-ed25519
}
