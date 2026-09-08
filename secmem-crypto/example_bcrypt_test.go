package secmemcrypto_test

import (
	"fmt"
	"log"

	"github.com/deadpoets/secmem"
	secmemcrypto "github.com/deadpoets/secmem/secmem-crypto"
)

// ExampleBcryptPBKDFInto derives OpenSSH's 48-byte key and IV from a
// passphrase the way ssh-keygen does, with both the passphrase and the
// result in secure memory. Use it when the requirement names bcrypt_pbkdf —
// reading or writing an OpenSSH key file's protection by hand, or matching a
// derivation ssh-keygen performed. For a password KDF chosen fresh, reach
// for Argon2Into instead: it is memory-hard, and this one is not.
func ExampleBcryptPBKDFInto() {
	passphrase, err := secmem.NewBuffer([]byte("correct horse battery staple"))
	if err != nil {
		log.Fatal(err)
	}
	defer passphrase.Destroy()

	// The salt is not secret: OpenSSH stores a fresh 16-byte salt, and the
	// round count, in the key file's header beside the ciphertext.
	salt := []byte("0123456789abcdef")
	const rounds = 16 // ssh-keygen's default; its -a flag sets it

	// Created after the passphrase buffer on purpose: the passphrase is
	// borrowed around the call below, and nested borrows must run
	// oldest-first (see SecureBuffer.LockOrder).
	keyAndIV, err := secmem.NewEmptyBuffer(48) // 32-byte AES-256 key || 16-byte IV
	if err != nil {
		log.Fatal(err)
	}
	defer keyAndIV.Destroy()

	if err := passphrase.WithBytesErr(func(p []byte) error {
		return secmemcrypto.BcryptPBKDFInto(p, salt, rounds, keyAndIV)
	}); err != nil {
		log.Fatal(err)
	}

	// The derived bytes stay in the buffer — use them inside a borrow. Only
	// their shape is printed here.
	fmt.Println(keyAndIV.Len())
	// Output: 48
}
