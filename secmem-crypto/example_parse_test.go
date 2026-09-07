package secmemcrypto_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"

	"github.com/deadpoets/secmem"
	secmemcrypto "github.com/deadpoets/secmem/secmem-crypto"
)

// ExampleParsePrivateKey loads an OpenSSH private-key file the way a
// hardened program should: the file bytes go into a SecureBuffer, the key is
// parsed from inside that buffer's borrow (the seed never lands on the
// heap), and the signer is handed to x/crypto/ssh through AsSSH.
func ExampleParsePrivateKey() {
	// Stand-in for the file on disk: an ssh-keygen-style OpenSSH key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		log.Fatal(err)
	}
	file := pem.EncodeToMemory(block)

	// Read the file into locked memory rather than os.ReadFile's heap slice.
	buf, _, err := secmem.NewBufferFromReader(bytes.NewReader(file), len(file))
	if err != nil {
		log.Fatal(err)
	}
	defer buf.Destroy()

	var signer secmemcrypto.Signer
	if err := buf.WithBytesErr(func(b []byte) error {
		var perr error
		signer, perr = secmemcrypto.ParsePrivateKey(b)
		return perr
	}); err != nil {
		log.Fatal(err)
	}
	defer signer.Destroy()

	sshSigner, err := secmemcrypto.AsSSH(signer)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sshSigner.PublicKey().Type())
	// Output: ssh-ed25519
}

// ExampleParsePrivateKeyWithPassphrase writes a passphrase-protected key
// file and reads it back: the format ssh-keygen produces for every key type
// when a passphrase is given. The passphrase and the file both come from
// SecureBuffers; nothing secret goes through the heap on either side.
func ExampleParsePrivateKeyWithPassphrase() {
	signer, err := secmemcrypto.GenerateEd25519Signer()
	if err != nil {
		log.Fatal(err)
	}
	defer signer.Destroy()

	passphrase, err := secmem.NewBuffer([]byte("correct horse battery staple"))
	if err != nil {
		log.Fatal(err)
	}
	defer passphrase.Destroy()

	// Stand-in for the file on disk.
	var file *secmem.SecureBuffer
	if err := passphrase.WithBytesErr(func(p []byte) error {
		var merr error
		file, merr = signer.MarshalOpenSSHPrivateKeyWithPassphrase("laptop", p)
		return merr
	}); err != nil {
		log.Fatal(err)
	}
	defer file.Destroy()

	var loaded secmemcrypto.Signer
	if err := file.WithBytesErr(func(f []byte) error {
		return passphrase.WithBytesErr(func(p []byte) error {
			var perr error
			loaded, perr = secmemcrypto.ParsePrivateKeyWithPassphrase(f, p)
			return perr
		})
	}); err != nil {
		log.Fatal(err)
	}
	defer loaded.Destroy()

	fmt.Println(loaded.Public().(ed25519.PublicKey).Equal(signer.Public()))
	// Output: true
}
