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
