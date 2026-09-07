package secmemcrypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/deadpoets/secmem"
)

// bufferBytes copies a SecureBuffer's contents out for a test that needs a
// plain []byte to hand to x/crypto or a file.
func bufferBytes(t testing.TB, b *secmem.SecureBuffer) []byte {
	t.Helper()
	var out []byte
	if err := b.WithBytesErr(func(x []byte) error { out = append([]byte(nil), x...); return nil }); err != nil { //nolint:secmem-lint // test reads the output out to parse it with x/crypto/ssh
		t.Fatal(err)
	}
	return out
}

// TestMarshalOpenSSHPrivateKeyWithPassphrase_RoundTrip is the real proof
// for the encrypted egress: what this package writes must open with the
// exact function x/crypto users call, yield the same key, refuse the wrong
// passphrase with the same error, and open with this package's own parser.
func TestMarshalOpenSSHPrivateKeyWithPassphrase_RoundTrip(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	pub := signer.Public().(ed25519.PublicKey)

	buf, err := signer.MarshalOpenSSHPrivateKeyWithPassphrase("a comment", []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Destroy()
	pemBytes := bufferBytes(t, buf)

	key, err := ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("x/crypto cannot open the file: %v", err)
	}
	priv, ok := key.(*ed25519.PrivateKey)
	if !ok {
		t.Fatalf("x/crypto parsed a %T", key)
	}
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		t.Fatal("x/crypto parsed a different key")
	}
	msg := []byte("round trip")
	sig := ed25519.Sign(*priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("the key x/crypto parsed does not sign as the original")
	}

	if _, err := ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte("wrong")); !errors.Is(err, x509.IncorrectPasswordError) {
		t.Errorf("x/crypto with the wrong passphrase: %v, want IncorrectPasswordError", err)
	}
	var missing *ssh.PassphraseMissingError
	if _, err := ssh.ParseRawPrivateKey(pemBytes); !errors.As(err, &missing) {
		t.Errorf("x/crypto without a passphrase: %v, want PassphraseMissingError", err)
	}

	ours, err := ParsePrivateKeyWithPassphrase(pemBytes, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("own parser: %v", err)
	}
	defer ours.Destroy()
	verifySigner(t, ours, pub)
	if _, err := ParsePrivateKey(pemBytes); !errors.Is(err, ErrEncryptedKey) {
		t.Errorf("own plain parser: %v, want ErrEncryptedKey", err)
	}
}

// TestMarshalOpenSSHPrivateKey_ContainerLayout decodes what both marshal
// forms write and checks the header fields OpenSSH will read: cipher and
// KDF names, a 16-byte salt and 16 rounds for the protected form, "none"
// and empty options for the plain one, one key, and a public block that is
// the signer's key.
func TestMarshalOpenSSHPrivateKey_ContainerLayout(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	sshPub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}

	plain, err := signer.MarshalOpenSSHPrivateKey("c")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Destroy()
	enc, err := signer.MarshalOpenSSHPrivateKeyWithPassphrase("c", []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Destroy()

	decode := func(b *secmem.SecureBuffer) opensshHeader {
		block, rest := pem.Decode(bufferBytes(t, b))
		if block == nil || len(rest) != 0 || block.Type != opensshPEMType || len(block.Headers) != 0 {
			t.Fatal("output is not exactly one OpenSSH PEM block")
		}
		h, err := readOpenSSHHeader(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	p, e := decode(plain), decode(enc)
	if string(p.cipher) != "none" || string(p.kdf) != "none" || len(p.kdfOpts) != 0 || p.numKeys != 1 {
		t.Errorf("plain header: cipher %q kdf %q opts %d keys %d", p.cipher, p.kdf, len(p.kdfOpts), p.numKeys)
	}
	if len(p.privBlock)%8 != 0 {
		t.Errorf("plain private block is %d bytes, not a multiple of 8", len(p.privBlock))
	}
	if string(e.cipher) != "aes256-ctr" || string(e.kdf) != "bcrypt" || e.numKeys != 1 {
		t.Errorf("encrypted header: cipher %q kdf %q keys %d", e.cipher, e.kdf, e.numKeys)
	}
	o := sshReader{e.kdfOpts}
	salt, ok1 := o.str()
	rounds, ok2 := o.uint32()
	if !ok1 || !ok2 || len(o.b) != 0 || len(salt) != 16 || rounds != 16 {
		t.Errorf("encrypted KDF options: salt %d bytes, %d rounds", len(salt), rounds)
	}
	if len(e.privBlock)%16 != 0 {
		t.Errorf("encrypted private block is %d bytes, not a multiple of 16", len(e.privBlock))
	}
	for name, h := range map[string]opensshHeader{"plain": p, "encrypted": e} {
		if !bytes.Equal(h.pubBlob, sshPub.Marshal()) {
			t.Errorf("%s: public block is not the signer's public key", name)
		}
	}

	// Two encrypted files of the same key differ: fresh salt and check.
	enc2, err := signer.MarshalOpenSSHPrivateKeyWithPassphrase("c", []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer enc2.Destroy()
	if bytes.Equal(bufferBytes(t, enc), bufferBytes(t, enc2)) {
		t.Error("two encryptions of the same key are byte-identical: the salt is not fresh")
	}
}

// TestMarshalOpenSSHPrivateKey_PEMMatchesEncodingPEM proves the in-place
// PEM writer lays the armour out exactly as encoding/pem would for the same
// container: decode ours, re-encode with the standard library, compare.
func TestMarshalOpenSSHPrivateKey_PEMMatchesEncodingPEM(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	// Comment lengths that put the container on every side of a 48-byte
	// line boundary.
	for _, comment := range []string{"", "x", strings.Repeat("y", 47), strings.Repeat("z", 48), strings.Repeat("w", 200)} {
		buf, err := signer.MarshalOpenSSHPrivateKey(comment)
		if err != nil {
			t.Fatal(err)
		}
		ours := bufferBytes(t, buf)
		buf.Destroy()
		block, rest := pem.Decode(ours)
		if block == nil || len(rest) != 0 {
			t.Fatalf("comment %d: output is not one PEM block", len(comment))
		}
		if theirs := pem.EncodeToMemory(block); !bytes.Equal(ours, theirs) {
			t.Fatalf("comment %d: PEM layout differs from encoding/pem's", len(comment))
		}
		if len(ours) != pemLen(opensshPEMType, len(block.Bytes)) {
			t.Fatalf("comment %d: pemLen says %d, output is %d", len(comment), pemLen(opensshPEMType, len(block.Bytes)), len(ours))
		}
	}
}

// TestMarshalOpenSSHPrivateKeyWithPassphrase_Refusals pins the empty
// passphrase and the nil / destroyed receiver.
func TestMarshalOpenSSHPrivateKeyWithPassphrase_Refusals(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.MarshalOpenSSHPrivateKeyWithPassphrase("c", nil); err == nil || !strings.Contains(err.Error(), "empty passphrase") {
		t.Errorf("empty passphrase: %v", err)
	}
	var nilSigner *Ed25519Signer
	if _, err := nilSigner.MarshalOpenSSHPrivateKeyWithPassphrase("c", []byte("p")); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil signer: %v, want ErrDestroyed", err)
	}
	if err := signer.Destroy(); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.MarshalOpenSSHPrivateKeyWithPassphrase("c", []byte("p")); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("destroyed signer: %v, want ErrDestroyed", err)
	}
}

// TestMarshalOpenSSHPrivateKeyWithPassphrase_WipesAESBlock aliases the
// round keys at wipe time and asserts they are zero after the marshal
// returns; and pins that a wipe that cannot locate them fails the marshal.
// Must not call t.Parallel(): it swaps a package var.
func TestMarshalOpenSSHPrivateKeyWithPassphrase_WipesAESBlock(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()

	var aliased [][]byte
	orig := wipeAESBlock
	wipeAESBlock = func(b cipher.Block) error {
		for _, f := range aesRoundKeyFields {
			if keys, err := aesRoundKeys(b, f); err == nil {
				aliased = append(aliased, keys)
			}
		}
		return orig(b)
	}
	buf, err := signer.MarshalOpenSSHPrivateKeyWithPassphrase("c", []byte(testPassphrase))
	wipeAESBlock = orig
	if err != nil {
		t.Fatal(err)
	}
	buf.Destroy()
	if len(aliased) != len(aesRoundKeyFields) {
		t.Fatalf("aliased %d schedules, want %d", len(aliased), len(aesRoundKeyFields))
	}
	for i, keys := range aliased {
		if !bytes.Equal(keys, make([]byte, len(keys))) {
			t.Fatalf("round keys %q live after the marshal returned", aesRoundKeyFields[i])
		}
	}

	wipeAESBlock = func(cipher.Block) error { return errors.New("simulated: round keys NOT wiped") }
	defer func() { wipeAESBlock = orig }()
	if buf, err := signer.MarshalOpenSSHPrivateKeyWithPassphrase("c", []byte(testPassphrase)); err == nil {
		buf.Destroy()
		t.Fatal("marshal succeeded although the AES schedule could not be wiped")
	}
}

// sshKeygenPublicKey runs `ssh-keygen -y` on a private-key file and returns
// "type base64" from its output, or skips when the tool is not installed.
func sshKeygenPublicKey(t *testing.T, pemBytes []byte, passphrase string) string {
	t.Helper()
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-y", "-P", passphrase, "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -y: %v\n%s", err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		t.Fatalf("ssh-keygen -y printed %q", out)
	}
	return fields[0] + " " + fields[1]
}

// TestMarshalOpenSSHPrivateKey_SSHKeygenOpensBothForms is the interop
// proof against the real tool: ssh-keygen must read both files this
// package writes and print the signer's public key.
func TestMarshalOpenSSHPrivateKey_SSHKeygenOpensBothForms(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	sshPub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	plain, err := signer.MarshalOpenSSHPrivateKey("interop")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Destroy()
	if got := sshKeygenPublicKey(t, bufferBytes(t, plain), ""); got != want {
		t.Errorf("ssh-keygen read the plain file as %q, want %q", got, want)
	}

	enc, err := signer.MarshalOpenSSHPrivateKeyWithPassphrase("interop", []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Destroy()
	if got := sshKeygenPublicKey(t, bufferBytes(t, enc), testPassphrase); got != want {
		t.Errorf("ssh-keygen read the encrypted file as %q, want %q", got, want)
	}
}
