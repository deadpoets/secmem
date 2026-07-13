package secmemcrypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestAsSSH_Ed25519(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer signer.Destroy()

	sshSigner, err := AsSSH(signer)
	if err != nil {
		t.Fatalf("AsSSH: %v", err)
	}
	if got := sshSigner.PublicKey().Type(); got != ssh.KeyAlgoED25519 {
		t.Errorf("public key type = %q, want %q", got, ssh.KeyAlgoED25519)
	}

	data := []byte("ssh signing data")
	sig, err := sshSigner.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sshSigner.PublicKey().Verify(data, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestAsSSH_ECDSA(t *testing.T) {
	t.Parallel()
	signer, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSASigner: %v", err)
	}
	defer signer.Destroy()

	sshSigner, err := AsSSH(signer)
	if err != nil {
		t.Fatalf("AsSSH: %v", err)
	}
	if got := sshSigner.PublicKey().Type(); got != ssh.KeyAlgoECDSA256 {
		t.Errorf("public key type = %q, want %q", got, ssh.KeyAlgoECDSA256)
	}

	data := []byte("ssh signing data")
	sig, err := sshSigner.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sshSigner.PublicKey().Verify(data, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// TestAsSSH_RSA pins the whole point of AsSSH: every signing path on the
// returned signer produces rsa-sha2, and legacy ssh-rsa (SHA-1) is
// unreachable — by negotiation (Algorithms), by explicit request
// (SignWithAlgorithm), and by the plain Sign default.
func TestAsSSH_RSA(t *testing.T) {
	t.Parallel()
	s := testRSASigner(t)

	sshSigner, err := AsSSH(s)
	if err != nil {
		t.Fatalf("AsSSH: %v", err)
	}
	multi, ok := sshSigner.(ssh.MultiAlgorithmSigner)
	if !ok {
		t.Fatalf("AsSSH(RSA) returned %T, want ssh.MultiAlgorithmSigner", sshSigner)
	}
	want := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	if got := multi.Algorithms(); !slices.Equal(got, want) {
		t.Errorf("Algorithms() = %v, want %v", got, want)
	}

	data := []byte("ssh signing data")

	// Plain Sign must default to the strongest algorithm, not ssh-rsa.
	sig, err := sshSigner.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA512 {
		t.Errorf("plain Sign produced %q, want %q", sig.Format, ssh.KeyAlgoRSASHA512)
	}
	if err := sshSigner.PublicKey().Verify(data, sig); err != nil {
		t.Errorf("Verify(rsa-sha2-512): %v", err)
	}

	sig256, err := multi.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA256)
	if err != nil {
		t.Fatalf("SignWithAlgorithm(rsa-sha2-256): %v", err)
	}
	if sig256.Format != ssh.KeyAlgoRSASHA256 {
		t.Errorf("SignWithAlgorithm produced %q, want %q", sig256.Format, ssh.KeyAlgoRSASHA256)
	}
	if err := sshSigner.PublicKey().Verify(data, sig256); err != nil {
		t.Errorf("Verify(rsa-sha2-256): %v", err)
	}

	if _, err := multi.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSA); err == nil {
		t.Error("SignWithAlgorithm(ssh-rsa) succeeded; SHA-1 must be unreachable")
	}
}

func TestAsSSH_BadInputs(t *testing.T) {
	t.Parallel()
	if _, err := AsSSH(nil); err == nil {
		t.Error("expected error for nil signer")
	}

	// x/crypto/ssh has no algorithm for P-224; the error should surface
	// from NewSignerFromSigner rather than panic.
	p224, err := GenerateECDSASigner(elliptic.P224())
	if err != nil {
		t.Fatalf("GenerateECDSASigner(P-224): %v", err)
	}
	defer p224.Destroy()
	if _, err := AsSSH(p224); err == nil {
		t.Error("expected error for a P-224 key (no SSH algorithm exists)")
	}
}
