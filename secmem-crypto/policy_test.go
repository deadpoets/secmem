package secmemcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/deadpoets/secmem"
	"golang.org/x/crypto/ssh"
)

// The tests in this file swap the package-level policy, so none of them may
// call t.Parallel(): a top-level test that does not is never run alongside
// the parallel ones.

// withPolicy runs fn with heapTransientsAllowed forced to allowed, restoring
// the shipped policy afterwards whatever fn does.
func withPolicy(t *testing.T, allowed bool, fn func()) {
	t.Helper()
	orig := heapTransientsAllowed
	defer func() { heapTransientsAllowed = orig }()
	heapTransientsAllowed = func() bool { return allowed }
	fn()
}

// TestHeapTransientsPolicy_DefaultIsRuntimeSecret pins the shipped policy to
// the runtime/secret posture, by identity as well as by value, so a revert to
// a permissive default fails here instead of shipping quietly.
func TestHeapTransientsPolicy_DefaultIsRuntimeSecret(t *testing.T) {
	if reflect.ValueOf(heapTransientsAllowed).Pointer() != reflect.ValueOf(secmem.RuntimeSecretActive).Pointer() {
		t.Fatal("heapTransientsAllowed is not secmem.RuntimeSecretActive; the gate's default has been changed")
	}
	if heapTransientsAllowed() != secmem.RuntimeSecretActive() {
		t.Fatalf("heapTransientsAllowed() = %v, RuntimeSecretActive() = %v", heapTransientsAllowed(), secmem.RuntimeSecretActive())
	}
}

// TestHeapTransientsPolicy_LegacyRefusesConstructors: with the policy
// refusing, as on every build without GOEXPERIMENT=runtimesecret, all four
// constructors refuse with ErrHeapTransients — before they look at their
// input, and without taking ownership of a buffer they were handed — and all
// four succeed once the caller passes AllowHeapTransients.
func TestHeapTransientsPolicy_LegacyRefusesConstructors(t *testing.T) {
	withPolicy(t, false, func() {
		// Before the input is read: a nil buffer is refused by the gate, not
		// reported as a nil buffer.
		if _, err := NewRSASigner(nil); !errors.Is(err, ErrHeapTransients) {
			t.Errorf("NewRSASigner(nil): %v, want ErrHeapTransients before input validation", err)
		}
		if _, err := NewECDSASigner(elliptic.P256(), nil); !errors.Is(err, ErrHeapTransients) {
			t.Errorf("NewECDSASigner(nil): %v, want ErrHeapTransients before input validation", err)
		}
		if _, err := GenerateRSASigner(2048); !errors.Is(err, ErrHeapTransients) {
			t.Errorf("GenerateRSASigner: %v, want ErrHeapTransients", err)
		}
		if _, err := GenerateECDSASigner(elliptic.P256()); !errors.Is(err, ErrHeapTransients) {
			t.Errorf("GenerateECDSASigner: %v, want ErrHeapTransients", err)
		}

		// A refused constructor does not take ownership: the caller's buffer
		// is still live and still the caller's to destroy.
		der := mustBuffer(t, x509.MarshalPKCS1PrivateKey(testRSAKey()))
		defer func() { _ = der.Destroy() }()
		if _, err := NewRSASigner(der); !errors.Is(err, ErrHeapTransients) {
			t.Fatalf("NewRSASigner: %v, want ErrHeapTransients", err)
		}
		if der.IsDestroyed() {
			t.Error("a refused NewRSASigner destroyed the caller's buffer; ownership must not transfer on failure")
		}

		ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		scalar, err := ek.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		sb := mustBuffer(t, scalar)
		defer func() { _ = sb.Destroy() }()
		if _, err := NewECDSASigner(elliptic.P256(), sb); !errors.Is(err, ErrHeapTransients) {
			t.Fatalf("NewECDSASigner: %v, want ErrHeapTransients", err)
		}
		if sb.IsDestroyed() {
			t.Error("a refused NewECDSASigner destroyed the caller's buffer; ownership must not transfer on failure")
		}

		// The error tells the caller every way out, the opt-in included.
		_, err = GenerateECDSASigner(elliptic.P256())
		for _, want := range []string{"GOEXPERIMENT=runtimesecret", "HSM", "AllowHeapTransients"} {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("refusal message %q does not mention %q", err, want)
			}
		}

		// The opt-in: all four proceed. The signers take ownership of der and
		// sb; the deferred Destroys above are then no-ops, Destroy being
		// idempotent.
		if s, err := NewRSASigner(der, AllowHeapTransients()); err != nil {
			t.Errorf("NewRSASigner with AllowHeapTransients: %v", err)
		} else {
			_ = s.Destroy()
		}
		if s, err := NewECDSASigner(elliptic.P256(), sb, AllowHeapTransients()); err != nil {
			t.Errorf("NewECDSASigner with AllowHeapTransients: %v", err)
		} else {
			_ = s.Destroy()
		}
		if s, err := GenerateRSASigner(2048, AllowHeapTransients()); err != nil {
			t.Errorf("GenerateRSASigner with AllowHeapTransients: %v", err)
		} else {
			_ = s.Destroy()
		}
		if s, err := GenerateECDSASigner(elliptic.P256(), AllowHeapTransients()); err != nil {
			t.Errorf("GenerateECDSASigner with AllowHeapTransients: %v", err)
		} else {
			_ = s.Destroy()
		}

		// A nil Option is ignored, not a panic and not an opt-in.
		if _, err := GenerateECDSASigner(elliptic.P256(), nil); !errors.Is(err, ErrHeapTransients) {
			t.Errorf("GenerateECDSASigner(nil option): %v, want ErrHeapTransients", err)
		}
	})
}

// TestHeapTransientsPolicy_LegacyParsers: the parsers apply the same gate by
// key type. An Ed25519 file parses without the option, because Ed25519 signs
// in place; an EC or RSA file is refused without it and parses with it. Both
// entry points, every key type the parser reads.
func TestHeapTransientsPolicy_LegacyParsers(t *testing.T) {
	withPolicy(t, false, func() {
		for _, k := range parseTestKeys(t) {
			pkcs8, err := x509.MarshalPKCS8PrivateKey(k.priv)
			if err != nil {
				t.Fatalf("%s: marshal: %v", k.name, err)
			}
			gated := k.name != "ed25519"

			s, err := ParsePrivateKey(pkcs8)
			switch {
			case gated && !errors.Is(err, ErrHeapTransients):
				t.Errorf("ParsePrivateKey(%s) without the option: %v, want ErrHeapTransients", k.name, err)
			case !gated && err != nil:
				t.Errorf("ParsePrivateKey(%s) without the option: %v, want success (Ed25519 is never gated)", k.name, err)
			}
			if s != nil {
				_ = s.Destroy()
			}
			if s, err := ParsePrivateKey(pkcs8, AllowHeapTransients()); err != nil {
				t.Errorf("ParsePrivateKey(%s) with AllowHeapTransients: %v", k.name, err)
			} else {
				_ = s.Destroy()
			}

			if !k.openssh {
				continue
			}
			block, err := ssh.MarshalPrivateKeyWithPassphrase(k.priv, "", []byte(testPassphrase))
			if err != nil {
				t.Fatalf("%s: marshal encrypted: %v", k.name, err)
			}
			file := pemEncodeToMemory(block)
			s, err = ParsePrivateKeyWithPassphrase(file, []byte(testPassphrase))
			switch {
			case gated && !errors.Is(err, ErrHeapTransients):
				t.Errorf("ParsePrivateKeyWithPassphrase(%s) without the option: %v, want ErrHeapTransients", k.name, err)
			case !gated && err != nil:
				t.Errorf("ParsePrivateKeyWithPassphrase(%s) without the option: %v, want success", k.name, err)
			}
			if s != nil {
				_ = s.Destroy()
			}
			if s, err := ParsePrivateKeyWithPassphrase(file, []byte(testPassphrase), AllowHeapTransients()); err != nil {
				t.Errorf("ParsePrivateKeyWithPassphrase(%s) with AllowHeapTransients: %v", k.name, err)
			} else {
				_ = s.Destroy()
			}
		}
	})
}

// TestHeapTransientsPolicy_RuntimeSecretAllows: with the policy allowing, as
// on a GOEXPERIMENT=runtimesecret build, nothing is refused and the option is
// not needed. Testable on any host because the policy is a package var.
func TestHeapTransientsPolicy_RuntimeSecretAllows(t *testing.T) {
	withPolicy(t, true, func() {
		if s, err := GenerateECDSASigner(elliptic.P256()); err != nil {
			t.Errorf("GenerateECDSASigner under an allowing policy: %v", err)
		} else {
			_ = s.Destroy()
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(testRSAKey())
		if err != nil {
			t.Fatal(err)
		}
		if s, err := ParsePrivateKey(pkcs8); err != nil {
			t.Errorf("ParsePrivateKey(rsa) under an allowing policy: %v", err)
		} else {
			_ = s.Destroy()
		}
	})
}
