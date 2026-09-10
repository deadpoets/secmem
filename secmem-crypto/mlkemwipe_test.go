package secmemcrypto

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/deadpoets/secmem"
)

// These tests pin wipeMLKEMDecapsulationKey to the current toolchain, the
// way aeswipe_test.go pins the AES round-key wipe: the helper reaches
// crypto/mlkem's unexported fields by name via reflection, which no
// compiler check protects, so a stdlib refactor must turn into a red run on
// the first CI pass of a new Go version — not into a wipe that quietly
// stopped wiping under a Decapsulate that still succeeds.

// TestWipeMLKEMDecapsulationKey_Tripwire proves, on this toolchain, that
// (1) the three reflected fields resolve to non-empty arrays holding the
// seed halves and a non-zero s, (2) the wipe reports success, and (3) the
// key no longer decapsulates afterwards and its Bytes() — crypto/mlkem's
// own view of d || z — reads as zero: two oracles independent of the
// reflection path, so a field that still exists but is no longer what the
// key uses is caught too.
func TestWipeMLKEMDecapsulationKey_Tripwire(t *testing.T) {
	t.Parallel()
	seed := make([]byte, mlkem.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := mlkem.NewEncapsulationKey768(dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	shared, ct := ek.Encapsulate()
	if got, err := dk.Decapsulate(ct); err != nil || !bytes.Equal(got, shared) {
		t.Fatalf("fresh key does not decapsulate: %v", err)
	}

	views := map[string][]byte{}
	for _, field := range mlkemSecretFields {
		b, err := mlkemSecretBytes(dk, field)
		if err != nil {
			t.Fatalf("crypto/mlkem field %q no longer resolves on this toolchain — update mlkemSecretFields: %v", field, err)
		}
		if bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("field %q is all zero on a freshly expanded key: not the secret", field)
		}
		views[field] = b
	}
	if !bytes.Equal(views["d"], seed[:32]) || !bytes.Equal(views["z"], seed[32:]) {
		t.Fatalf("reflected d/z = %x/%x, want the seed halves %x/%x", views["d"], views["z"], seed[:32], seed[32:])
	}
	if len(views["s"]) != 3*256*2 {
		t.Fatalf("field s is %d bytes, want 1536 ([3][256]uint16)", len(views["s"]))
	}

	if err := wipeMLKEMDecapsulationKey(dk); err != nil {
		t.Fatalf("wipeMLKEMDecapsulationKey: %v", err)
	}
	for field, b := range views {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("field %q still holds the secret after the wipe", field)
		}
	}
	if got := dk.Bytes(); !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatalf("dk.Bytes() after wipe = %x, want zero: the reflected d/z are not the fields the key uses", got)
	}
	if got, err := dk.Decapsulate(ct); err == nil && bytes.Equal(got, shared) {
		t.Fatal("the key still decapsulates after the wipe: the reflected s is not the decryption key it uses")
	}

	if err := wipeMLKEMDecapsulationKey(nil); err != nil {
		t.Errorf("wipeMLKEMDecapsulationKey(nil) = %v, want nil", err)
	}
}

// TestMLKEMSecretBytes_ReportsUnresolvableField pins the fail-loud half: a
// missing field and a field of the wrong shape must each be reported as
// NOT wiped, never returned as if wiped.
func TestMLKEMSecretBytes_ReportsUnresolvableField(t *testing.T) {
	t.Parallel()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, field string }{
		{"missing field", "noSuchField"},
		{"wrong shape", "encryptionKey"}, // a struct, not an array
	} {
		b, err := mlkemSecretBytes(dk, tc.field)
		if err == nil {
			t.Errorf("%s: reported success with %d bytes", tc.name, len(b))
			continue
		}
		if !strings.Contains(err.Error(), "NOT wiped") {
			t.Errorf("%s: error does not say the key was not wiped: %v", tc.name, err)
		}
	}
	if _, _, err := mlkemInnerType(nil); err == nil || !strings.Contains(err.Error(), "NOT wiped") {
		t.Errorf("nil type: got %v", err)
	}
	if b := dk.Bytes(); bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("a failed lookup must leave the key untouched")
	}
}

// TestMLKEM768Key_WipesLiveExpansion wraps the package's wipe var to alias
// the expanded key's seed halves and s at the moment each path wipes them,
// and asserts those exact arrays are zero once the call has returned — for
// construction and for Decapsulate. Must not call t.Parallel(): it swaps a
// package var (see livewipe_test.go).
func TestMLKEM768Key_WipesLiveExpansion(t *testing.T) {
	var fired int
	var aliased [][]byte
	orig := wipeMLKEMDecapsulationKey
	wipeMLKEMDecapsulationKey = func(dk *mlkem.DecapsulationKey768) error {
		fired++
		for _, field := range mlkemSecretFields {
			if b, err := mlkemSecretBytes(dk, field); err == nil {
				aliased = append(aliased, b)
			}
		}
		return orig(dk)
	}
	defer func() { wipeMLKEMDecapsulationKey = orig }()

	k, err := GenerateMLKEM768Key()
	if err != nil {
		t.Skipf("GenerateMLKEM768Key: %v", err)
	}
	defer k.Destroy()
	if fired != 1 {
		t.Fatalf("construction fired the wipe %d times, want 1", fired)
	}
	ekBytes, err := k.EncapsulationKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	if fired != 1 {
		t.Fatalf("EncapsulationKeyBytes expanded the seed (wipe fired %d times); it must use the cached key", fired)
	}
	ct, shared, err := Encapsulate(ekBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Destroy()
	got, err := k.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	defer got.Destroy()
	if fired != 2 {
		t.Fatalf("Decapsulate fired the wipe %d times in total, want 2", fired)
	}
	if len(aliased) != 2*len(mlkemSecretFields) {
		t.Fatalf("aliased %d arrays, want %d", len(aliased), 2*len(mlkemSecretFields))
	}
	for i, b := range aliased {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("expanded-key array %d is not zero after the call returned", i)
		}
	}
	var equal bool
	_ = shared.WithBytesErr(func(a []byte) error {
		return got.WithBytesErr(func(b []byte) error {
			equal = bytes.Equal(a, b)
			return nil
		})
	})
	if !equal {
		t.Fatal("shared secrets differ: the wipe hook broke decapsulation")
	}
}

// TestMLKEM768Key_WipeFailureIsAnError pins the fail-closed contract: when
// the wipe cannot locate the expansion, construction and Decapsulate return
// the error rather than reporting success over a live heap copy.
func TestMLKEM768Key_WipeFailureIsAnError(t *testing.T) {
	k, err := GenerateMLKEM768Key()
	if err != nil {
		t.Skipf("GenerateMLKEM768Key: %v", err)
	}
	defer k.Destroy()
	ekBytes, _ := k.EncapsulationKeyBytes()
	ct, shared, err := Encapsulate(ekBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Destroy()

	orig := wipeMLKEMDecapsulationKey
	wipeMLKEMDecapsulationKey = func(dk *mlkem.DecapsulationKey768) error {
		_ = orig(dk)
		return errWipeSimulated
	}
	defer func() { wipeMLKEMDecapsulationKey = orig }()

	if out, err := k.Decapsulate(ct); err == nil {
		out.Destroy()
		t.Fatal("Decapsulate reported success although the wipe failed")
	} else if !strings.Contains(err.Error(), errWipeSimulated.Error()) {
		t.Fatalf("Decapsulate error does not carry the wipe failure: %v", err)
	}
	seed, err := secmem.NewEmptyBuffer(mlkem.SeedSize)
	if err != nil {
		t.Skip(err)
	}
	defer seed.Destroy()
	if k2, err := NewMLKEM768Key(seed); err == nil {
		k2.Destroy()
		t.Fatal("NewMLKEM768Key reported success although the wipe failed")
	}
}
