//lint:file-ignore U1000 the stand-in structs below are read by reflection only; their fields exist to be enumerated, not used.

package secmemcrypto

import (
	"crypto/rsa"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

// The reflective wipes account for every field of the objects they clean:
// each is either a secret the wipe zeroes or a value known to be public, and
// a layout with a field that is neither is refused. These tests drive the
// resolvers with synthetic layouts a future toolchain could produce — the
// real ones are pinned by the tripwire tests beside each wipe.

// TestResolveAESGCMLayout_RefusesUnknownFields: a GCM object whose GHASH
// table has another name, or that grew a field, must not resolve to a layout
// that wipes only the fields it recognises.
func TestResolveAESGCMLayout_RefusesUnknownFields(t *testing.T) {
	//lint:ignore U1000 only the reflected shapes matter
	type block struct {
		rounds   int        //nolint:unused // reflected shape only
		enc, dec [60]uint32 //nolint:unused // reflected shape only
	}
	//lint:ignore U1000 only the reflected shapes matter
	type current struct {
		cipher             block     //nolint:unused // reflected shape only
		nonceSize, tagSize int       //nolint:unused // reflected shape only
		productTable       [256]byte //nolint:unused // reflected shape only
	}
	if l, err := resolveAESGCMLayout(reflect.TypeOf(&current{})); err != nil || len(l.regions) != 3 {
		t.Fatalf("control failed: today's layout resolves to %+v, %v; want three regions", l, err)
	}

	//lint:ignore U1000 only the reflected shapes matter
	type renamedTable struct {
		cipher             block     //nolint:unused // reflected shape only
		nonceSize, tagSize int       //nolint:unused // reflected shape only
		ghashTable         [256]byte //nolint:unused // reflected shape only
	}
	//lint:ignore U1000 only the reflected shapes matter
	type platform struct {
		hashKey [16]byte //nolint:unused // reflected shape only
	}
	//lint:ignore U1000 only the reflected shapes matter
	type embeddedPlatformData struct {
		cipher             block //nolint:unused // reflected shape only
		nonceSize, tagSize int   //nolint:unused // reflected shape only
		platform
	}
	//lint:ignore U1000 only the reflected shapes matter
	type blockWithKey struct {
		rounds   int        //nolint:unused // reflected shape only
		enc, dec [60]uint32 //nolint:unused // reflected shape only
		key      [32]byte   //nolint:unused // reflected shape only
	}
	//lint:ignore U1000 only the reflected shapes matter
	type grownBlock struct {
		cipher             blockWithKey //nolint:unused // reflected shape only
		nonceSize, tagSize int          //nolint:unused // reflected shape only
		productTable       [256]byte    //nolint:unused // reflected shape only
	}
	for name, c := range map[string]struct {
		typ   reflect.Type
		field string
	}{
		"GHASH table renamed":            {reflect.TypeOf(&renamedTable{}), "ghashTable"},
		"platform data with another key": {reflect.TypeOf(&embeddedPlatformData{}), "hashKey"},
		"cipher block grew a field":      {reflect.TypeOf(&grownBlock{}), "key"},
	} {
		l, err := resolveAESGCMLayout(c.typ)
		if err == nil {
			t.Errorf("%s: resolved to %+v; the field %q would be left unwiped", name, l.regions, c.field)
			continue
		}
		if !strings.Contains(err.Error(), c.field) {
			t.Errorf("%s: the refusal does not name %q: %v", name, c.field, err)
		}
	}
}

// TestWipeRSAFIPSKey_RefusesMissingFIPSKey: a private key the standard
// library has precomputed carries its FIPS form; if it does not, the form
// has moved somewhere this wipe does not look, and saying "nothing to wipe"
// would be the silent failure the wipe exists to rule out.
func TestWipeRSAFIPSKey_RefusesMissingFIPSKey(t *testing.T) {
	parsed := stdlibRSAKey(t)
	// A private copy of the struct, with the pointer cleared the way a
	// toolchain that keeps the FIPS key elsewhere would leave it.
	key := *parsed
	f := reflect.ValueOf(&key).Elem().FieldByName("Precomputed").FieldByName(rsaFIPSField)
	if !f.IsValid() || f.Kind() != reflect.Pointer || f.IsNil() {
		t.Fatalf("control failed: a parsed key has no FIPS form at Precomputed.%s", rsaFIPSField)
	}
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().SetZero()

	err := wipeRSAFIPSKey(&key)
	if err == nil {
		t.Fatal("a private key with no FIPS form was reported wiped")
	}
	if !strings.Contains(err.Error(), "NOT wiped") {
		t.Fatalf("the error does not say the key was not wiped: %v", err)
	}
	// A key with no private part has nothing to wipe, FIPS form or not.
	if err := wipeRSAFIPSKey(&rsa.PrivateKey{}); err != nil {
		t.Fatalf("an empty key: %v", err)
	}
}

// TestRSAFIPSSecretViews_RefusesUnknownFields: the FIPS-form key, and the
// bigmod values inside it, with a field this wipe has never seen.
func TestRSAFIPSSecretViews_RefusesUnknownFields(t *testing.T) {
	type nat struct{ limbs []uint }
	type modulus struct {
		nat   *nat
		odd   bool
		m0inv uint
		rr    *nat
	}
	type current struct {
		pub          struct{ N *nat } //nolint:unused // reflected shape only
		d            *nat
		p, q         *modulus
		dP, dQ       []byte
		qInv         *nat
		fipsApproved bool //nolint:unused // reflected shape only
	}
	one := func() *nat { return &nat{limbs: []uint{1}} }
	mod := func() *modulus { return &modulus{nat: one(), rr: one(), m0inv: 1, odd: true} }
	good := &current{d: one(), p: mod(), q: mod(), dP: []byte{1}, dQ: []byte{1}, qInv: one()}
	if views, err := rsaFIPSSecretViews(reflect.ValueOf(good).Elem()); err != nil || len(views) != 10 {
		t.Fatalf("control failed: today's layout gives %d views, %v; want 10", len(views), err)
	}

	type grownKey struct {
		pub          struct{ N *nat } //nolint:unused // reflected shape only
		d            *nat
		p, q         *modulus
		dP, dQ       []byte
		qInv         *nat
		fipsApproved bool //nolint:unused // reflected shape only
		dCache       []byte
	}
	type grownModulus struct {
		nat   *nat
		odd   bool //nolint:unused // reflected shape only
		m0inv uint
		rr    *nat
		r3    *nat
	}
	type keyWithGrownModulus struct {
		pub          struct{ N *nat } //nolint:unused // reflected shape only
		d            *nat
		p, q         *grownModulus
		dP, dQ       []byte
		qInv         *nat
		fipsApproved bool //nolint:unused // reflected shape only
	}
	gmod := func() *grownModulus { return &grownModulus{nat: one(), rr: one(), r3: one(), m0inv: 1} }
	for name, c := range map[string]struct {
		key   any
		field string
	}{
		"key grew a field":     {&grownKey{d: one(), p: mod(), q: mod(), dP: []byte{1}, dQ: []byte{1}, qInv: one(), dCache: []byte{1}}, "dCache"},
		"modulus grew a field": {&keyWithGrownModulus{d: one(), p: gmod(), q: gmod(), dP: []byte{1}, dQ: []byte{1}, qInv: one()}, "r3"},
	} {
		views, err := rsaFIPSSecretViews(reflect.ValueOf(c.key).Elem())
		if err == nil {
			t.Errorf("%s: %d views returned; the field %q would be left unwiped", name, len(views), c.field)
			continue
		}
		if len(views) != 0 || !strings.Contains(err.Error(), c.field) || !strings.Contains(err.Error(), "NOT wiped") {
			t.Errorf("%s: want no views and a refusal naming %q: %d views, %v", name, c.field, len(views), err)
		}
	}
}

// TestResolveAESLayout_RefusesUnknownFields is the same rule for the bare
// Block the passphrase paths wipe.
func TestResolveAESLayout_RefusesUnknownFields(t *testing.T) {
	//lint:ignore U1000 only the reflected shapes matter
	type expanded struct {
		rounds   int        //nolint:unused // reflected shape only
		enc, dec [60]uint32 //nolint:unused // reflected shape only
	}
	type current struct{ expanded } //nolint:unused // reflected shape only
	if l := resolveAESLayout(reflect.TypeOf(&current{})); l.err != nil {
		t.Fatalf("control failed: today's layout does not resolve: %v", l.err)
	}
	//lint:ignore U1000 only the reflected shapes matter
	type grown struct {
		expanded
		storage [32]byte //nolint:unused // reflected shape only
	}
	l := resolveAESLayout(reflect.TypeOf(&grown{}))
	if l.err == nil || !strings.Contains(l.err.Error(), "storage") || !strings.Contains(l.err.Error(), "NOT wiped") {
		t.Fatalf("a Block that also stores the raw key resolved: %v", l.err)
	}
}

func TestUnaccountedField(t *testing.T) {
	type inner struct{ s, t int } //nolint:unused // reflected shape only
	type outer struct {
		d     int   //nolint:unused // reflected shape only
		inner       //nolint:unused // reflected shape only
		named inner //nolint:unused // reflected shape only
	}
	st := reflect.TypeOf(outer{})
	if got := unaccountedField(st, "d", "s", "t", "named"); got != "" {
		t.Errorf("every field named, got %q", got)
	}
	if got := unaccountedField(st, "d", "s", "named"); got != "t" {
		t.Errorf("a promoted field left out: got %q, want t", got)
	}
	if got := unaccountedField(st, "d", "s", "t"); got != "named" {
		t.Errorf("a named struct field is one field, not its contents: got %q, want named", got)
	}
}
