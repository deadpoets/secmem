package secmemcrypto

import (
	"crypto/rsa"
	"fmt"
	"reflect"
	"runtime"
	"unsafe"

	"github.com/deadpoets/secmem"
)

// crypto/rsa keeps a second, FIPS-form copy of every private key it
// operates on: PrecomputedValues.fips, a *crypto/internal/fips140/rsa.PrivateKey
// that x509's parsers populate through Precompute and that every Sign and
// Decrypt uses. In go1.26 it holds d and qInv as bigmod.Nat limb slices,
// p and q as bigmod.Modulus values (each the prime's limbs plus two
// Montgomery constants derived from it, R² mod p and -p⁻¹ mod 2⁶⁴), and dP
// and dQ as big-endian byte slices — every secret integer of the key, a
// second time, on the heap. Zeroing the exported big.Ints (wipeRSAPrivateKey
// in rsa.go) does not touch it. Like the AES round keys and the ML-KEM
// expansion, it is reachable only through unexported fields, so it is
// wiped by reflection, pinned to the toolchain by a tripwire test, and the
// wipe fails loud when the layout it expects is not there. It walks
// reflect.Values rather than caching offsets: an RSA operation allocates
// hundreds of times already, and the pointer graph (three levels of
// pointers to slices) would make a cached layout more code than the walk.

// rsaFIPSField is the unexported pointer inside rsa.PrecomputedValues.
const rsaFIPSField = "fips"

// rsaFIPSSecretFields are the secret fields of the FIPS-form key and the
// shape each must have, checked before anything is written.
var rsaFIPSSecretFields = [...]struct {
	name string
	kind rsaFIPSKind
}{
	{"d", rsaNat},
	{"p", rsaModulus},
	{"q", rsaModulus},
	{"dP", rsaBytes},
	{"dQ", rsaBytes},
	{"qInv", rsaNat},
}

// The fields of each struct on the way that hold nothing secret. Together
// with the secret ones they must be every field there is (see
// unaccountedField in mlkemwipe.go): a FIPS-form key, a Modulus or a Nat
// with a field in neither list is not a layout this wipe can vouch for.
var (
	rsaPrecomputedFields = [...]string{"Dp", "Dq", "Qinv", "CRTValues", rsaFIPSField} // the exported ones are wipeRSAPrivateKey's
	rsaFIPSPublicFields  = [...]string{"pub", "fipsApproved"}
	rsaModulusFields     = [...]string{"nat", "odd", "m0inv", "rr"} // odd is public; the rest are wiped
	rsaNatFields         = [...]string{"limbs"}
)

type rsaFIPSKind uint8

const (
	rsaNat     rsaFIPSKind = iota // *bigmod.Nat: struct{ limbs []uint }
	rsaModulus                    // *bigmod.Modulus: struct{ nat *Nat; odd bool; m0inv uint; rr *Nat }
	rsaBytes                      // []byte
)

func rsaWipeErr(format string, args ...any) error {
	return fmt.Errorf("secmemcrypto: wipe rsa fips key: "+format+" on %s; the FIPS-form key was NOT wiped", append(args, runtime.Version())...)
}

// rsaFIPSKey returns the FIPS-form key reachable from key (a struct Value,
// possibly the zero Value when the pointer is nil) or an error when the
// field is not where this toolchain is expected to keep it, or
// PrecomputedValues has a field this package has never seen — which is
// where a relocated FIPS key would be.
func rsaFIPSKey(key *rsa.PrivateKey) (reflect.Value, error) {
	pre := reflect.ValueOf(key).Elem().FieldByName("Precomputed")
	if name := unaccountedField(pre.Type(), rsaPrecomputedFields[:]...); name != "" {
		return reflect.Value{}, rsaWipeErr("rsa.PrecomputedValues has a field %q this package does not know", name)
	}
	f := pre.FieldByName(rsaFIPSField)
	if !f.IsValid() {
		return reflect.Value{}, rsaWipeErr("rsa.PrecomputedValues has no field %q", rsaFIPSField)
	}
	if f.Kind() != reflect.Pointer || f.Type().Elem().Kind() != reflect.Struct {
		return reflect.Value{}, rsaWipeErr("rsa.PrecomputedValues.%s is %s, want a pointer to a struct", rsaFIPSField, f.Type())
	}
	if f.IsNil() {
		return reflect.Value{}, nil
	}
	return f.Elem(), nil
}

// rsaFIPSSecretViews returns a byte view over every secret slice and word
// inside the FIPS-form key fips, aliasing its storage (no copy). It fails,
// returning no views, when any field is missing or of the wrong shape: a
// partial wipe would be reported as a failure anyway, so nothing is
// written before the whole layout has been checked. The tripwire test uses
// it as its independent path to the storage; production goes through it
// from wipeRSAFIPSKey.
func rsaFIPSSecretViews(fips reflect.Value) ([][]byte, error) {
	known := rsaFIPSPublicFields[:]
	for _, sf := range rsaFIPSSecretFields {
		known = append(known, sf.name)
	}
	if name := unaccountedField(fips.Type(), known...); name != "" {
		return nil, rsaWipeErr("%s has a field %q this package does not know to be public", fips.Type(), name)
	}
	var views [][]byte
	for _, sf := range rsaFIPSSecretFields {
		f := fips.FieldByName(sf.name)
		if !f.IsValid() {
			return nil, rsaWipeErr("%s has no field %q", fips.Type(), sf.name)
		}
		var err error
		switch sf.kind {
		case rsaNat:
			views, err = appendNatView(views, f, sf.name)
		case rsaModulus:
			views, err = appendModulusView(views, f, sf.name)
		case rsaBytes:
			if f.Kind() != reflect.Slice || f.Type().Elem().Kind() != reflect.Uint8 {
				return nil, rsaWipeErr("%s.%s is %s, want []byte", fips.Type(), sf.name, f.Type())
			}
			if b := sliceBytes(f); b != nil {
				views = append(views, b)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return views, nil
}

// appendNatView appends the limb slice of a *bigmod.Nat field. A nil
// pointer (a multi-prime key built without CRT values has none) is legal
// and contributes nothing.
func appendNatView(views [][]byte, f reflect.Value, name string) ([][]byte, error) {
	if f.Kind() != reflect.Pointer || f.Type().Elem().Kind() != reflect.Struct {
		return nil, rsaWipeErr("%s is %s, want *bigmod.Nat", name, f.Type())
	}
	if field := unaccountedField(f.Type().Elem(), rsaNatFields[:]...); field != "" {
		return nil, rsaWipeErr("%s points to %s, which has a field %q this package does not know", name, f.Type().Elem(), field)
	}
	if f.IsNil() {
		return views, nil
	}
	limbs := f.Elem().FieldByName("limbs")
	if !limbs.IsValid() || limbs.Kind() != reflect.Slice || limbs.Type().Elem().Kind() != reflect.Uint {
		return nil, rsaWipeErr("%s points to %s, want a struct with limbs []uint", name, f.Type().Elem())
	}
	return append(views, sliceBytes(limbs)), nil
}

// appendModulusView appends the prime's own limbs and the two Montgomery
// constants derived from it inside a *bigmod.Modulus field.
func appendModulusView(views [][]byte, f reflect.Value, name string) ([][]byte, error) {
	if f.Kind() != reflect.Pointer || f.Type().Elem().Kind() != reflect.Struct {
		return nil, rsaWipeErr("%s is %s, want *bigmod.Modulus", name, f.Type())
	}
	if field := unaccountedField(f.Type().Elem(), rsaModulusFields[:]...); field != "" {
		return nil, rsaWipeErr("%s points to %s, which has a field %q this package does not know", name, f.Type().Elem(), field)
	}
	if f.IsNil() {
		return views, nil
	}
	m := f.Elem()
	var err error
	for _, natField := range [...]string{"nat", "rr"} {
		if views, err = appendNatView(views, m.FieldByName(natField), name+"."+natField); err != nil {
			return nil, err
		}
	}
	m0inv := m.FieldByName("m0inv")
	if !m0inv.IsValid() || m0inv.Kind() != reflect.Uint {
		return nil, rsaWipeErr("%s has no m0inv uint", f.Type().Elem())
	}
	//nolint:gosec // G103: audited — the field's own word, addressable inside the key.
	views = append(views, unsafe.Slice((*byte)(unsafe.Pointer(m0inv.UnsafeAddr())), int(m0inv.Type().Size())))
	return views, nil
}

// sliceBytes views the backing array of a slice Value as bytes.
func sliceBytes(v reflect.Value) []byte {
	if v.Len() == 0 {
		return nil
	}
	//nolint:gosec // G103: audited — the slice's own backing array, no foreign memory.
	return unsafe.Slice((*byte)(v.UnsafePointer()), v.Len()*int(v.Type().Elem().Size()))
}

// wipeRSAFIPSKey zeroes every secret field of the FIPS-form key inside a
// *rsa.PrivateKey — d, p, q (with their Montgomery constants), dP, dQ and
// qInv — leaving the public modulus intact. A key with a private exponent
// and no FIPS form is an error, not "nothing to wipe": every key this
// package wipes was precomputed by the standard library, which is what
// builds that form, so its absence means the form is kept somewhere this
// function does not look. (A key with no private exponent has no secret in
// either form.) When the layout cannot be resolved it returns an error
// instead of silently doing nothing;
// wipeRSAPrivateKey folds that into its result and every caller into its
// own, so no caller is told an operation was cleaned up while the key is
// still live on the heap.
func wipeRSAFIPSKey(key *rsa.PrivateKey) error {
	if key == nil {
		return nil
	}
	fips, err := rsaFIPSKey(key)
	if err != nil {
		return err
	}
	if !fips.IsValid() {
		if key.D == nil {
			return nil
		}
		return rsaWipeErr("the key has a private exponent but no rsa.PrecomputedValues.%s", rsaFIPSField)
	}
	views, err := rsaFIPSSecretViews(fips)
	if err != nil {
		return err
	}
	for _, v := range views {
		secmem.SecureWipe(v)
	}
	runtime.KeepAlive(key)
	return nil
}
