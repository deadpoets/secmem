package secmemcrypto

import (
	"crypto/mlkem"
	"fmt"
	"reflect"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/deadpoets/secmem"
)

// crypto/mlkem expands the 64-byte seed into a heap DecapsulationKey768 on
// every NewDecapsulationKey768 and exposes nothing to clear it. In go1.26
// the FIPS-form key (crypto/internal/fips140/mlkem.DecapsulationKey768)
// holds the seed halves verbatim — d and z, [32]byte each — and the secret
// polynomial vector s ([3][256]uint16, the decryption key), alongside the
// public ρ, H(ek), t and A. As with the AES round keys (aeswipe.go), those
// three are reachable only through unexported fields, so they are wiped by
// reflection at a cached offset, pinned to the toolchain by a tripwire
// test, and the wipe fails loud rather than silently doing nothing when the
// layout it expects is not there.

// mlkemKeyField is the one field of crypto/mlkem.DecapsulationKey768: the
// pointer to the FIPS-form key.
const mlkemKeyField = "key"

// mlkemSecretFields names the secret arrays inside the FIPS-form key: the
// two seed halves and the decryption key s (promoted from the embedded
// decryptionKey). Everything else in the struct is the encapsulation key.
var mlkemSecretFields = [...]string{"d", "z", "s"}

// mlkemLayout is the resolved position of the FIPS key pointer inside the
// outer type and of each secret array inside the inner one, or the reason
// they could not be resolved.
type mlkemLayout struct {
	typ    reflect.Type
	keyOff uintptr
	off    [len(mlkemSecretFields)]uintptr
	size   [len(mlkemSecretFields)]int
	err    error
}

var mlkemLayoutCache atomic.Pointer[mlkemLayout]

func mlkemLayoutFor(dk *mlkem.DecapsulationKey768) *mlkemLayout {
	t := reflect.TypeOf(dk)
	if l := mlkemLayoutCache.Load(); l != nil && l.typ == t {
		return l
	}
	l := &mlkemLayout{typ: t}
	keyOff, inner, err := mlkemInnerType(t)
	if err != nil {
		l.err = err
	} else {
		l.keyOff = keyOff
		for i, field := range mlkemSecretFields {
			off, size, err := mlkemArrayField(inner, field)
			if err != nil {
				l.err = err
				break
			}
			l.off[i], l.size[i] = off, size
		}
	}
	mlkemLayoutCache.Store(l)
	return l
}

// mlkemInnerType resolves the "key" pointer field of the outer type and
// returns its offset and the struct type it points to.
func mlkemInnerType(t reflect.Type) (uintptr, reflect.Type, error) {
	if t == nil || t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
		return 0, nil, fmt.Errorf("secmemcrypto: wipe mlkem key: %v is not a pointer to a struct on %s; the expanded key was NOT wiped", t, runtime.Version())
	}
	sf, ok := t.Elem().FieldByName(mlkemKeyField)
	if !ok {
		return 0, nil, fmt.Errorf("secmemcrypto: wipe mlkem key: %v has no field %q on %s; the expanded key was NOT wiped", t, mlkemKeyField, runtime.Version())
	}
	if sf.Type.Kind() != reflect.Pointer || sf.Type.Elem().Kind() != reflect.Struct {
		return 0, nil, fmt.Errorf("secmemcrypto: wipe mlkem key: %v.%s is %s on %s, want a pointer to a struct; the expanded key was NOT wiped", t, mlkemKeyField, sf.Type, runtime.Version())
	}
	return promotedFieldOffset(t.Elem(), sf), sf.Type.Elem(), nil
}

// mlkemArrayField resolves a named array field of the inner struct, through
// any embedded structs, and returns its byte offset and size. The field must
// be a fixed array whose innermost element is an unsigned integer ([32]byte
// for d and z, [k][n]uint16 for s); anything else is the shape a stdlib
// refactor would leave behind, and is refused.
func mlkemArrayField(st reflect.Type, field string) (uintptr, int, error) {
	sf, ok := st.FieldByName(field)
	if !ok {
		return 0, 0, fmt.Errorf("secmemcrypto: wipe mlkem key: %v has no field %q on %s; the expanded key was NOT wiped", st, field, runtime.Version())
	}
	elem := sf.Type
	for elem.Kind() == reflect.Array {
		elem = elem.Elem()
	}
	if sf.Type.Kind() == reflect.Array && sf.Type.Size() > 0 {
		switch elem.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
			return promotedFieldOffset(st, sf), int(sf.Type.Size()), nil
		}
	}
	return 0, 0, fmt.Errorf("secmemcrypto: wipe mlkem key: %v.%s is %s on %s, want a non-empty array of unsigned integers; the expanded key was NOT wiped", st, field, sf.Type, runtime.Version())
}

// promotedFieldOffset returns sf's byte offset from the start of st. A
// promoted field's Offset is relative to the struct that declares it, so
// the index path is walked from the outermost struct.
func promotedFieldOffset(st reflect.Type, sf reflect.StructField) uintptr {
	var off uintptr
	cur := st
	for _, i := range sf.Index {
		f := cur.Field(i)
		off += f.Offset
		cur = f.Type
	}
	return off
}

// mlkemInnerKey follows the outer key's pointer field to the FIPS-form key.
func mlkemInnerKey(dk *mlkem.DecapsulationKey768, keyOff uintptr) (unsafe.Pointer, error) {
	//nolint:gosec // G103: audited — reading the outer key's own pointer field at a resolved offset.
	p := *(*unsafe.Pointer)(unsafe.Add(unsafe.Pointer(dk), keyOff))
	if p == nil {
		return nil, fmt.Errorf("secmemcrypto: wipe mlkem key: nil FIPS-form key on %s; the expanded key was NOT wiped", runtime.Version())
	}
	return p, nil
}

// mlkemSecretBytes returns a byte view of the named secret array inside
// dk's FIPS-form key, aliasing its storage (no copy). It resolves the layout
// afresh each call and is the tripwire test's independent path to the
// fields; production goes through the cached layout in
// wipeMLKEMDecapsulationKey.
func mlkemSecretBytes(dk *mlkem.DecapsulationKey768, field string) ([]byte, error) {
	keyOff, inner, err := mlkemInnerType(reflect.TypeOf(dk))
	if err != nil {
		return nil, err
	}
	off, size, err := mlkemArrayField(inner, field)
	if err != nil {
		return nil, err
	}
	p, err := mlkemInnerKey(dk, keyOff)
	if err != nil {
		return nil, err
	}
	//nolint:gosec // G103: audited — aliasing the inner key's own array at a resolved offset.
	return unsafe.Slice((*byte)(unsafe.Add(p, off)), size), nil
}

// wipeMLKEMDecapsulationKey zeroes the seed halves and the decryption key
// inside a crypto/mlkem DecapsulationKey768, leaving the public parts. When
// they cannot be located it returns an error instead of silently doing
// nothing; every caller folds that into its own result, so no caller is
// told an operation was cleaned up while the seed is still live on the
// heap. The reflection runs once per process (the offsets are cached), so
// the wipe itself allocates nothing.
//
// A package var so a test can wrap it to prove the ML-KEM paths fire the
// wipe on the live key; production always runs the value defined here.
var wipeMLKEMDecapsulationKey = func(dk *mlkem.DecapsulationKey768) error {
	if dk == nil {
		return nil
	}
	l := mlkemLayoutFor(dk)
	if l.err != nil {
		return l.err
	}
	p, err := mlkemInnerKey(dk, l.keyOff)
	if err != nil {
		return err
	}
	for i := range mlkemSecretFields {
		//nolint:gosec // G103: audited — the inner key's own array at the cached offset for its concrete type.
		secmem.SecureWipe(unsafe.Slice((*byte)(unsafe.Add(p, l.off[i])), l.size[i]))
	}
	runtime.KeepAlive(dk)
	return nil
}
