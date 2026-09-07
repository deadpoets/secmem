package secmemcrypto

import (
	"crypto/cipher"
	"fmt"
	"reflect"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/deadpoets/secmem"
)

// The AES key schedule is the one piece of an OpenSSH passphrase
// decryption that no caller-owned workspace can hold: crypto/aes expands
// the key into a heap object it allocates itself, and exposes nothing to
// clear it. Like the parsed ECDH scalar (rsa.go), the round keys are
// reachable only through the type's unexported fields, so they are wiped by
// reflection, pinned to the toolchain by a tripwire test, and the wipe fails
// loud rather than silently doing nothing when the layout it expects is not
// there. The reflection runs once per concrete Block type: the field
// offsets are cached, so the wipe itself allocates nothing (the proof in
// parse_proof_encrypted_test.go would flag it).

// aesRoundKeyFields names the two [60]uint32 arrays of the expanded key
// inside crypto/internal/fips140/aes.Block ("enc" and "dec" in go1.26's
// aes.go, promoted from the embedded blockExpanded). Each holds
// (rounds+1)×4 words of the schedule; the rest is zero.
//
// TestWipeAESBlock_Tripwire fails on any toolchain where the names or the
// shape stop resolving, so a crypto/aes refactor shows up as a red test run.
// A build where the concrete type is something else (BoringCrypto, s390x's
// unexpanded block) fails the same way at runtime, and the passphrase paths
// refuse to proceed rather than leave a key schedule on the heap.
var aesRoundKeyFields = [...]string{"enc", "dec"}

// aesLayout is the resolved position of each round-key array inside one
// concrete Block type, or the reason it could not be resolved.
type aesLayout struct {
	typ  reflect.Type
	off  [len(aesRoundKeyFields)]uintptr
	size [len(aesRoundKeyFields)]int
	err  error
}

// aesLayoutCache holds the layout of the last Block type seen; crypto/aes
// returns one type per process, so this is resolved once.
var aesLayoutCache atomic.Pointer[aesLayout]

func aesLayoutFor(b cipher.Block) *aesLayout {
	t := reflect.TypeOf(b)
	if l := aesLayoutCache.Load(); l != nil && l.typ == t {
		return l
	}
	l := &aesLayout{typ: t}
	for i, field := range aesRoundKeyFields {
		off, size, err := aesFieldLayout(t, field)
		if err != nil {
			l.err = err
			break
		}
		l.off[i], l.size[i] = off, size
	}
	aesLayoutCache.Store(l)
	return l
}

// aesFieldLayout resolves the named field of *t's struct, through any
// embedded structs, and returns its byte offset from the start of the
// struct and its size. It fails — never returns a position — when t is not
// a pointer to a struct, the field is missing, or it is not a non-empty
// array of uint32, the ways a stdlib refactor would break the lookup.
func aesFieldLayout(t reflect.Type, field string) (uintptr, int, error) {
	if t == nil || t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
		return 0, 0, fmt.Errorf("secmemcrypto: wipe aes block: %v is not a pointer to a struct on %s; the round keys were NOT wiped", t, runtime.Version())
	}
	st := t.Elem()
	sf, ok := st.FieldByName(field)
	if !ok {
		return 0, 0, fmt.Errorf("secmemcrypto: wipe aes block: %v has no field %q on %s; the round keys were NOT wiped", t, field, runtime.Version())
	}
	if sf.Type.Kind() != reflect.Array || sf.Type.Elem().Kind() != reflect.Uint32 || sf.Type.Len() == 0 {
		return 0, 0, fmt.Errorf("secmemcrypto: wipe aes block: %v.%s is %s on %s, want [N]uint32; the round keys were NOT wiped", t, field, sf.Type, runtime.Version())
	}
	// A promoted field's Offset is relative to the struct that declares it;
	// walk the index path for the offset from the outermost struct.
	var off uintptr
	cur := st
	for _, i := range sf.Index {
		f := cur.Field(i)
		off += f.Offset
		cur = f.Type
	}
	return off, int(sf.Type.Size()), nil
}

// aesRoundKeys returns a byte view of the named round-key array inside b,
// aliasing the Block's own storage (no copy). It resolves the layout afresh
// each call and is the tripwire test's independent path to the schedule;
// production goes through the cached layout in wipeAESBlock.
func aesRoundKeys(b cipher.Block, field string) ([]byte, error) {
	off, size, err := aesFieldLayout(reflect.TypeOf(b), field)
	if err != nil {
		return nil, err
	}
	//nolint:gosec // G103: audited — aliasing the Block's own round-key array at a resolved offset; no foreign memory is dereferenced.
	return unsafe.Slice((*byte)(unsafe.Add(reflect.ValueOf(b).UnsafePointer(), off)), size), nil
}

// wipeAESBlock zeroes both round-key schedules inside a crypto/aes Block.
// When they cannot be located it returns an error instead of silently doing
// nothing; every caller folds that into its own result, so no caller is
// told a decryption or encryption was cleaned up while the schedule is
// still live on the heap.
//
// A package var so a test can wrap it to prove the passphrase paths fire
// the wipe on the live Block; production always runs the value defined here.
var wipeAESBlock = func(b cipher.Block) error {
	if b == nil {
		return nil
	}
	l := aesLayoutFor(b)
	if l.err != nil {
		return l.err
	}
	base := reflect.ValueOf(b).UnsafePointer()
	for i := range aesRoundKeyFields {
		//nolint:gosec // G103: audited — the Block's own storage at the cached offset for its concrete type.
		secmem.SecureWipe(unsafe.Slice((*byte)(unsafe.Add(base, l.off[i])), l.size[i]))
	}
	runtime.KeepAlive(b)
	return nil
}
