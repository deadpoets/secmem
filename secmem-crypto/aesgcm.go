package secmemcrypto

// aesgcm.go lends out an AES-GCM AEAD built from a key in a SecureBuffer and
// wipes every copy of the key schedule before returning.
//
// The standard library gives an AEAD key nowhere to live but the heap:
// aes.NewCipher expands the key into a heap Block, and cipher.NewGCM copies
// that Block by value into its own heap object together with (on amd64 and
// arm64) a GHASH table derived from the key. Nothing exported clears either.
// A cipher.AEAD kept for the life of a connection keeps the key on the heap
// for that long; one built per call and dropped leaves both objects for the
// collector, which does not zero them on a legacy build. The residue test
// found the round keys after every call either way.

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/deadpoets/secmem"
)

// ErrAEADOutOfScope is the panic value of a Seal or Open on an AEAD handed
// to a [WithAESGCM] callback, called after the callback returned. By then
// the key schedule it used has been wiped; letting the call through would
// encrypt under an all-zero schedule and report success.
var ErrAEADOutOfScope = errors.New("secmemcrypto: AEAD used after its WithAESGCM callback returned; its key schedule has been wiped")

// WithAESGCM builds AES-GCM (a 12-byte nonce, a 16-byte tag — what
// cipher.NewGCM builds) from the AES key held in key (16, 24 or 32 bytes)
// and passes it to fn. When fn returns — or panics — every copy of the key
// schedule is wiped: both round-key arrays in the aes.Block, the copy of
// them inside the GCM object, and the GCM object's key-derived GHASH table
// where the platform has one. The whole call runs inside [secmem.ScrubErr].
//
// fn may use the AEAD any way cipher.AEAD allows, including with [SealFrom]
// and [OpenInto] to keep the plaintext in locked memory too. It must not
// keep it: the AEAD fn receives panics with [ErrAEADOutOfScope] if Seal or
// Open is called after fn has returned.
//
// Build the AEAD per use rather than keeping one for a session: that is what
// keeps the round keys off the heap between uses. It costs a key expansion
// and the wipe — sealing 1 KiB took about 2.4 µs this way against 0.2 µs on
// a kept AEAD and 0.6 µs built per call and dropped, on a Core Ultra 7 265KF
// (BenchmarkAESGCM); most of the difference is the cache-flushing wipe. The residue test finds
// neither the key, its schedule, nor the GHASH table outside locked memory
// after a call. While fn runs, the schedule is on the heap in the two objects
// this wipes; that is the operation, and no stdlib AES avoids it.
//
// The wipe reaches the objects through unexported fields, resolved by
// reflection and pinned to the toolchain by a tripwire test. If the layout
// is not the one expected, WithAESGCM returns an error before the key is
// expanded, so a toolchain change can never leave a schedule behind silently.
func WithAESGCM(key *secmem.SecureBuffer, fn func(aead cipher.AEAD) error) error {
	if key == nil {
		return errors.New("secmemcrypto: with aes-gcm: nil key buffer")
	}
	if fn == nil {
		return errors.New("secmemcrypto: with aes-gcm: nil callback")
	}
	switch key.Len() {
	case 16, 24, 32:
	default:
		return fmt.Errorf("secmemcrypto: with aes-gcm: key is %d bytes, want 16, 24 or 32", key.Len())
	}
	layout, err := aesGCMLayoutReady()
	if err != nil {
		return err
	}
	err = secmem.ScrubErr(func() error {
		return key.WithBytesErr(func(k []byte) (err error) {
			blk, err := aes.NewCipher(k) //nolint:secmem-lint // the heap schedule is this function's to wipe, and the deferred wipes below do
			if err != nil {
				return err
			}
			defer func() { err = errors.Join(err, wipeAESBlock(blk)) }()
			aead, err := cipher.NewGCM(blk)
			if err != nil {
				return err
			}
			defer func() { err = errors.Join(err, layout.wipe(aead)) }()
			if withAESGCMProbe != nil {
				withAESGCMProbe(blk, aead)
			}
			scoped := &scopedAEAD{aead: aead}
			defer scoped.done.Store(true)
			return fn(scoped)
		})
	})
	if err != nil {
		return fmt.Errorf("secmemcrypto: with aes-gcm: %w", err)
	}
	return nil
}

// withAESGCMProbe, nil in production, lets a test hold the Block and the
// GCM object WithAESGCM builds, to read them back after the wipe.
var withAESGCMProbe func(blk cipher.Block, aead cipher.AEAD)

// scopedAEAD refuses Seal and Open once its WithAESGCM callback has returned.
type scopedAEAD struct {
	aead cipher.AEAD
	done atomic.Bool
}

func (s *scopedAEAD) NonceSize() int { return s.aead.NonceSize() }
func (s *scopedAEAD) Overhead() int  { return s.aead.Overhead() }

func (s *scopedAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if s.done.Load() {
		panic(ErrAEADOutOfScope)
	}
	return s.aead.Seal(dst, nonce, plaintext, additionalData)
}

func (s *scopedAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if s.done.Load() {
		panic(ErrAEADOutOfScope)
	}
	return s.aead.Open(dst, nonce, ciphertext, additionalData)
}

// aesGCMRegion is one secret array inside the GCM object.
type aesGCMRegion struct {
	name string
	off  uintptr
	size int
}

// aesGCMLayout is where the secret arrays sit inside the concrete type
// cipher.NewGCM returns for an aes.Block on this toolchain.
type aesGCMLayout struct {
	typ     reflect.Type
	regions []aesGCMRegion
}

var aesGCMLayoutCache atomic.Pointer[aesGCMLayout]

// aesGCMLayoutReady resolves (once) and returns the GCM layout, together
// with the aes.Block layout wipeAESBlock needs, by building both from a
// throwaway all-zero key — which is not secret — so that a layout that
// cannot be wiped is reported before any real key is expanded.
func aesGCMLayoutReady() (*aesGCMLayout, error) {
	if l := aesGCMLayoutCache.Load(); l != nil {
		return l, nil
	}
	var zero [32]byte
	blk, err := aes.NewCipher(zero[:])
	if err != nil {
		return nil, err
	}
	if l := aesLayoutFor(blk); l.err != nil {
		return nil, l.err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	l, err := resolveAESGCMLayout(reflect.TypeOf(aead))
	if err != nil {
		return nil, err
	}
	aesGCMLayoutCache.Store(l)
	return l, nil
}

// resolveAESGCMLayout finds, inside *GCM, the round-key arrays of the
// embedded copy of the Block ("cipher", then "enc" and "dec") and, where
// present, the GHASH table ("productTable", a byte array). It fails — never
// returns a partial layout — when the type is not a pointer to a struct, a
// round-key array is missing or not [N]uint32, or productTable exists but is
// not a byte array.
func resolveAESGCMLayout(t reflect.Type) (*aesGCMLayout, error) {
	fail := func(format string, args ...any) (*aesGCMLayout, error) {
		return nil, fmt.Errorf("secmemcrypto: with aes-gcm: "+format+" on %s; refusing to expand a key whose schedule could not be wiped", append(args, runtime.Version())...)
	}
	if t == nil || t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
		return fail("cipher.NewGCM returned %v, not a pointer to a struct", t)
	}
	st := t.Elem()
	l := &aesGCMLayout{typ: t}
	cf, ok := st.FieldByName("cipher")
	if !ok || cf.Type.Kind() != reflect.Struct {
		return fail("%v has no embedded cipher block", t)
	}
	for _, name := range aesRoundKeyFields {
		sf, ok := cf.Type.FieldByName(name)
		if !ok || sf.Type.Kind() != reflect.Array || sf.Type.Elem().Kind() != reflect.Uint32 || sf.Type.Len() == 0 {
			return fail("%v.cipher.%s is missing or not [N]uint32", t, name)
		}
		l.regions = append(l.regions, aesGCMRegion{"cipher." + name, cf.Offset + promotedFieldOffset(cf.Type, sf), int(sf.Type.Size())})
	}
	if pf, ok := st.FieldByName("productTable"); ok {
		if pf.Type.Kind() != reflect.Array || pf.Type.Elem().Kind() != reflect.Uint8 {
			return fail("%v.productTable is %s, want a byte array", t, pf.Type)
		}
		l.regions = append(l.regions, aesGCMRegion{"productTable", promotedFieldOffset(st, pf), int(pf.Type.Size())})
	}
	return l, nil
}

// wipe zeroes every region of the layout inside aead, which must be of the
// layout's type.
func (l *aesGCMLayout) wipe(aead cipher.AEAD) error {
	if reflect.TypeOf(aead) != l.typ {
		return fmt.Errorf("secmemcrypto: with aes-gcm: AEAD is %T, layout resolved for %v; the key schedule was NOT wiped", aead, l.typ)
	}
	base := reflect.ValueOf(aead).UnsafePointer()
	for _, r := range l.regions {
		//nolint:gosec // G103: audited — the GCM object's own storage at an offset resolved for its concrete type.
		secmem.SecureWipe(unsafe.Slice((*byte)(unsafe.Add(base, r.off)), r.size))
	}
	runtime.KeepAlive(aead)
	return nil
}
