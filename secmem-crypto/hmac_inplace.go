package secmemcrypto

// hmac_inplace.go runs HMAC (RFC 2104) and HKDF (RFC 5869) without a heap
// object anywhere near the key. crypto/hmac keeps the key XORed into its
// pads and the inner and outer digest states — each key-equivalent — in heap
// allocations nothing outside the package can reach, and x/crypto/hkdf adds
// the pseudorandom key. The out-of-process residue test found all of them
// after every call.
//
// The standard library's one-shot hash functions (sha256.Sum256 and the
// rest) keep their digest state in a stack local, so HMAC is computed here as
// two one-shots over a scratch region holding pad || message: on the stack
// inside the caller's Scrub window when it is small, in a locked buffer when
// it is not. That works for exactly the hashes that have one-shots; any other
// hash constructor takes the heap path and its gate (see HMACInto).

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"errors"
	"hash"
	"reflect"
	"sync/atomic"

	"github.com/deadpoets/secmem"
)

// inPlaceHash names a hash this file can compute as a one-shot. The zero
// value is "not supported".
type inPlaceHash uint8

const (
	hashNone inPlaceHash = iota
	hashSHA224
	hashSHA256
	hashSHA384
	hashSHA512
	hashSHA512_224
	hashSHA512_256
	hashSHA3_224
	hashSHA3_256
	hashSHA3_384
	hashSHA3_512
)

// maxHashSize bounds every supported hash's output: SHA-512's.
const maxHashSize = 64

// hmacStackRegion is the largest working region kept on the stack; a larger
// one is a locked buffer. The frame is inside the caller's Scrub band (32 KiB
// on a legacy build), which this stays far under.
const hmacStackRegion = 1536

func (h inPlaceHash) size() int {
	switch h {
	case hashSHA224, hashSHA512_224, hashSHA3_224:
		return 28
	case hashSHA256, hashSHA512_256, hashSHA3_256:
		return 32
	case hashSHA384, hashSHA3_384:
		return 48
	case hashSHA512, hashSHA3_512:
		return 64
	}
	return 0
}

// block is the HMAC block size, which is what crypto/hmac uses:
// hash.Hash.BlockSize, the rate for SHA-3.
func (h inPlaceHash) block() int {
	switch h {
	case hashSHA224, hashSHA256:
		return 64
	case hashSHA384, hashSHA512, hashSHA512_224, hashSHA512_256:
		return 128
	case hashSHA3_224:
		return 144
	case hashSHA3_256:
		return 136
	case hashSHA3_384:
		return 104
	case hashSHA3_512:
		return 72
	}
	return 0
}

// sum writes H(data) into dst[:h.size()]. Every case is a direct call to a
// one-shot whose digest state is a stack local; the result array is a local
// too, and is wiped here. A switch, not a table of funcs: an indirect call
// would make data escape.
func (h inPlaceHash) sum(dst, data []byte) {
	switch h {
	case hashSHA224:
		s := sha256.Sum224(data)
		copy(dst, s[:])
		secmem.SecureWipe(s[:])
	case hashSHA256:
		s := sha256.Sum256(data)
		copy(dst, s[:])
		secmem.SecureWipe(s[:])
	case hashSHA384:
		s := sha512.Sum384(data)
		copy(dst, s[:])
		secmem.SecureWipe(s[:])
	case hashSHA512:
		s := sha512.Sum512(data)
		copy(dst, s[:])
		secmem.SecureWipe(s[:])
	case hashSHA512_224:
		s := sha512.Sum512_224(data)
		copy(dst, s[:])
		secmem.SecureWipe(s[:])
	case hashSHA512_256:
		s := sha512.Sum512_256(data)
		copy(dst, s[:])
		secmem.SecureWipe(s[:])
	case hashSHA3_224:
		s := sha3.Sum224(data)
		copy(dst, s[:])
		secmem.SecureWipe(s[:])
	case hashSHA3_256:
		s := sha3.Sum256(data)
		copy(dst, s[:])
		secmem.SecureWipe(s[:])
	case hashSHA3_384:
		s := sha3.Sum384(data)
		copy(dst, s[:])
		secmem.SecureWipe(s[:])
	case hashSHA3_512:
		s := sha3.Sum512(data)
		copy(dst, s[:])
		secmem.SecureWipe(s[:])
	default:
		panic("secmemcrypto: sum on an unsupported hash")
	}
}

// Reference dynamic types of the standard library's hash constructors.
var (
	sha256Type = reflect.TypeOf(sha256.New())
	sha512Type = reflect.TypeOf(sha512.New())
	sha3Type   = reflect.TypeOf(sha3.New256())
)

type inPlaceHashEntry struct {
	typ  reflect.Type
	size int
	id   inPlaceHash
}

// inPlaceHashSeen caches the verdict per dynamic type and size, so the
// verification below runs once per hash, not once per call. Copy-on-write.
var inPlaceHashSeen atomic.Pointer[[]inPlaceHashEntry]

// inPlaceHashProbe is the fixed, public input a candidate is checked on.
var inPlaceHashProbe = []byte("secmem-crypto: is this constructor the one-shot it looks like?")

// inPlaceHashOf reports which one-shot computes the same function as probe,
// a fresh instance from the caller's constructor, or hashNone. The dynamic
// type and output size pick a candidate — within each standard-library
// digest type the size identifies the variant — and the candidate is only
// accepted if the constructor's own output, block size and size agree with
// it on a fixed input, so a look-alike can never be computed as something it
// is not.
func inPlaceHashOf(probe hash.Hash) inPlaceHash {
	if probe == nil {
		return hashNone
	}
	typ, size := reflect.TypeOf(probe), probe.Size()
	if seen := inPlaceHashSeen.Load(); seen != nil {
		for _, e := range *seen {
			if e.typ == typ && e.size == size {
				return e.id
			}
		}
	}
	id := hashNone
	switch {
	case typ == sha256Type && size == 28:
		id = hashSHA224
	case typ == sha256Type && size == 32:
		id = hashSHA256
	case typ == sha512Type && size == 48:
		id = hashSHA384
	case typ == sha512Type && size == 64:
		id = hashSHA512
	case typ == sha512Type && size == 28:
		id = hashSHA512_224
	case typ == sha512Type && size == 32:
		id = hashSHA512_256
	case typ == sha3Type && size == 28:
		id = hashSHA3_224
	case typ == sha3Type && size == 32:
		id = hashSHA3_256
	case typ == sha3Type && size == 48:
		id = hashSHA3_384
	case typ == sha3Type && size == 64:
		id = hashSHA3_512
	}
	if id != hashNone {
		probe.Reset()
		probe.Write(inPlaceHashProbe)
		var want [maxHashSize]byte
		id.sum(want[:], inPlaceHashProbe)
		if probe.BlockSize() != id.block() || !bytes.Equal(probe.Sum(nil), want[:size]) {
			id = hashNone
		}
		probe.Reset()
	}
	for {
		old := inPlaceHashSeen.Load()
		var next []inPlaceHashEntry
		if old != nil {
			next = append(next, *old...)
		}
		next = append(next, inPlaceHashEntry{typ, size, id})
		if inPlaceHashSeen.CompareAndSwap(old, &next) {
			return id
		}
	}
}

// hmacInPlace computes HMAC-h(key, parts...) into dst[:h.size()], using
// scratch for pad || message. scratch must hold h.block() plus the larger of
// the message's length and h.size(). A key longer than the block is hashed
// first, as RFC 2104 requires. dst may alias a part: every part is copied
// into scratch before dst is written. Everything secret this writes — the
// padded key, the message copy, the inner digest — is in scratch or a local,
// and is wiped before return.
func hmacInPlace(h inPlaceHash, dst, scratch, key []byte, parts ...[]byte) {
	size, block := h.size(), h.block()
	var hashedKey [maxHashSize]byte
	if len(key) > block {
		h.sum(hashedKey[:], key)
		key = hashedKey[:size]
	}
	pad := scratch[:block]
	n := block
	for _, p := range parts {
		n += copy(scratch[n:], p)
	}
	clear(pad)
	copy(pad, key)
	for i := range pad {
		pad[i] ^= 0x36
	}
	var inner [maxHashSize]byte
	h.sum(inner[:], scratch[:n])

	clear(pad)
	copy(pad, key)
	for i := range pad {
		pad[i] ^= 0x5c
	}
	copy(scratch[block:], inner[:size])
	h.sum(dst[:size], scratch[:block+size])

	secmem.SecureWipe(inner[:])
	secmem.SecureWipe(hashedKey[:])
	secmem.SecureWipe(scratch[:max(n, block+size)])
}

// hmacIntoInPlace computes HMAC-h(key=secret, message=info) into dst. The
// working region — pad || message and nothing else — is a stack array when it
// fits, a locked buffer otherwise. Callers run it inside a Scrub window.
//
// Nothing secret is ever captured by a closure: a captured array would be
// moved to the heap, which is the whole thing this file exists to avoid. The
// locked path's closure holds only slice headers.
func hmacIntoInPlace(h inPlaceHash, dst, secret, info []byte) error {
	n := h.block() + max(len(info), h.size())
	if n <= hmacStackRegion {
		var region [hmacStackRegion]byte
		hmacInPlace(h, dst, region[:n], secret, info)
		return nil
	}
	buf, err := secmem.NewEmptyBuffer(n)
	if err != nil {
		return err
	}
	err = buf.WithBytesErr(func(region []byte) error {
		hmacInPlace(h, dst, region, secret, info)
		return nil
	})
	return errors.Join(err, buf.Destroy())
}

// hkdfInPlace is RFC 5869 over h, writing len(dst) bytes of output into dst.
// Its working region holds the pseudorandom key, the running T block and the
// HMAC scratch, and is a stack array when it fits, a locked buffer otherwise;
// callers run it inside a Scrub window. As in hmacIntoInPlace, no closure
// captures anything but slice headers.
func hkdfInPlace(h inPlaceHash, dst, secret, salt, info []byte) error {
	n := 2*maxHashSize + h.block() + max(len(secret), h.size()+len(info)+1)
	if n <= hmacStackRegion {
		var region [hmacStackRegion]byte
		hkdfCompute(h, dst, region[:n], secret, salt, info)
		return nil
	}
	buf, err := secmem.NewEmptyBuffer(n)
	if err != nil {
		return err
	}
	err = buf.WithBytesErr(func(region []byte) error {
		hkdfCompute(h, dst, region, secret, salt, info)
		return nil
	})
	return errors.Join(err, buf.Destroy())
}

// hkdfCompute runs HKDF in region: PRK = HMAC(salt, secret) in region[0:],
// then T(i) = HMAC(PRK, T(i-1) || info || i) in region[maxHashSize:], with
// the HMAC scratch after both. region is wiped before return.
func hkdfCompute(h inPlaceHash, dst, region, secret, salt, info []byte) {
	size := h.size()
	prk := region[:size]
	t := region[maxHashSize : maxHashSize+size]
	scratch := region[2*maxHashSize:]

	// RFC 5869 §2.2: an absent salt is HashLen zeros. As an HMAC key that is
	// the same as an empty key — both pad to a zero block — so it needs no
	// special case.
	hmacInPlace(h, prk, scratch, salt, secret)

	var ctr [1]byte
	prev := t[:0]
	for off := 0; off < len(dst); off += size {
		ctr[0]++
		hmacInPlace(h, t, scratch, prk, prev, info, ctr[:])
		copy(dst[off:], t)
		prev = t
	}
	secmem.SecureWipe(region)
}
