package secmemcrypto

import (
	"encoding/base64"
	"encoding/binary"

	"github.com/deadpoets/secmem"
)

// The writing half of the OpenSSH container (parse_openssh.go has the
// reader): an SSH wire-format writer into a fixed slice, and a PEM encoder
// into a fixed slice. Neither allocates, so a private-key file can be
// assembled entirely inside SecureBuffers. encoding/pem is not used on
// purpose: pem.Encode runs the body through a base64.NewEncoder whose 1 KiB
// output buffer is a heap object holding a base64 window of the key that
// nothing can wipe.

// Names in the container.
const (
	opensshPEMType     = "OPENSSH PRIVATE KEY"
	opensshCipherNone  = "none"
	opensshCipherCTR   = "aes256-ctr"
	opensshCipherCBC   = "aes256-cbc"
	opensshKDFNone     = "none"
	opensshKDFBcrypt   = "bcrypt"
	opensshSaltLen     = 16   // what ssh-keygen writes
	opensshRounds      = 16   // ssh-keygen's default (-a)
	opensshMaxRounds   = 2048 // x/crypto/ssh's cap on files it will open; see parse_encrypted.go
	opensshAESBlock    = 16
	opensshNoneBlock   = 8
	opensshKeyEd25519  = "ssh-ed25519"
	opensshKeyIVLen    = 32 + 16 // AES-256 key || CTR/CBC IV
	opensshKDFOptsSize = 4 + opensshSaltLen + 4
)

// opensshCipher is a supported private-block cipher, resolved from its name
// by the caller so the crypt routine formats no name into an error (a
// []byte handed to fmt escapes to the heap; the allocation proof flags it).
type opensshCipher uint8

const (
	cipherUnsupported opensshCipher = iota
	cipherAES256CTR
	cipherAES256CBC
)

// opensshCipherByName maps a container's cipher name to the enum;
// cipherUnsupported for anything this package does not run.
func opensshCipherByName(name []byte) opensshCipher {
	switch string(name) { // comparison only: no string is allocated
	case opensshCipherCTR:
		return cipherAES256CTR
	case opensshCipherCBC:
		return cipherAES256CBC
	}
	return cipherUnsupported
}

// sshWriter appends SSH wire encoding (RFC 4251 §5) into a fixed slice; the
// caller sizes the slice exactly and checks n afterwards.
type sshWriter struct {
	b []byte
	n int
}

func (w *sshWriter) uint32(v uint32) {
	binary.BigEndian.PutUint32(w.b[w.n:], v)
	w.n += 4
}

func (w *sshWriter) bytes(p []byte) { w.n += copy(w.b[w.n:], p) }

func (w *sshWriter) string(s string) { w.n += copy(w.b[w.n:], s) }

// str writes a length-prefixed byte string.
func (w *sshWriter) str(p []byte) {
	w.uint32(uint32(len(p))) //nolint:gosec // G115: lengths here are bounded by the file layout, far below 2^32.
	w.bytes(p)
}

// strs writes a length-prefixed string without converting it to []byte.
func (w *sshWriter) strs(s string) {
	w.uint32(uint32(len(s))) //nolint:gosec // G115: as above.
	w.string(s)
}

// length writes an int as a uint32 length field.
func (w *sshWriter) length(n int) {
	w.uint32(uint32(n)) //nolint:gosec // G115: as above.
}

// sshStrLen is the encoded size of a string of n bytes.
func sshStrLen(n int) int { return 4 + n }

// pemLen is the size of the PEM armour for n raw bytes with the given type
// label: header, base64 in 64-character lines each ending in '\n', footer.
func pemLen(typ string, n int) int {
	enc := base64.StdEncoding.EncodedLen(n)
	lines := (enc + 63) / 64
	return len(pemBegin) + len(typ) + len(pemDashes) + 1 + enc + lines + len(pemEnd) + len(typ) + len(pemDashes) + 1
}

// pemEncode writes the PEM armour for src into dst, which must be at least
// pemLen(typ, len(src)) bytes, and returns the bytes written. Every 48 raw
// bytes make one 64-character line, exactly as encoding/pem lays it out.
func pemEncode(dst []byte, typ string, src []byte) int {
	n := copy(dst, pemBegin)
	n += copy(dst[n:], typ)
	n += copy(dst[n:], pemDashes)
	dst[n] = '\n'
	n++
	for len(src) > 0 {
		k := min(48, len(src))
		base64.StdEncoding.Encode(dst[n:], src[:k])
		n += base64.StdEncoding.EncodedLen(k)
		dst[n] = '\n'
		n++
		src = src[k:]
	}
	n += copy(dst[n:], pemEnd)
	n += copy(dst[n:], typ)
	n += copy(dst[n:], pemDashes)
	dst[n] = '\n'
	return n + 1
}

// borrowOrdered borrows two SecureBuffers in ascending LockOrder — the
// module's rule for every two-buffer operation — and calls fn with their
// contents in the order the buffers were passed.
func borrowOrdered(a, b *secmem.SecureBuffer, fn func(a, b []byte) error) error {
	first, second := a, b
	if first.LockOrder() > second.LockOrder() {
		first, second = second, first
	}
	return first.WithBytesErr(func(x []byte) error {
		return second.WithBytesErr(func(y []byte) error {
			if first == a {
				return fn(x, y)
			}
			return fn(y, x)
		})
	})
}
