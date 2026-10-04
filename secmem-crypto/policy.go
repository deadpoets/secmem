package secmemcrypto

import (
	"errors"
	"fmt"

	"github.com/deadpoets/secmem"
)

// ErrHeapTransients is returned, wrapped, when a constructor refuses to build
// a key type whose every operation copies secret material through the Go
// heap on a build where nothing erases those copies: [RSASigner] and
// [ECDSASigner], which copy the private key, and [MLKEM768Key], whose every
// decapsulation leaves the message that gives that ciphertext's shared key.
//
// That is every build except linux/amd64 and linux/arm64 compiled with
// GOEXPERIMENT=runtimesecret: Windows, macOS, and Linux without the
// experiment. There the standard library's per-operation copies of the
// scalar or the key (listed in each type's doc and in the README under
// "What each signer actually buys you") are reclaimed by the collector but
// never zeroed, so a heap dump of a process that signs or agrees keys
// contains the key whether or not the durable copy lives in a SecureBuffer.
//
// Returned by [NewRSASigner], [GenerateRSASigner], [NewECDSASigner],
// [GenerateECDSASigner], [NewMLKEM768Key] and [GenerateMLKEM768Key], by
// [ParsePrivateKey] and
// [ParsePrivateKeyWithPassphrase] for an RSA or EC key file, and by
// [HKDFInto] and [HMACInto] given a hash other than SHA-2 or SHA-3, which
// have no in-place implementation. The refusal
// happens before the key is handed to the standard library, so a refused
// call makes none of the heap copies it exists to prevent. A caller who
// accepts that residual passes [AllowHeapTransients]; a caller who does not
// should build with the experiment or keep the key in an HSM or KMS.
// Ed25519 and X25519 keys, which this module operates on in place, and
// [Encapsulate], which leaves nothing behind, are never refused.
var ErrHeapTransients = errors.New("secmemcrypto: operation would leave key material on the unprotected heap on this build")

// Option configures a constructor, parser or derivation in this package.
// Every exported function that allocates a [secmem.SecureBuffer] takes them,
// and every key type remembers the ones it was built with, for the buffers
// its methods allocate later.
type Option func(*options)

type options struct {
	allowHeapTransients bool
	buf                 bufferOptions
}

// bufferOptions is the core options a call was given through
// [BufferOptions], and the only way this package allocates: every
// SecureBuffer it creates — a key, an output, a scratch workspace — comes
// from one of the two methods below, so an option given at the call site
// reaches all of them. A key type keeps the value it was constructed with.
// bufferoptions_test.go fails if anything else in the package calls a core
// constructor.
type bufferOptions []secmem.Option

func (b bufferOptions) newEmptyBuffer(size int) (*secmem.SecureBuffer, error) {
	return secmem.NewEmptyBuffer(size, b...)
}

// newBuffer is secmem.NewBuffer: raw is wiped whether or not it succeeds.
func (b bufferOptions) newBuffer(raw []byte) (*secmem.SecureBuffer, error) {
	return secmem.NewBuffer(raw, b...)
}

// BufferOptions passes core options to every [secmem.SecureBuffer] the call
// allocates: the buffer a constructor or generator returns inside its key,
// the outputs a key's methods return later ([X25519Key.SharedSecret],
// [MLKEM768Key.Decapsulate], the Ed25519 Marshal forms — a key keeps the
// options it was built with), and the locked scratch a derivation or a
// parser uses and frees within the call.
//
// The core option that exists today is [secmem.WithInsecureFallback]. Without
// it this package is secure-memory-only: on a platform with no lockable
// off-heap memory every allocating call fails with an error wrapping
// [secmem.ErrNoSecureMemory]. With it, there, the same calls succeed on
// plain heap memory with none of the protections this module's documentation
// describes — the buffers report Capabilities().Insecure — which is the
// core's trade, made visible at the call site in the core's own words:
//
//	secmemcrypto.GenerateEd25519Signer(
//		secmemcrypto.BufferOptions(secmem.WithInsecureFallback()))
//
// On Linux, macOS and Windows it changes nothing. A buffer the caller
// allocates and hands in (a seed, an out) is the caller's, and is governed
// by the options the caller gave the core for it, not by this one.
//
// The name follows [AllowHeapTransients] rather than the core's With form:
// in this package With… names the scoped borrows ([WithAESGCM],
// [Ed25519Signer.WithSeed]).
func BufferOptions(opts ...secmem.Option) Option {
	return func(o *options) {
		// A fresh backing array each time: options values are copied, and
		// an append into shared spare capacity would let one call's options
		// overwrite another's.
		o.buf = append(o.buf[:len(o.buf):len(o.buf)], opts...)
	}
}

// AllowHeapTransients lets [RSASigner], [ECDSASigner] and [MLKEM768Key] be
// built, and [HKDFInto] and [HMACInto] run over a hash other than SHA-2 or
// SHA-3, on a build where their per-operation heap copies are never erased.
// Without it, the constructors and the parsers refuse such keys there with
// [ErrHeapTransients].
//
// Pass it when the durable key in locked memory is what you want and the
// transients are an accepted residual: a process that loads a key and uses
// it rarely spends most of its life with the key only in the buffer. Do not
// pass it to make an error go away on a service that signs or agrees keys
// continuously — that process has an unwiped copy of the key on the heap at
// almost every moment, and the buffer does not change that. For
// [MLKEM768Key] the copy is not the decapsulation key but each
// decapsulation's shared key, so the question is whether those session keys
// may sit in unwiped heap memory until the collector reuses it. It has no
// effect on a GOEXPERIMENT=runtimesecret build, where nothing is refused, nor
// on Ed25519, X25519 or [Encapsulate], which never make the copies.
func AllowHeapTransients() Option {
	return func(o *options) { o.allowHeapTransients = true }
}

// resolveOptions folds opts into one value. A nil Option is ignored.
//
// The no-options case returns before the fold on purpose: an Option is
// called with a pointer to the value being built, which moves that value to
// the heap, and the functions whose allocation counts classification_test.go
// pins (the in-place HMAC and HKDF) resolve their options on every call.
func resolveOptions(opts []Option) options {
	if len(opts) == 0 {
		return options{}
	}
	return foldOptions(opts)
}

func foldOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// heapTransientsAllowed decides whether RSASigner, ECDSASigner and
// MLKEM768Key may be built on this build without an explicit
// AllowHeapTransients. It is true exactly where the runtime erases the heap
// copies those types make — at the next garbage collection, not when the
// operation returns: a GOEXPERIMENT=runtimesecret build on linux/amd64 or
// linux/arm64.
//
// A package var, not a direct call, so a test can exercise both outcomes
// on any build; policy_test.go pins that its default is
// secmem.RuntimeSecretActive, so this cannot quietly become permissive.
var heapTransientsAllowed = secmem.RuntimeSecretActive

// checkHeapTransientsHash is the same gate for HMACInto and HKDFInto given
// a hash that has no in-place implementation; its remedy names the hashes
// that do.
func (o options) checkHeapTransientsHash(op string) error {
	if o.allowHeapTransients || heapTransientsAllowed() {
		return nil
	}
	return fmt.Errorf("%s: %w (use a SHA-2 or SHA-3 hash, which run in place, build with GOEXPERIMENT=runtimesecret on linux/amd64 or linux/arm64, or pass AllowHeapTransients to accept the residual)", op, ErrHeapTransients)
}

// checkHeapTransients is the gate every RSA, ECDSA and ML-KEM constructor
// calls before touching key material; op names the constructor for the
// error.
func (o options) checkHeapTransients(op string) error {
	if o.allowHeapTransients || heapTransientsAllowed() {
		return nil
	}
	return fmt.Errorf("%s: %w (build with GOEXPERIMENT=runtimesecret on linux/amd64 or linux/arm64, keep the key in an HSM or KMS, or pass AllowHeapTransients to accept the residual)", op, ErrHeapTransients)
}
