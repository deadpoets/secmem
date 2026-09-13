package secmemcrypto

import (
	"errors"
	"fmt"

	"github.com/deadpoets/secmem"
)

// ErrHeapTransients is returned, wrapped, when a constructor refuses to build
// a key type whose every operation copies the private key through the Go
// heap — [RSASigner] and [ECDSASigner] — on a build where nothing erases
// those copies.
//
// That is every build except linux/amd64 and linux/arm64 compiled with
// GOEXPERIMENT=runtimesecret: Windows, macOS, and Linux without the
// experiment. There the standard library's per-signature copies of the
// scalar or the key (listed in each type's doc and in the README under
// "What each signer actually buys you") are reclaimed by the collector but
// never zeroed, so a heap dump of a process that signs contains the key
// whether or not the durable copy lives in a SecureBuffer.
//
// Returned by [NewRSASigner], [GenerateRSASigner], [NewECDSASigner],
// [GenerateECDSASigner], and by [ParsePrivateKey] and
// [ParsePrivateKeyWithPassphrase] for an RSA or EC key file. The refusal
// happens before the key is handed to the standard library, so a refused
// call makes none of the heap copies it exists to prevent. A caller who
// accepts that residual passes [AllowHeapTransients]; a caller who does not
// should build with the experiment or keep the key in an HSM or KMS.
// Ed25519 keys are never refused.
var ErrHeapTransients = errors.New("secmemcrypto: operation would leave key material on the unprotected heap on this build")

// Option configures a constructor or parser in this package.
type Option func(*options)

type options struct {
	allowHeapTransients bool
}

// AllowHeapTransients lets [RSASigner] and [ECDSASigner] be built on a
// build where their per-operation heap copies of the private key are never
// erased. Without it, the constructors and the parsers refuse such keys
// there with [ErrHeapTransients].
//
// Pass it when the durable key in locked memory is what you want and the
// transients are an accepted residual: a process that loads a key and signs
// rarely spends most of its life with the key only in the buffer. Do not
// pass it to make an error go away on a service that signs continuously —
// that process has an unwiped copy of the key on the heap at almost every
// moment, and the buffer does not change that. It has no effect on a
// GOEXPERIMENT=runtimesecret build, where the copies are erased and nothing
// is refused, nor on Ed25519, which never makes them.
func AllowHeapTransients() Option {
	return func(o *options) { o.allowHeapTransients = true }
}

// resolveOptions folds opts into one value. A nil Option is ignored.
func resolveOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// heapTransientsAllowed decides whether RSASigner and ECDSASigner may be
// built on this build without an explicit AllowHeapTransients. It is true
// exactly where the runtime erases the heap copies those types make: a
// GOEXPERIMENT=runtimesecret build on linux/amd64 or linux/arm64.
//
// A package var, not a direct call, so a test can exercise both outcomes
// on any build; policy_test.go pins that its default is
// secmem.RuntimeSecretActive, so this cannot quietly become permissive.
var heapTransientsAllowed = secmem.RuntimeSecretActive

// checkHeapTransients is the gate every RSA and ECDSA constructor calls
// before touching key material; op names the constructor for the error.
func (o options) checkHeapTransients(op string) error {
	if o.allowHeapTransients || heapTransientsAllowed() {
		return nil
	}
	return fmt.Errorf("%s: %w (build with GOEXPERIMENT=runtimesecret on linux/amd64 or linux/arm64, keep the key in an HSM or KMS, or pass AllowHeapTransients to accept the residual)", op, ErrHeapTransients)
}
