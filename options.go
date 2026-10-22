// options.go implements the constructor Option mechanism and the LOUD
// degradation gate. WithInsecureFallback is deliberately ugly to type: a
// silent fallback to the heap is the exact footgun this library exists to
// prevent, so accepting one must be visible at the call site.

package secmem

import (
	"log/slog"
	"runtime"
	"sync"
)

// config collects the effects of constructor Options.
type config struct {
	insecureFallback    bool
	unauthenticatedSeal bool
	closedAtRest        bool
	noMemfdSecret       bool
}

// Option configures a constructor ([NewBuffer], [NewEmptyBuffer],
// [NewBufferFromReader], [NewSecret], [NewArena]).
type Option func(*config)

// WithInsecureFallback permits a constructor to fall back to plain Go heap
// memory on platforms with no lockable off-heap memory (everything except
// linux, darwin, and windows).
//
// It is a permission, not a demand: on supported platforms it changes
// nothing. On unsupported platforms it converts the constructor's
// [ErrNoSecureMemory] failure into a heap allocation with NO protection —
// not locked, swappable, GC-visible, included in core dumps. The resulting
// [Capabilities] report Insecure=true, Warnings() leads with the exposure,
// and a one-time slog warning fires on first use.
func WithInsecureFallback() Option {
	return func(c *config) { c.insecureFallback = true }
}

// WithUnauthenticatedSeal makes [SecureBuffer.Seal] on this buffer page
// protection only (plus the Windows seal cipher): no tag is taken over the
// dormant bytes and [SecureBuffer.Unseal] verifies nothing, so a bit that
// changes while the buffer is sealed is handed back as the secret.
//
// It exists for one reason: the tag's key is derived from a 16 KiB prekey
// locked once per process, and a process whose lock budget cannot spare that
// — RLIMIT_MEMLOCK was 64 KiB on kernels before 5.16 — would otherwise have
// Seal fail. Raise the budget with [EnsureMemlockLimit] first; take this
// option only when that is not available. It is a per-buffer, visible
// choice, reported by [Capabilities.UnauthenticatedSeal] and named by
// [Capabilities.Warnings]. See THREAT-MODEL.md on Rowhammer for what the tag
// protects against.
func WithUnauthenticatedSeal() Option {
	return func(c *config) { c.unauthenticatedSeal = true }
}

// WithoutMemfdSecret makes a constructor skip the memfd_secret tier on Linux
// and allocate the guarded, locked anonymous mapping directly. On other
// platforms it changes nothing.
//
// memfd_secret memory is removed from the kernel's own mappings, which is its
// point, and the kernel therefore refuses to pin it: a buffer that has to be
// handed to a path that pins user pages — O_DIRECT I/O, io_uring registered
// buffers, vmsplice, process_vm_readv — fails there with EFAULT. Use this
// option for such a buffer. It also costs two fewer pages of the lock budget
// per allocation. Everything else is unchanged; [Capabilities.MemfdSecret]
// reports false for the buffer.
func WithoutMemfdSecret() Option {
	return func(c *config) { c.noMemfdSecret = true }
}

// alloc allocates through the tier the options ask for.
func (c config) alloc(size int) (secRegion, []byte, allocInfo, error) {
	if c.noMemfdSecret {
		return allocMapAnon(size)
	}
	return allocSecretMem(size)
}

// applyOptions folds opts into a config. Nil options are ignored (no-panic).
func applyOptions(opts []Option) config {
	var cfg config
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return cfg
}

// gateInsecure is the LOUD degradation policy: allocation on a platform with
// no secure memory fails with [ErrNoSecureMemory] unless the caller opted in.
// The platform fact is a parameter (rather than read from the build-tagged
// const directly) so the policy is testable on every platform.
func gateInsecure(platformSecure bool, cfg config) error {
	if platformSecure {
		return nil
	}
	if !cfg.insecureFallback {
		return ErrNoSecureMemory
	}
	warnInsecureFallback()
	return nil
}

// insecureWarnOnce backs the one-time LOUD warning on first use of the
// fallback.
var insecureWarnOnce sync.Once //nolint:gochecknoglobals // once-only process-wide warning.

// warnInsecureFallback fires the one-time warning that a constructor has
// accepted the plain-heap fallback. It lives on the gate, not in the stub
// allocator: Probe allocates through the same path to REPORT what the
// platform provides, and used to trip the warning on a platform where no
// caller had opted into anything — a false alarm on the one call meant to
// tell the truth quietly.
func warnInsecureFallback() {
	insecureWarnOnce.Do(func() {
		slog.Warn("secmem: INSECURE fallback in use — secrets are on the unprotected Go heap "+
			"(not locked, swappable, GC-visible, included in core dumps)",
			"GOOS", runtime.GOOS, "GOARCH", runtime.GOARCH)
	})
}
