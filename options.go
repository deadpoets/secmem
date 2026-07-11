// options.go implements the constructor Option mechanism and the LOUD
// degradation gate. The only option so far is WithInsecureFallback —
// deliberately ugly to type: a silent fallback to the heap is the exact
// footgun this library exists to prevent, so accepting one must be visible
// at the call site.

package secmem

// config collects the effects of constructor Options.
type config struct {
	insecureFallback bool
}

// Option configures a constructor ([NewBuffer], [NewEmptyBuffer],
// [NewSyscallSafeBuffer], [NewBufferFromReader], [NewArena]).
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
	if !platformSecure && !cfg.insecureFallback {
		return ErrNoSecureMemory
	}
	return nil
}
