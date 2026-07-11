package secmem_test

import (
	"fmt"

	"github.com/deadpoets/secmem"
)

// The package-level example shows the core lifecycle: create, defer Destroy
// immediately, and touch the plaintext only inside a borrowing closure.
func Example() {
	key := []byte("super-secret-signing-key")

	buf, err := secmem.NewBuffer(key) // key is wiped after the copy
	if err != nil {
		// On a platform with no lockable off-heap memory this is
		// ErrNoSecureMemory unless WithInsecureFallback() is passed.
		fmt.Println("alloc:", err)
		return
	}
	defer func() { _ = buf.Destroy() }()

	err = buf.WithBytesErr(func(borrowed []byte) error {
		// borrowed is valid ONLY here — never store it or send it elsewhere.
		fmt.Println("secret length:", len(borrowed))
		return nil
	})
	if err != nil {
		fmt.Println("access:", err)
	}
	// Output: secret length: 24
}

// Scope binds a buffer's lifetime to a function and wipes it on return, even
// on panic.
func ExampleScope() {
	err := secmem.Scope(32, func(buf *secmem.SecureBuffer) error {
		if _, err := buf.CopyIn([]byte("derived-key-material"), 0); err != nil {
			return err
		}
		return buf.WithBytesErr(func(b []byte) error {
			fmt.Println("filled", buf.Len(), "bytes")
			return nil
		})
	})
	if err != nil {
		fmt.Println("scope:", err)
	}
	// Output: filled 32 bytes
}

// Secret is safe to embed in structs that get logged, formatted, or
// marshalled: every such path yields the redaction sentinel, never the
// contents.
func ExampleSecret() {
	token, err := secmem.NewSecret([]byte("ghp_realtokenvalue"))
	if err != nil {
		fmt.Println("secret:", err)
		return
	}
	defer func() { _ = token.Destroy() }()

	type Config struct {
		User  string
		Token secmem.Secret
	}
	cfg := Config{User: "svc-account", Token: token}

	// Formatting the whole struct cannot leak the token.
	fmt.Printf("%v\n", cfg)
	// Output: {svc-account [REDACTED]}
}

// Probe reports what the running platform can do; use it once at startup to
// log or gate on the protections in force. The output varies by platform, so
// this example only demonstrates the call.
func ExampleProbe() {
	caps := secmem.Probe()
	if caps.Insecure {
		// Refuse to start, or accept the risk deliberately.
		fmt.Println("no secure memory on this platform")
	}
	for _, w := range caps.Warnings() {
		_ = w // e.g. slog.Warn("secmem", "degradation", w)
	}
}

// SecureArena pools many small same-size secrets in one locked slab — O(1)
// OS overhead where one buffer per secret would exhaust RLIMIT_MEMLOCK.
func ExampleSecureArena() {
	arena, err := secmem.NewArena(32, 128) // 128 slots of 32 bytes
	if err != nil {
		fmt.Println("arena:", err)
		return
	}
	defer func() { _ = arena.Destroy() }()

	slot, err := arena.Acquire()
	if err != nil {
		fmt.Println("acquire:", err)
		return
	}
	_ = slot.WithBytes(func(b []byte) {
		copy(b, []byte("per-session-key"))
	})
	fmt.Println("live slots:", arena.LiveCount())

	_ = slot.Release() // wiped and returned to the pool
	fmt.Println("live slots:", arena.LiveCount())
	// Output:
	// live slots: 1
	// live slots: 0
}
