package secmem

import (
	"errors"
	"runtime"
	"testing"
)

// TestGateInsecure_Policy pins the LOUD degradation policy across all four
// combinations: only "no secure memory AND no opt-in" fails, and it fails
// with the ErrNoSecureMemory sentinel.
func TestGateInsecure_Policy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		platformSecure bool
		optIn          bool
		wantErr        bool
	}{
		{"secure platform, no opt-in", true, false, false},
		{"secure platform, opt-in", true, true, false},
		{"stub platform, no opt-in", false, false, true},
		{"stub platform, opt-in", false, true, false},
	}
	for _, tc := range cases {
		err := gateInsecure(tc.platformSecure, config{insecureFallback: tc.optIn})
		if tc.wantErr && !errors.Is(err, ErrNoSecureMemory) {
			t.Errorf("%s: err = %v, want ErrNoSecureMemory", tc.name, err)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: err = %v, want nil", tc.name, err)
		}
	}
}

// TestApplyOptions verifies option folding, including the no-panic rule for
// a nil Option in the list.
func TestApplyOptions(t *testing.T) {
	t.Parallel()
	if cfg := applyOptions(nil); cfg.insecureFallback {
		t.Error("zero options set insecureFallback")
	}
	if cfg := applyOptions([]Option{nil, WithInsecureFallback(), nil}); !cfg.insecureFallback {
		t.Error("WithInsecureFallback did not set insecureFallback (or a nil Option panicked earlier)")
	}
}

// TestWithInsecureFallback_PermissionNotDemand pins the option's semantics on
// supported platforms: passing it changes nothing — the buffer is still
// off-heap and secure. It permits degradation; it never causes it.
func TestWithInsecureFallback_PermissionNotDemand(t *testing.T) {
	t.Parallel()
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
	default:
		t.Skipf("stub platform %s: covered by the stub-tagged tests", runtime.GOOS)
	}

	buf, err := NewBuffer([]byte("opt-in-on-supported"), WithInsecureFallback())
	if err != nil {
		t.Fatalf("NewBuffer with WithInsecureFallback: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	c := buf.Capabilities()
	if c.Insecure {
		t.Error("WithInsecureFallback forced the insecure path on a supported platform")
	}
	if !c.OffHeap {
		t.Error("buffer not off-heap on a supported platform despite WithInsecureFallback being a no-op")
	}
}

// TestConstructors_AcceptOptions verifies every constructor takes the
// variadic options and still round-trips on this platform.
func TestConstructors_AcceptOptions(t *testing.T) {
	t.Parallel()
	buf, err := NewEmptyBuffer(32, WithInsecureFallback())
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	_ = buf.Destroy()

	buf, err = NewSyscallSafeBuffer([]byte("syscall-safe-opts"), WithInsecureFallback())
	if err != nil {
		t.Fatalf("NewSyscallSafeBuffer: %v", err)
	}
	_ = buf.Destroy()

	arena, err := NewArena(16, 2, WithInsecureFallback())
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	_ = arena.Destroy()
}
