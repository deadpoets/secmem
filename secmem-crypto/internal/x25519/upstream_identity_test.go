package x25519

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestUpstreamIdentity_Ladder makes doc.go's provenance claim checkable:
// x25519ScalarMult is text-identical to the one in the toolchain's own
// crypto/ecdh. A Go release that changes the ladder turns this red and
// forces the re-port. Skips, not fails, when the toolchain's source tree is
// unavailable.
func TestUpstreamIdentity_Ladder(t *testing.T) {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Skipf("go env GOROOT: %v", err)
	}
	theirs, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "src", "crypto", "ecdh", "x25519.go"))
	if err != nil {
		t.Skipf("toolchain source unavailable: %v", err)
	}
	ours, err := os.ReadFile("x25519.go")
	if err != nil {
		t.Fatal(err)
	}
	if a, b := funcText(t, ours), funcText(t, theirs); a != b {
		t.Fatalf("x25519ScalarMult differs from the toolchain's crypto/ecdh copy; doc.go claims identity — port the change or update the claim\nours:\n%s\ntheirs:\n%s", a, b)
	}
}

func funcText(t *testing.T, src []byte) string {
	t.Helper()
	m := regexp.MustCompile(`(?ms)^func x25519ScalarMult\(.*?^}$`).Find([]byte(strings.ReplaceAll(string(src), "\r\n", "\n")))
	if m == nil {
		t.Fatal("x25519ScalarMult not found")
	}
	return string(m)
}
