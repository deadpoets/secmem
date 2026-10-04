package argon2

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This file makes the provenance claims in NOTICE and doc.go checkable
// instead of asserted: blamka_amd64.s is byte-identical to the x/crypto
// argon2 the module resolves, and the verbatim Go functions are
// text-identical to theirs. A Dependabot bump of x/crypto that changes the
// forked algorithm turns red here and forces the port decision, rather
// than leaving the fork silently behind a fix.

// upstreamArgon2Dir locates the resolved golang.org/x/crypto module's argon2
// directory through the go tool. Skips, not fails, when the tool or the
// module cache is unavailable (a vendored or offline build), since that is
// an environment condition.
func upstreamArgon2Dir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "golang.org/x/crypto").Output()
	if err != nil {
		t.Skipf("go list -m golang.org/x/crypto: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Skip("golang.org/x/crypto has no module directory (vendored?)")
	}
	return filepath.Join(dir, "argon2")
}

func TestUpstreamIdentity_Assembly(t *testing.T) {
	up := upstreamArgon2Dir(t)
	theirs, err := os.ReadFile(filepath.Join(up, "blamka_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	ours, err := os.ReadFile("blamka_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ours, theirs) {
		t.Fatal("blamka_amd64.s differs from the resolved golang.org/x/crypto/argon2/blamka_amd64.s; NOTICE claims byte identity — port the change or update the claim")
	}
}

// funcText returns the source text of the named top-level function in src,
// from "func name(" to the closing brace at column 0, with comment-only
// lines dropped so that a lint annotation on our side does not count as a
// change to the algorithm.
func funcText(t *testing.T, src []byte, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?ms)^func ` + regexp.QuoteMeta(name) + `\(.*?^}$`)
	m := re.Find(src)
	if m == nil {
		t.Fatalf("function %s not found", name)
	}
	var kept []string
	for _, line := range strings.Split(string(m), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func TestUpstreamIdentity_VerbatimFunctions(t *testing.T) {
	up := upstreamArgon2Dir(t)
	for _, c := range []struct{ ourFile, theirFile, fn string }{
		{"blamka_generic.go", "blamka_generic.go", "blamkaGeneric"},
		{"argon2.go", "argon2.go", "indexAlpha"},
		{"argon2.go", "argon2.go", "phi"},
	} {
		ours, err := os.ReadFile(c.ourFile)
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := os.ReadFile(filepath.Join(up, c.theirFile))
		if err != nil {
			t.Fatal(err)
		}
		if a, b := funcText(t, ours, c.fn), funcText(t, theirs, c.fn); a != b {
			t.Errorf("%s is documented as verbatim from upstream but differs from the resolved x/crypto copy", c.fn)
		}
	}
}

// varText is funcText for a top-level `var name = …` declaration that ends
// with a closing brace in column 0, trailing line comments dropped.
func varText(t *testing.T, src []byte, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?ms)^var ` + regexp.QuoteMeta(name) + ` = .*?^}$`)
	m := re.Find(src)
	if m == nil {
		t.Fatalf("variable %s not found", name)
	}
	return regexp.MustCompile(`(?m)\s*//.*$`).ReplaceAllString(string(m), "")
}

// TestUpstreamIdentity_BLAKE2b covers the other package this fork copies
// from. The copies cannot be text-identical — outside package blake2b the
// constants need its qualifier, and checkSum calls the portable compression
// function by its own name rather than through the dispatching hashBlocks —
// so they are compared with exactly those two differences undone, and
// nothing else. H0 and every H' length without a one-shot go through this
// code; a bump that changes it upstream fails here, at the bump.
func TestUpstreamIdentity_BLAKE2b(t *testing.T) {
	up := filepath.Join(filepath.Dir(upstreamArgon2Dir(t)), "blake2b")
	ours, err := os.ReadFile("blake2b_generic.go")
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(up, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	generic, main := read("blake2b_generic.go"), read("blake2b.go")
	unqualify := func(s string) string { return strings.ReplaceAll(s, "blake2b.", "") }

	if a, b := unqualify(funcText(t, ours, "hashBlocksGeneric")), funcText(t, generic, "hashBlocksGeneric"); a != b {
		t.Error("hashBlocksGeneric differs from the resolved x/crypto copy by more than the blake2b qualifier")
	}
	a := strings.ReplaceAll(unqualify(funcText(t, ours, "checkSum")), "hashBlocksGeneric(", "hashBlocks(")
	if b := funcText(t, main, "checkSum"); a != b {
		t.Error("checkSum differs from the resolved x/crypto copy by more than the qualifier and the compression function's name")
	}
	if a, b := varText(t, ours, "precomputed"), varText(t, generic, "precomputed"); a != b {
		t.Error("precomputed differs from the resolved x/crypto copy")
	}
	if a, b := varText(t, ours, "iv"), varText(t, main, "iv"); a != b {
		t.Error("iv differs from the resolved x/crypto copy")
	}
}
