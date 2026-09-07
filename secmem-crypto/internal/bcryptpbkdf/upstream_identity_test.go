package bcryptpbkdf

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
// instead of asserted: const.go is byte-identical to x/crypto's blowfish
// tables below the package clause, and the verbatim functions are
// text-identical to theirs. A Dependabot bump of x/crypto that changes the
// forked algorithm turns red here and forces the port decision.

// upstreamDir locates a directory of the resolved golang.org/x/crypto module
// through the go tool. Skips, not fails, when the tool or the module cache
// is unavailable (a vendored or offline build).
func upstreamDir(t *testing.T, sub string) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "golang.org/x/crypto").Output()
	if err != nil {
		t.Skipf("go list -m golang.org/x/crypto: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Skip("golang.org/x/crypto has no module directory (vendored?)")
	}
	return filepath.Join(dir, sub)
}

// TestUpstreamIdentity_Constants compares const.go with upstream's after
// dropping every comment line and the package clause from both: the only
// edits on our side are the provenance note and the package name.
func TestUpstreamIdentity_Constants(t *testing.T) {
	theirs, err := os.ReadFile(filepath.Join(upstreamDir(t, "blowfish"), "const.go"))
	if err != nil {
		t.Fatal(err)
	}
	ours, err := os.ReadFile("const.go")
	if err != nil {
		t.Fatal(err)
	}
	if a, b := codeOnly(ours), codeOnly(theirs); a != b {
		t.Fatal("const.go differs from the resolved golang.org/x/crypto/blowfish/const.go beyond the package clause; NOTICE claims identity — port the change or update the claim")
	}
}

func codeOnly(src []byte) string {
	var kept []string
	for _, line := range strings.Split(string(src), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "package ") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// funcText returns the source text of the named top-level function in src,
// from "func name(" to the closing brace at column 0, with comment-only
// lines dropped.
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
	bf := upstreamDir(t, "blowfish")
	ours, err := os.ReadFile("blowfish.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ theirFile, fn string }{
		{"block.go", "getNextWord"},
		{"block.go", "ExpandKey"},
		{"block.go", "expandKeyWithSalt"},
		{"block.go", "encryptBlock"},
		{"cipher.go", "initCipher"},
		{"cipher.go", "(c *Cipher) Encrypt"},
	} {
		theirs, err := os.ReadFile(filepath.Join(bf, c.theirFile))
		if err != nil {
			t.Fatal(err)
		}
		if a, b := funcText(t, ours, c.fn), funcText(t, theirs, c.fn); a != b {
			t.Errorf("%s is documented as verbatim from upstream but differs from the resolved x/crypto copy", c.fn)
		}
	}
}

// TestUpstreamIdentity_Vectors pins that the golden vectors in this package
// are upstream's, byte for byte, so a vector edit here cannot pass as an
// upstream one.
func TestUpstreamIdentity_Vectors(t *testing.T) {
	theirs, err := os.ReadFile(filepath.Join(upstreamDir(t, filepath.Join("ssh", "internal", "bcrypt_pbkdf")), "bcrypt_pbkdf_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	ours, err := os.ReadFile("bcrypt_pbkdf_test.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?ms)^var golden = .*?^}$`)
	a, b := re.Find(ours), re.Find(theirs)
	if a == nil || b == nil {
		t.Fatal("golden table not found")
	}
	if !bytes.Equal(a, b) {
		t.Fatal("the golden vectors differ from upstream's")
	}
}
