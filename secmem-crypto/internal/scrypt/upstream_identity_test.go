package scrypt

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This file makes the provenance claims in NOTICE and doc.go checkable
// instead of asserted: the verbatim functions are text-identical to the
// x/crypto scrypt the module resolves, and smix differs from upstream's by
// exactly the edit doc.go describes. A Dependabot bump of x/crypto that
// changes the forked algorithm turns red here and forces the port decision.

// upstreamDir locates the resolved golang.org/x/crypto module's scrypt
// directory through the go tool. Skips, not fails, when the tool or the
// module cache is unavailable (a vendored or offline build).
func upstreamDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "golang.org/x/crypto").Output()
	if err != nil {
		t.Skipf("go list -m golang.org/x/crypto: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Skip("golang.org/x/crypto has no module directory (vendored?)")
	}
	return filepath.Join(dir, "scrypt")
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
	for _, line := range strings.Split(strings.ReplaceAll(string(m), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func sources(t *testing.T) (ours, theirs []byte) {
	t.Helper()
	theirs, err := os.ReadFile(filepath.Join(upstreamDir(t), "scrypt.go"))
	if err != nil {
		t.Fatal(err)
	}
	ours, err = os.ReadFile("scrypt.go")
	if err != nil {
		t.Fatal(err)
	}
	return ours, theirs
}

func TestUpstreamIdentity_VerbatimFunctions(t *testing.T) {
	ours, theirs := sources(t)
	for _, fn := range []string{"blockCopy", "blockXOR", "salsaXOR", "blockMix", "integer"} {
		if a, b := funcText(t, ours, fn), funcText(t, theirs, fn); a != b {
			t.Errorf("%s is documented as verbatim from upstream but differs from the resolved x/crypto copy", fn)
		}
	}
}

// TestUpstreamIdentity_SmixDiffersOnlyByTheHoistedBlock: smix is the one
// forked function that is not verbatim, and the claim is that the only
// change is where tmp lives. Apply that edit to upstream's text — the
// parameter added, the declaration dropped, &tmp become tmp — and the
// result must be ours.
func TestUpstreamIdentity_SmixDiffersOnlyByTheHoistedBlock(t *testing.T) {
	ours, theirs := sources(t)
	up := funcText(t, theirs, "smix")
	for _, edit := range []struct{ from, to string }{
		{"func smix(b []byte, r, N int, v, xy []uint32) {", "func smix(b []byte, r, N int, v, xy []uint32, tmp *[16]uint32) {"},
		{"\tvar tmp [16]uint32\n", ""},
		{"&tmp", "tmp"},
	} {
		if !strings.Contains(up, edit.from) {
			t.Fatalf("upstream's smix no longer contains %q: it changed, so the port has to be looked at", edit.from)
		}
		up = strings.ReplaceAll(up, edit.from, edit.to)
	}
	if got := funcText(t, ours, "smix"); got != up {
		t.Errorf("smix differs from upstream's by more than the hoisted chaining block\n--- ours\n%s\n--- upstream, edited\n%s", got, up)
	}
}
