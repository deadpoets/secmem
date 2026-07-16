package secmemcrypto

import (
	"strings"
	"testing"
)

// TestEFFWordlist_Integrity pins the real embedded file's shape: exactly
// 7776 words (6^5, the classic 5-dice diceware construction), all unique,
// none dropped by effWords' defensive parsing. If the embedded file were
// ever accidentally truncated, re-encoded, or corrupted, this fails loudly
// instead of silently shrinking the effective wordlist.
func TestEFFWordlist_Integrity(t *testing.T) {
	list := effWords()
	const want = 7776
	if len(list) != want {
		t.Fatalf("effWords() returned %d words, want %d", len(list), want)
	}

	seen := make(map[string]bool, want)
	for i, w := range list {
		if w == "" {
			t.Fatalf("word %d is empty", i)
		}
		if strings.ContainsAny(w, " \t\r\n") {
			t.Fatalf("word %d = %q contains whitespace", i, w)
		}
		if seen[w] {
			t.Fatalf("word %q appears more than once", w)
		}
		seen[w] = true
	}
}

// TestGenerateDicewarePassphrase_WordCountAndSeparators proves the output
// has exactly n words separated by single spaces — n-1 spaces, no leading,
// trailing, or doubled separators.
func TestGenerateDicewarePassphrase_WordCountAndSeparators(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 2, 6, 10} {
		buf, err := GenerateDicewarePassphrase(n)
		if err != nil {
			t.Fatalf("n=%d: GenerateDicewarePassphrase: %v", n, err)
		}

		var words []string
		_ = buf.WithBytesErr(func(b []byte) error {
			words = strings.Split(string(b), " ") //nolint:secmem-lint // test splits the generated phrase to verify its shape
			return nil
		})
		_ = buf.Destroy()

		if len(words) != n {
			t.Errorf("n=%d: got %d space-separated fields, want %d (fields: %q)", n, len(words), n, words)
		}
		for _, w := range words {
			if w == "" {
				t.Errorf("n=%d: empty field — doubled or edge separator", n)
			}
		}
	}
}

// TestGenerateDicewarePassphrase_WordsAreFromTheList proves every generated
// word is a genuine member of the embedded wordlist, not an artifact of a
// parsing or indexing bug.
func TestGenerateDicewarePassphrase_WordsAreFromTheList(t *testing.T) {
	t.Parallel()
	valid := make(map[string]bool, len(effWords()))
	for _, w := range effWords() {
		valid[w] = true
	}

	buf, err := GenerateDicewarePassphrase(20)
	if err != nil {
		t.Fatalf("GenerateDicewarePassphrase: %v", err)
	}
	defer buf.Destroy()

	_ = buf.WithBytesErr(func(b []byte) error {
		for _, w := range strings.Split(string(b), " ") { //nolint:secmem-lint // test validates generated words against the public wordlist
			if !valid[w] {
				t.Errorf("generated word %q is not in the EFF wordlist", w)
			}
		}
		return nil
	})
}

// TestGenerateDicewarePassphrase_Varies is a basic sanity check that output
// is not fixed or degenerate — not a rigorous randomness test (crypto/rand
// itself is trusted), just a guard against an index-always-zero-style bug.
func TestGenerateDicewarePassphrase_Varies(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		buf, err := GenerateDicewarePassphrase(6)
		if err != nil {
			t.Fatalf("GenerateDicewarePassphrase: %v", err)
		}
		var phrase string
		_ = buf.WithBytesErr(func(b []byte) error { phrase = string(b); return nil }) //nolint:secmem-lint // test checks output varies across calls
		_ = buf.Destroy()
		seen[phrase] = true
	}
	if len(seen) < 18 { // allow a little slack; a collision at 6 words from 7776 is astronomically unlikely
		t.Errorf("only %d distinct passphrases across 20 calls — suspiciously low variation", len(seen))
	}
}

// TestGenerateDicewarePassphrase_InvalidN proves n < 1 errors rather than
// returning an empty or nil buffer.
func TestGenerateDicewarePassphrase_InvalidN(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, -1, -100} {
		if _, err := GenerateDicewarePassphrase(n); err == nil {
			t.Errorf("n=%d: expected an error, got nil", n)
		}
	}
}

// TestGenerateDicewarePassphrase_OneWordNoSeparator covers the n=1 edge case
// explicitly: no space at all, just the single word.
func TestGenerateDicewarePassphrase_OneWordNoSeparator(t *testing.T) {
	t.Parallel()
	buf, err := GenerateDicewarePassphrase(1)
	if err != nil {
		t.Fatalf("GenerateDicewarePassphrase: %v", err)
	}
	defer buf.Destroy()

	_ = buf.WithBytesErr(func(b []byte) error {
		if strings.Contains(string(b), " ") { //nolint:secmem-lint // test checks the single-word output contains no separator
			t.Errorf("n=1 output contains a space: %q", b)
		}
		return nil
	})
}
