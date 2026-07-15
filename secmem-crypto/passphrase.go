// passphrase.go generates a diceware-style passphrase directly into a
// [secmem.SecureBuffer] using the EFF long wordlist — see NOTICE for that
// file's attribution and license (CC BY 3.0, distinct from this project's
// own Apache-2.0).
package secmemcrypto

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/deadpoets/secmem"
)

//go:embed eff_large_wordlist.txt
var effWordlistRaw string

var (
	effWordlistOnce sync.Once //nolint:gochecknoglobals // lazy-parsed, immutable once loaded
	effWordlist     []string  //nolint:gochecknoglobals // lazy-parsed, immutable once loaded
)

// effWords parses the embedded wordlist on first use. The file is
// "<5-digit dice-roll code>\t<word>" per line, exactly as the EFF
// distributes it; only the word column is kept.
func effWords() []string {
	effWordlistOnce.Do(func() {
		lines := strings.Split(effWordlistRaw, "\n")
		words := make([]string, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				continue
			}
			_, word, ok := strings.Cut(line, "\t")
			if !ok {
				continue // defensive; TestEFFWordlist_Integrity pins the real file's shape
			}
			words = append(words, word)
		}
		effWordlist = words
	})
	return effWordlist
}

// GenerateDicewarePassphrase draws n words uniformly at random — via
// crypto/rand, one rejection-free draw per word — from the 7776-word EFF
// long wordlist (~12.9 bits of entropy per word: log2(7776)), joins them
// with single spaces, and writes the result directly into a fresh
// SecureBuffer the caller owns and must Destroy. n must be >= 1; the EFF's
// own guidance suggests at least 6 words (~77 bits) for anything long-lived.
//
// The chosen words themselves are not secret — the wordlist is public — so
// selecting them holds only word references (into the embedded list's own
// backing memory, not separately allocated secret bytes) on the ordinary
// heap for the duration of this call. What the words spell out together,
// the actual passphrase, is assembled directly inside the returned buffer's
// borrowing closure and never exists as a combined heap string or []byte at
// any point — there is no [strings.Join] here precisely because its result
// would be an immutable Go string this package could never wipe.
func GenerateDicewarePassphrase(n int) (*secmem.SecureBuffer, error) {
	if n < 1 {
		return nil, fmt.Errorf("secmemcrypto: generate diceware passphrase: n must be >= 1, got %d", n)
	}
	list := effWords()
	listLen := big.NewInt(int64(len(list)))

	chosen := make([]string, n)
	total := 0
	for i := range chosen {
		idx, err := rand.Int(rand.Reader, listLen)
		if err != nil {
			return nil, fmt.Errorf("secmemcrypto: generate diceware passphrase: %w", err)
		}
		chosen[i] = list[idx.Int64()]
		total += len(chosen[i])
		if i > 0 {
			total++ // separating space
		}
	}

	out, err := secmem.NewEmptyBuffer(total)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate passphrase buffer: %w", err)
	}
	if err := out.WithBytesErr(func(dst []byte) error {
		pos := 0
		for i, w := range chosen {
			if i > 0 {
				dst[pos] = ' '
				pos++
			}
			pos += copy(dst[pos:], w)
		}
		return nil
	}); err != nil {
		_ = out.Destroy()
		return nil, fmt.Errorf("secmemcrypto: generate diceware passphrase: %w", err)
	}
	return out, nil
}
