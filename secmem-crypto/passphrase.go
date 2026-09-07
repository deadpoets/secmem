// passphrase.go generates a diceware-style passphrase directly into a
// [secmem.SecureBuffer] using the EFF long wordlist — see NOTICE for that
// file's attribution and license (CC BY 3.0, distinct from this project's
// own Apache-2.0).
package secmemcrypto

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"errors"
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

// wordList is the read side of a wordlist as [selectWord] sees it. It is an
// interface, not a []string, so a test can substitute an implementation
// that counts how often each entry is read and prove the access pattern is
// the same for every index; production always passes [stringWordList].
type wordList interface {
	Len() int
	At(i int) string
}

// stringWordList adapts a []string to [wordList].
type stringWordList []string

func (l stringWordList) Len() int        { return len(l) }
func (l stringWordList) At(i int) string { return l[i] }

// selectWord writes words.At(idx) into slot, zero-padded to len(slot), and
// returns the word's length — with a memory access pattern that does not
// depend on idx. Indexing the list directly with the secret draw
// (list[idx]) touches one entry, and the wordlist lives in the binary's
// read-only data, page-cache-shared with every other process running the
// same binary: exactly the precondition for a Flush+Reload observer to
// learn which cache line, and so which handful of candidate words, each
// draw hit. selectWord instead reads every entry's bytes on every call and
// keeps the match with [subtle.ConstantTimeSelect], so the only reads that
// vary are the ones any implementation must make.
//
// The branch on each candidate's length is on public data (the candidate's
// position in the list, not the draw). Entries longer than slot are
// truncated; the caller sizes slot to the longest entry. An idx outside
// [0, words.Len()) selects nothing: slot is left as it was and 0 is
// returned, so callers validate the draw first.
func selectWord(slot []byte, words wordList, idx int64) int {
	n := 0
	for j := range words.Len() {
		w := words.At(j)
		mask := subtle.ConstantTimeEq(int32(j), int32(idx)) //nolint:gosec // G115: j < words.Len() and idx are both bounded by a 7776-entry list; no overflow is reachable
		for p := range slot {
			var b byte
			if p < len(w) {
				b = w[p]
			}
			slot[p] = byte(subtle.ConstantTimeSelect(mask, int(b), int(slot[p]))) //nolint:gosec // G115: the select yields one of its two operands, both bytes widened to int
		}
		n = subtle.ConstantTimeSelect(mask, len(w), n)
	}
	return n
}

// drawWordIndex draws a uniform index in [0, bound) with crypto/rand — one
// rejection-free [rand.Int] draw, exactly as the previous list[idx]
// implementation did, so the same random bytes still select the same word.
// The big.Int the draw lands in is zeroed before it is dropped.
func drawWordIndex(bound int64) (int64, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(bound))
	if err != nil {
		return 0, err
	}
	idx := v.Int64()
	wipeBigInt(v)
	return idx, nil
}

// GenerateDicewarePassphrase draws n words uniformly at random — via
// crypto/rand, one rejection-free draw per word — from the 7776-word EFF
// long wordlist (~12.9 bits of entropy per word: log2(7776)), joins them
// with single spaces, and writes the result directly into a fresh
// SecureBuffer the caller owns and must Destroy. n must be >= 1; the EFF's
// own guidance suggests at least 6 words (~77 bits) for anything long-lived.
//
// Individual words are public wordlist content, but which ones get chosen,
// and in what order, is exactly the passphrase. So every selected word is
// written straight into the returned buffer, inside its own borrowing
// closure, by a constant-access-pattern gather over the whole list (see
// [selectWord]): the passphrase never exists as a []string of chosen words,
// a joined heap string, or a []byte anywhere else, and the reads of the
// shared wordlist do not reveal which entries were chosen. The buffer is
// allocated for n longest words and trimmed to the real length with
// [secmem.SecureBuffer.Truncate], which wipes the unused tail. Selection and
// assembly run inside one [secmem.ScrubErr]-guarded region, so the draw's
// transient big.Int and the call-stack residue are erased on runtimesecret
// builds, the same discipline [HMACInto] and
// [Ed25519Signer.MarshalOpenSSHPrivateKey] apply to their own heap transits.
//
// Honesty caveat — what is not hidden: the draw itself (crypto/rand's
// rejection sampling, and the index in the transient big.Int) and the
// write offsets inside the SecureBuffer, which advance by each chosen
// word's length. Those writes land in process-private locked memory, not in
// a shared page, so they are outside the shared-table channel selectWord
// closes; they could at most leak cumulative word lengths to an observer
// already co-resident on the core, which the threat model excludes.
func GenerateDicewarePassphrase(n int) (*secmem.SecureBuffer, error) {
	return generateDiceware(n, stringWordList(effWords()), drawWordIndex)
}

// generateDiceware is [GenerateDicewarePassphrase] with the wordlist and the
// draw injected, so tests can pin the output for fixed random bytes and
// observe the access pattern without a package-level seam.
func generateDiceware(n int, words wordList, draw func(bound int64) (int64, error)) (*secmem.SecureBuffer, error) {
	if n < 1 {
		return nil, fmt.Errorf("secmemcrypto: generate diceware passphrase: n must be >= 1, got %d", n)
	}
	count := words.Len()
	if count == 0 {
		return nil, errors.New("secmemcrypto: generate diceware passphrase: empty wordlist")
	}
	maxLen := 0
	for j := range count {
		maxLen = max(maxLen, len(words.At(j)))
	}

	var out *secmem.SecureBuffer
	err := secmem.ScrubErr(func() error {
		// Room for n longest words plus separators; the length actually
		// used is only known once the words are chosen, and choosing them
		// outside the buffer is what this function exists to avoid.
		buf, err := secmem.NewEmptyBuffer(n*maxLen + (n - 1))
		if err != nil {
			return fmt.Errorf("secmemcrypto: allocate passphrase buffer: %w", err)
		}
		total := 0
		if err := buf.WithBytesErr(func(dst []byte) error {
			pos := 0
			for i := range n {
				idx, err := draw(int64(count))
				if err != nil {
					return err
				}
				if idx < 0 || idx >= int64(count) {
					return fmt.Errorf("internal error: draw returned %d, want [0, %d)", idx, count)
				}
				if i > 0 {
					dst[pos] = ' '
					pos++
				}
				// The slot's zero padding past the word is overwritten by the
				// next separator and word, or wiped by Truncate for the last.
				pos += selectWord(dst[pos:pos+maxLen], words, idx)
			}
			total = pos
			return nil
		}); err != nil {
			_ = buf.Destroy()
			return fmt.Errorf("secmemcrypto: generate diceware passphrase: %w", err)
		}
		if err := buf.Truncate(total); err != nil {
			_ = buf.Destroy()
			return fmt.Errorf("secmemcrypto: generate diceware passphrase: %w", err)
		}
		out = buf
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
