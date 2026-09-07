//go:build !race

// Allocation-site attribution needs an exact memory profile, which the race
// detector's instrumentation perturbs; the non-race CI job runs this.

package secmemcrypto

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestParsePrivateKey_ParserAllocatesNoSecret is the proof behind
// ParsePrivateKey's claim that the parser itself puts nothing on the heap
// but public metadata. It sets the memory profiler to record every
// allocation, parses each Ed25519, ECDSA, and (non-OpenSSH) RSA encoding,
// and attributes every allocation that happened to the first frame of this
// package on its stack. An allocation owned by parse.go or parse_openssh.go
// fails the test unless its site is one of two known non-secret sources:
// cryptobyte materialising an OBJECT IDENTIFIER (algorithm and curve names)
// and the core secmem package's bookkeeping for a new buffer (a Go-side
// struct; the bytes themselves are off-heap). Allocations owned by the
// signer constructors (ed25519.go, ecdsa.go, rsa.go) are those types'
// documented business, not the parser's.
//
// The OpenSSH RSA container is excluded on purpose: pkcs1DER computes the
// CRT exponents with math/big and says so in its doc — that path is
// covered by the DER identity test, not by this proof.
//
// A stray copy — a seed cloned into a []byte, a scalar formatted into an
// error, an escaping closure — shows up here as a named allocation site.
func TestParsePrivateKey_ParserAllocatesNoSecret(t *testing.T) {
	old := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	t.Cleanup(func() { runtime.MemProfileRate = old })

	for _, k := range parseTestKeys(t) {
		for _, enc := range encodings(t, k) {
			if k.pkcs1 && strings.HasPrefix(enc.name, "openssh") {
				continue
			}
			t.Run(k.name+"/"+enc.name, func(t *testing.T) {
				// One warm-up parse so lazily initialised state (curve
				// tables, the secmem registry, profiler buckets) is not
				// attributed to the measured runs.
				s, err := ParsePrivateKey(enc.data)
				if err != nil {
					t.Fatal(err)
				}
				s.Destroy()

				runtime.GC()
				runtime.GC()
				before := memProfileByStack()
				for range 3 {
					s, err := ParsePrivateKey(enc.data)
					if err != nil {
						t.Fatal(err)
					}
					s.Destroy()
				}
				runtime.GC()
				runtime.GC()
				after := memProfileByStack()

				for stack, rec := range after {
					delta := rec.AllocObjects - before[stack].AllocObjects
					if delta <= 0 {
						continue
					}
					if site := parserOwnedAllocation(rec, delta); site != "" {
						t.Errorf("parser allocated on the heap: %s", site)
					}
				}
			})
		}
	}
}

// memProfileByStack snapshots the memory profile keyed by call stack. The
// profile is updated at garbage collection, so callers GC first.
func memProfileByStack() map[[32]uintptr]runtime.MemProfileRecord {
	n, _ := runtime.MemProfile(nil, true)
	recs := make([]runtime.MemProfileRecord, n+64)
	for {
		m, ok := runtime.MemProfile(recs, true)
		if ok {
			recs = recs[:m]
			break
		}
		recs = make([]runtime.MemProfileRecord, m+64)
	}
	out := make(map[[32]uintptr]runtime.MemProfileRecord, len(recs))
	for _, r := range recs {
		out[r.Stack0] = r
	}
	return out
}

// parserOwnedAllocation returns a description of the allocation when its
// owning frame in this package is in the parser's files and no frame between
// the allocation and that owner belongs to an allowlisted non-secret source;
// "" otherwise. The allowlist is checked along the whole path, not only at
// the innermost frame, because the core package's buffer bookkeeping
// allocates through sync (a lock's condition variable) and the profiler
// names sync as the site.
func parserOwnedAllocation(rec runtime.MemProfileRecord, objects int64) string {
	return ownedAllocation(rec, objects,
		map[string]bool{"parse.go": true, "parse_openssh.go": true},
		[]string{
			"github.com/deadpoets/secmem.",    // SecureBuffer bookkeeping; the contents are off-heap
			"golang.org/x/crypto/cryptobyte.", // OBJECT IDENTIFIER slices: algorithm and curve names
		})
}

// ownedAllocation is parserOwnedAllocation for any set of owning files and
// any allowlist of function-name prefixes (parse_proof_encrypted_test.go
// uses it for the passphrase paths).
func ownedAllocation(rec runtime.MemProfileRecord, objects int64, files map[string]bool, allowedPrefixes []string) string {
	const pkg = "github.com/deadpoets/secmem/secmem-crypto."
	var site, owner runtime.Frame
	haveSite, haveOwner, allowed := false, false, false
	frames := runtime.CallersFrames(rec.Stack())
	for {
		f, more := frames.Next()
		if !haveSite && !strings.HasPrefix(f.Function, "runtime.") {
			site, haveSite = f, true
		}
		if !haveOwner {
			if strings.HasPrefix(f.Function, pkg) {
				owner, haveOwner = f, true
			} else {
				for _, prefix := range allowedPrefixes {
					if strings.HasPrefix(f.Function, prefix) {
						allowed = true
					}
				}
			}
		}
		if !more {
			break
		}
	}
	if !haveOwner || allowed || !files[filepath.Base(owner.File)] {
		return ""
	}
	return fmt.Sprintf("%d object(s) at %s (%s:%d), owned by %s (%s:%d)",
		objects, site.Function, filepath.Base(site.File), site.Line,
		owner.Function, filepath.Base(owner.File), owner.Line)
}
