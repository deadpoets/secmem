// Package forks reads forks.json, the record of every piece of third-party
// code copied into this module.
//
// It exists so that the two readers of that file cannot disagree about it:
// forks_test.go, which checks the manifest against the tree and against the
// prose in NOTICE and each fork's doc.go, and internal/forkcheck, which asks
// whether upstream has moved since the fork point. The manifest's own
// _comment explains the contract; CONTRIBUTING.md's "Maintaining the forks"
// explains what to do when the answer is yes.
package forks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Name is the manifest's filename, at the module root.
const Name = "forks.json"

// Upstream kinds.
const (
	KindGomod  = "gomod"  // a Go module, every version fetchable from the proxy
	KindGoroot = "goroot" // the standard library of whichever toolchain runs
	KindURL    = "url"    // a published file, embedded byte-for-byte
)

// Identity comparison modes.
const (
	ModeBytes = "bytes" // whole file, exactly
	ModeCode  = "code"  // ignoring comments, blank lines and the package clause
	ModeFunc  = "func"  // one top-level function, comment lines dropped
	ModeBlock = "block" // the span matched by Name as a regexp
)

type Manifest struct {
	Comment []string `json:"_comment"`
	Forks   []Fork   `json:"forks"`
}

type Fork struct {
	ID       string   `json:"id"`
	Path     string   `json:"path"`
	Notes    string   `json:"notes"`
	Upstream Upstream `json:"upstream"`
	// ForkPoint is the upstream version this copy was taken from. It is
	// history: a dependency bump moves the module's requirement, not this.
	ForkPoint string `json:"fork_point,omitempty"`
	// Reviewed records upstream changes past ForkPoint that were read and
	// deliberately not ported, oldest first. It is what lets a drift report
	// be answered "does not apply" without editing ForkPoint, which would
	// claim a port that never happened.
	Reviewed []Review `json:"reviewed,omitempty"`
	// UnchangedThrough is the newest upstream release checked to be
	// identical in the copied paths to Base(), so the fields together say
	// "ported from X, upstream's changes through R reviewed and not ported,
	// and nothing further changed through Y".
	UnchangedThrough string `json:"unchanged_through,omitempty"`
	// Claims are the files whose prose states ForkPoint. The test fails when
	// one of them stops saying it, which is what kept the version in the
	// documentation true.
	Claims   []string   `json:"claims"`
	Identity []Identity `json:"identity,omitempty"`
	SHA256   string     `json:"sha256,omitempty"`
}

// Review is one upstream release whose changes to the copied paths, since
// the previous review or the fork point, were read and judged not to apply.
// Reason says why, for the next reader; the diff itself is not kept here.
type Review struct {
	Through string `json:"through"`
	Reason  string `json:"reason"`
}

// Base is the upstream version the copied paths are compared from: the
// newest review, or the fork point when nothing has been reviewed.
func (f *Fork) Base() string {
	if n := len(f.Reviewed); n > 0 {
		return f.Reviewed[n-1].Through
	}
	return f.ForkPoint
}

// CheckReviewed reports whether Reviewed is usable: only on a module
// upstream (the only kind forkcheck diffs between versions), every entry
// with a reason, strictly ascending above ForkPoint, and none newer than
// UnchangedThrough. A review at or below the fork point is one a port should
// have dropped; one above unchanged_through claims more than was checked.
func CheckReviewed(f *Fork) error {
	if len(f.Reviewed) == 0 {
		return nil
	}
	if f.Upstream.Kind != KindGomod {
		return fmt.Errorf("%s: reviewed is only meaningful for a %s upstream", f.ID, KindGomod)
	}
	prev := f.ForkPoint
	for _, r := range f.Reviewed {
		if strings.TrimSpace(r.Reason) == "" {
			return fmt.Errorf("%s: the review through %s gives no reason", f.ID, r.Through)
		}
		c, err := CompareVersions(r.Through, prev)
		if err != nil {
			return fmt.Errorf("%s: reviewed: %w", f.ID, err)
		}
		if c <= 0 {
			return fmt.Errorf("%s: the review through %s is not newer than %s; reviews ascend from the fork point, and a port drops the ones it absorbs", f.ID, r.Through, prev)
		}
		prev = r.Through
	}
	if c, err := CompareVersions(f.UnchangedThrough, prev); err != nil || c < 0 {
		return fmt.Errorf("%s: unchanged_through %q is older than the newest review %s", f.ID, f.UnchangedThrough, prev)
	}
	return nil
}

var releaseVersion = regexp.MustCompile(`^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)

// CompareVersions orders two release versions of the form vMAJOR.MINOR.PATCH,
// returning -1, 0 or +1. Pre-release and build suffixes are refused rather
// than ordered: a fork is taken from, and reviewed against, releases.
func CompareVersions(a, b string) (int, error) {
	var p [2][3]int
	for i, v := range []string{a, b} {
		m := releaseVersion.FindStringSubmatch(v)
		if m == nil {
			return 0, fmt.Errorf("%q is not a release version like v1.2.3", v)
		}
		for j := range 3 {
			n, err := strconv.Atoi(m[j+1])
			if err != nil {
				return 0, fmt.Errorf("%q: %w", v, err)
			}
			p[i][j] = n
		}
	}
	for j := range 3 {
		switch {
		case p[0][j] < p[1][j]:
			return -1, nil
		case p[0][j] > p[1][j]:
			return 1, nil
		}
	}
	return 0, nil
}

type Upstream struct {
	Kind   string   `json:"kind"`
	Module string   `json:"module,omitempty"`
	Paths  []string `json:"paths,omitempty"`
	URL    string   `json:"url,omitempty"`
}

// Identity is one claim that a piece of this copy is unmodified.
type Identity struct {
	Mode   string `json:"mode"`
	Name   string `json:"name,omitempty"`
	Ours   string `json:"ours"`
	Theirs string `json:"theirs"`
}

// ReadFile reads a file this repository owns: a path named by forks.json, a
// file in the module cache, or a source file of the running toolchain. Both
// readers of the manifest go through it so that the suppression below is
// stated once, where the reasoning lives, rather than at every call site —
// nothing in either package opens a path that came from outside this
// repository.
func ReadFile(name string) ([]byte, error) {
	//nolint:gosec // G304: see the doc comment.
	return os.ReadFile(name)
}

func Load(name string) (*Manifest, error) {
	b, err := ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read %s (run from the module root): %w", name, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if len(m.Forks) == 0 {
		return nil, fmt.Errorf("%s lists no forks", name)
	}
	for i := range m.Forks {
		if err := CheckReviewed(&m.Forks[i]); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return &m, nil
}

var (
	idField        = regexp.MustCompile(`"id":\s*"([^"]*)"`)
	unchangedField = regexp.MustCompile(`("unchanged_through":\s*")[^"]*(")`)
)

// SetUnchangedThrough rewrites unchanged_through for the forks in set (id to
// version) in the manifest file, in place. It edits the text rather than
// re-marshalling, because the committed file is laid out by hand (one-line
// identity claims, inline arrays) and a re-marshal turns a one-field update
// into a reformat of the whole file that buries it. The result is re-parsed
// and must differ from the original in exactly those fields, or nothing is
// written.
func SetUnchangedThrough(name string, set map[string]string) error {
	b, err := ReadFile(name)
	if err != nil {
		return err
	}
	var want Manifest
	if err := json.Unmarshal(b, &want); err != nil {
		return fmt.Errorf("parse %s: %w", name, err)
	}

	// Each entry's text runs from its "id" to the next one; the field is
	// rewritten only inside that span, and must occur there exactly once.
	ids := idField.FindAllSubmatchIndex(b, -1)
	var out []byte
	last := 0
	for i, loc := range ids {
		id := string(b[loc[2]:loc[3]])
		version, ok := set[id]
		if !ok {
			continue
		}
		end := len(b)
		if i+1 < len(ids) {
			end = ids[i+1][0]
		}
		span := b[loc[1]:end]
		if n := len(unchangedField.FindAllIndex(span, -1)); n != 1 {
			return fmt.Errorf("%s: entry %q has %d unchanged_through fields, expected 1", name, id, n)
		}
		out = append(out, b[last:loc[1]]...)
		out = append(out, unchangedField.ReplaceAll(span, []byte("${1}"+version+"${2}"))...)
		last = end
	}
	out = append(out, b[last:]...)

	var got Manifest
	if err := json.Unmarshal(out, &got); err != nil {
		return fmt.Errorf("%s: the edit produced invalid JSON: %w", name, err)
	}
	for i := range want.Forks {
		if v, ok := set[want.Forks[i].ID]; ok {
			want.Forks[i].UnchangedThrough = v
		}
	}
	wb, err := json.Marshal(want)
	if err != nil {
		return err
	}
	gb, err := json.Marshal(got)
	if err != nil {
		return err
	}
	if string(wb) != string(gb) {
		return fmt.Errorf("%s: the edit would change more than unchanged_through; nothing written", name)
	}
	//nolint:gosec // G306: the manifest is a committed source file, so this is
	// the mode git expects for it; it holds nothing secret.
	return os.WriteFile(name, out, 0o644)
}

// CodeOnly drops comments, blank lines and the package clause: in a file
// copied whole, those are the only edits this module makes.
func CodeOnly(src []byte) string {
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

// FuncText returns one top-level function's source, from "func name(" to the
// closing brace at column 0, with comment-only lines dropped so a lint
// annotation on this side does not read as a change to the algorithm.
func FuncText(src []byte, name string) (string, error) {
	re, err := regexp.Compile(`(?ms)^func ` + regexp.QuoteMeta(name) + `\(.*?^}$`)
	if err != nil {
		return "", err
	}
	m := re.Find(src)
	if m == nil {
		return "", fmt.Errorf("function %s not found", name)
	}
	var kept []string
	for _, line := range strings.Split(string(m), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n"), nil
}

// Block returns the span of src matched by pattern, treated as a multi-line
// regexp — a golden table, say.
func Block(src []byte, pattern string) (string, error) {
	re, err := regexp.Compile(`(?ms)` + pattern)
	if err != nil {
		return "", fmt.Errorf("block pattern %q: %w", pattern, err)
	}
	m := re.Find(src)
	if m == nil {
		return "", fmt.Errorf("block %q not found", pattern)
	}
	return string(m), nil
}

// SHA256File hashes a file on disk, streaming, so an embedded corpus does not
// have to fit in memory twice.
func SHA256File(name string) (string, error) {
	//nolint:gosec // G304: an embedded corpus named by the manifest.
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
