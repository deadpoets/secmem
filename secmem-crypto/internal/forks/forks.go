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
	// UnchangedThrough is the newest upstream release checked to be
	// identical in the copied paths, so the pair says "ported from X, and
	// upstream has not changed through Y".
	UnchangedThrough string `json:"unchanged_through,omitempty"`
	// Claims are the files whose prose states ForkPoint. The test fails when
	// one of them stops saying it, which is what kept the version in the
	// documentation true.
	Claims   []string   `json:"claims"`
	Identity []Identity `json:"identity,omitempty"`
	SHA256   string     `json:"sha256,omitempty"`
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
	return &m, nil
}

// Save rewrites the manifest with the indentation it is committed with, so an
// automated field update produces a one-line diff rather than a reformat.
func Save(name string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	//nolint:gosec // G306: the manifest is a committed source file, so this is
	// the mode git expects for it; it holds nothing secret.
	return os.WriteFile(name, append(b, '\n'), 0o644)
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
