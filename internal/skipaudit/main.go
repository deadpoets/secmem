// Command skipaudit makes skipped tests visible in CI, and makes an
// unexpected one fail the job.
//
// A plain `go test` prints nothing for a test that calls t.Skip, so a proof
// that stops running — because a kernel feature went away on the runner, a
// lock budget shrank, or a helper binary disappeared — looks exactly like a
// proof that passed. This program reads `go test -json` events on stdin,
// echoes the ordinary test output so the log stays readable, and at the end
// prints every skip with the reason the test gave. A skip that is not on the
// allowlist is an error: the runner is no longer exercising something the
// documentation says it exercises, and somebody has to decide whether that
// is the environment or the claim.
//
// Usage:
//
//	go test -race -json ./... | skipaudit -allow .github/skip-allowlist/linux.txt
//
// The allowlist has one entry per line, "<import path> <test name>". A test
// name ending in "/..." covers every subtest under it. Blank lines and lines
// starting with '#' are ignored. An entry that never skipped is reported as
// a note so stale entries do not accumulate; it is not an error.
//
// Exit status is non-zero when a skip is not allowlisted, when any test or
// package failed (so a failure is never lost behind the audit's own verdict),
// or when no test events arrived at all — an empty pipe is a broken pipe,
// not a clean run.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// event is the subset of the test2json record this program reads.
type event struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

// skip is one skipped test and the reason its t.Skip gave, if any.
type skip struct {
	Package, Test, Reason string
}

// allowlist is the set of skips a runner is expected to produce.
type allowlist struct {
	entries []allowEntry
}

type allowEntry struct {
	pkg, test string
	used      bool
}

// parseAllowlist reads the "<import path> <test name>" lines.
func parseAllowlist(r io.Reader) (*allowlist, error) {
	al := &allowlist{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("allowlist line %d: want \"<import path> <test name>\", got %q", n, line)
		}
		al.entries = append(al.entries, allowEntry{pkg: fields[0], test: fields[1]})
	}
	return al, sc.Err()
}

// allows reports whether the skip matches an entry, marking the entry used.
func (al *allowlist) allows(s skip) bool {
	if al == nil {
		return false
	}
	for i := range al.entries {
		e := &al.entries[i]
		if e.pkg != s.Package {
			continue
		}
		if e.test == s.Test || (strings.HasSuffix(e.test, "/...") && strings.HasPrefix(s.Test, strings.TrimSuffix(e.test, "..."))) {
			e.used = true
			return true
		}
	}
	return false
}

// unused returns the entries no skip matched, for the stale-entry note. Only
// entries for packages that appeared in the stream count: one allowlist
// serves every module a lane tests, and each module is a separate run.
func (al *allowlist) unused(seen map[string]bool) []allowEntry {
	if al == nil {
		return nil
	}
	var out []allowEntry
	for _, e := range al.entries {
		if !e.used && seen[e.pkg] {
			out = append(out, e)
		}
	}
	return out
}

// reasonLine matches the line testing prints for t.Skip/t.Skipf (and t.Log):
// "    file_test.go:123: reason". The reason may be empty for a bare t.Skip().
var reasonLine = regexp.MustCompile(`^\s*[^\s:]+\.go:\d+: ?(.*)$`)

// result is what an audit found.
type result struct {
	skips    []skip
	failed   []string // "pkg Test", or "pkg" for a package-level failure
	events   int      // test-level pass/fail/skip events seen
	nonJSON  int      // lines on stdin that were not test2json records
	disallow []skip
	packages map[string]bool // packages that produced any event
}

// audit reads events from r, echoes test output to out, and returns what it
// found. It never stops on a malformed line: anything that is not a JSON
// record is passed through, because `go test -json` itself emits build
// errors as plain text.
func audit(r io.Reader, out io.Writer, al *allowlist) (*result, error) {
	res := &result{packages: map[string]bool{}}
	// The reason a test skipped is printed as an output line BEFORE the skip
	// event, so remember the last reason-shaped line per test.
	lastReason := map[string]string{}
	key := func(e event) string { return e.Package + " " + e.Test }

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20) // a race report or a fuzz crash can be long
	for sc.Scan() {
		line := sc.Bytes()
		var e event
		if len(line) == 0 || line[0] != '{' || json.Unmarshal(line, &e) != nil {
			res.nonJSON++
			_, _ = fmt.Fprintln(out, string(line))
			continue
		}
		if e.Package != "" {
			res.packages[e.Package] = true
		}
		switch e.Action {
		case "output", "build-output":
			_, _ = fmt.Fprint(out, e.Output)
			if e.Test != "" {
				if m := reasonLine.FindStringSubmatch(strings.TrimRight(e.Output, "\n")); m != nil {
					lastReason[key(e)] = m[1]
				}
			}
		case "skip":
			if e.Test == "" {
				continue // a package with no test files
			}
			res.events++
			s := skip{Package: e.Package, Test: e.Test, Reason: lastReason[key(e)]}
			res.skips = append(res.skips, s)
			if !al.allows(s) {
				res.disallow = append(res.disallow, s)
			}
		case "pass":
			if e.Test != "" {
				res.events++
			}
		case "fail", "build-fail":
			if e.Test != "" {
				res.events++
				res.failed = append(res.failed, e.Package+" "+e.Test)
			} else {
				res.failed = append(res.failed, e.Package)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("reading test output: %w", err)
	}
	return res, nil
}

// report prints the summary and returns the error the exit status should
// reflect, or nil.
func report(res *result, al *allowlist, out io.Writer) error {
	// Write errors on the summary are not the audit's verdict; stdout going
	// away is the CI runner's problem and the exit status still carries it.
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "skipaudit: %d test result(s), %d skipped\n", res.events, len(res.skips))
	sort.Slice(res.skips, func(i, j int) bool {
		if res.skips[i].Package != res.skips[j].Package {
			return res.skips[i].Package < res.skips[j].Package
		}
		return res.skips[i].Test < res.skips[j].Test
	})
	for _, s := range res.skips {
		mark := "allowed"
		if !al.allows(s) {
			mark = "NOT ALLOWED"
		}
		_, _ = fmt.Fprintf(out, "  skip [%s] %s %s: %s\n", mark, s.Package, s.Test, s.Reason)
	}
	for _, e := range al.unused(res.packages) {
		_, _ = fmt.Fprintf(out, "  note: allowlisted but did not skip on this runner: %s %s\n", e.pkg, e.test)
	}

	var errs []error
	if res.events == 0 {
		errs = append(errs, errors.New("skipaudit: no test events on stdin — the pipe is broken, not the suite clean"))
	}
	if len(res.failed) > 0 {
		errs = append(errs, fmt.Errorf("skipaudit: %d failure(s): %s", len(res.failed), strings.Join(res.failed, ", ")))
	}
	if len(res.disallow) > 0 {
		names := make([]string, 0, len(res.disallow))
		for _, s := range res.disallow {
			names = append(names, s.Package+" "+s.Test)
		}
		errs = append(errs, fmt.Errorf("skipaudit: %d skip(s) not on the allowlist: %s", len(res.disallow), strings.Join(names, ", ")))
	}
	return errors.Join(errs...)
}

func main() {
	allowPath := flag.String("allow", "", "allowlist file of expected skips (\"<import path> <test name>\" per line)")
	flag.Parse()

	var al *allowlist
	if *allowPath != "" {
		f, err := os.Open(*allowPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "skipaudit:", err)
			os.Exit(2)
		}
		al, err = parseAllowlist(f)
		_ = f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "skipaudit:", err)
			os.Exit(2)
		}
	}

	res, err := audit(os.Stdin, os.Stdout, al)
	if err != nil {
		fmt.Fprintln(os.Stderr, "skipaudit:", err)
		os.Exit(2)
	}
	if err := report(res, al, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stdout, err)
		os.Exit(1)
	}
}
