package main

import (
	"bytes"
	"strings"
	"testing"
)

// events builds a test2json stream from (action, pkg, test, output) rows.
func events(rows ...[4]string) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(`{"Action":"` + r[0] + `","Package":"` + r[1] + `"`)
		if r[2] != "" {
			b.WriteString(`,"Test":"` + r[2] + `"`)
		}
		if r[3] != "" {
			b.WriteString(`,"Output":"` + r[3] + `"`)
		}
		b.WriteString("}\n")
	}
	return b.String()
}

func mustAllow(t *testing.T, text string) *allowlist {
	t.Helper()
	al, err := parseAllowlist(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return al
}

func TestAudit_ReasonIsTheLineBeforeTheSkip(t *testing.T) {
	in := events(
		[4]string{"run", "p", "TestA", ""},
		[4]string{"output", "p", "TestA", `=== RUN   TestA\n`},
		[4]string{"output", "p", "TestA", `    a_test.go:12: kernel says no\n`},
		[4]string{"output", "p", "TestA", `--- SKIP: TestA (0.00s)\n`},
		[4]string{"skip", "p", "TestA", ""},
		[4]string{"run", "p", "TestB", ""},
		[4]string{"output", "p", "TestB", `    b_test.go:3: \n`}, // bare t.Skip()
		[4]string{"skip", "p", "TestB", ""},
		[4]string{"pass", "p", "", ""},
	)
	var out bytes.Buffer
	res, err := audit(strings.NewReader(in), &out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.skips) != 2 {
		t.Fatalf("skips = %+v, want 2", res.skips)
	}
	if res.skips[0].Reason != "kernel says no" {
		t.Errorf("reason = %q", res.skips[0].Reason)
	}
	if res.skips[1].Reason != "" {
		t.Errorf("bare t.Skip() reason = %q, want empty", res.skips[1].Reason)
	}
	// The ordinary -v output is echoed so the log stays readable.
	if !strings.Contains(out.String(), "--- SKIP: TestA") {
		t.Errorf("test output was not echoed: %q", out.String())
	}
}

func TestReport_DisallowedSkipFails(t *testing.T) {
	in := events(
		[4]string{"pass", "p", "TestOK", ""},
		[4]string{"skip", "p", "TestNo", ""},
	)
	al := mustAllow(t, "# nothing\n")
	res, err := audit(strings.NewReader(in), &bytes.Buffer{}, al)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = report(res, al, &out)
	if err == nil {
		t.Fatal("a skip with no allowlist entry must fail")
	}
	if !strings.Contains(err.Error(), "p TestNo") {
		t.Errorf("error does not name the skip: %v", err)
	}
	if !strings.Contains(out.String(), "NOT ALLOWED") {
		t.Errorf("summary does not flag the skip: %s", out.String())
	}
}

func TestReport_AllowedSkipPasses_AndSubtestWildcard(t *testing.T) {
	al := mustAllow(t, "p TestA\np FuzzX/...\n")
	in := events(
		[4]string{"skip", "p", "TestA", ""},
		[4]string{"skip", "p", "FuzzX/seed#1", ""},
		[4]string{"pass", "p", "FuzzX", ""},
	)
	res, err := audit(strings.NewReader(in), &bytes.Buffer{}, al)
	if err != nil {
		t.Fatal(err)
	}
	if err := report(res, al, &bytes.Buffer{}); err != nil {
		t.Fatalf("allowlisted skips must pass: %v", err)
	}
}

func TestAllowlist_PackageMustMatch(t *testing.T) {
	al := mustAllow(t, "other TestA\n")
	if al.allows(skip{Package: "p", Test: "TestA"}) {
		t.Fatal("an entry for another package must not allow the skip")
	}
	// The stale-entry note is per package seen: one list serves every module
	// a lane tests, so an entry for a module that did not run is not stale.
	if got := al.unused(map[string]bool{"p": true}); len(got) != 0 {
		t.Errorf("unused for a package not in the run = %v, want none", got)
	}
	if got := al.unused(map[string]bool{"other": true}); len(got) != 1 {
		t.Errorf("unused = %v, want the one entry", got)
	}
}

func TestReport_FailureIsNeverLost(t *testing.T) {
	in := events(
		[4]string{"fail", "p", "TestBoom", ""},
		[4]string{"fail", "p", "", ""},
	)
	res, err := audit(strings.NewReader(in), &bytes.Buffer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := report(res, nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "TestBoom") {
		t.Fatalf("a failed test must fail the audit and be named: %v", err)
	}
}

func TestReport_EmptyPipeFails(t *testing.T) {
	res, err := audit(strings.NewReader("not json at all\n"), &bytes.Buffer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.nonJSON != 1 {
		t.Errorf("nonJSON = %d, want 1", res.nonJSON)
	}
	if err := report(res, nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "no test events") {
		t.Fatalf("an empty stream must fail: %v", err)
	}
}

func TestParseAllowlist_RejectsMalformedLine(t *testing.T) {
	if _, err := parseAllowlist(strings.NewReader("just-one-field\n")); err == nil {
		t.Fatal("a line without two fields must be rejected")
	}
}
